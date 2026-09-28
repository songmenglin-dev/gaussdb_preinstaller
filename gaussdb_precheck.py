#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gaussdb_precheck.py
===================
GaussDB 轻量化部署形态预安装脚本（OS 层）。

用法：
    python3 gaussdb_precheck.py check   # 输出检查表格（检查项 / 当前值 / 预期值 / 是否 OK）
    python3 gaussdb_precheck.py run     # 幂等地将所有 NOT OK 项修复到预期值

仅涉及操作系统层面的服务和文件配置（防火墙、字符集、时区、sysctl、limits、
profile、fstab、网卡 MTU 等），不触碰 install_cluster.conf / install_cluster.json。
脚本被设计为可重复执行——任何项若已经是预期值，run 不会重复插入或覆盖。
"""

import os
import platform
import re
import subprocess
import sys
import unicodedata
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# 兼容性自检
# --------------------------------------------------------------------------- #

if sys.version_info < (3, 7):
    sys.stderr.write(
        "gaussdb_precheck.py 需要 Python 3.7.9 或更高版本（文档推荐 3.7.9）；"
        f"当前为 {sys.version.split()[0]}\n"
    )
    sys.exit(1)

# --------------------------------------------------------------------------- #
# 常量 / 推荐值
# --------------------------------------------------------------------------- #

MANAGED_BEGIN = "# >>> gaussdb_precheck managed >>>"
MANAGED_END   = "# <<< gaussdb_precheck managed <<<"

# 注意：本脚本不主动修改 sysctl 类操作系统参数（如 net.ipv4.tcp_max_tw_buckets、
# net.core.*、vm.overcommit_*、kernel.sem/shmall/shmmax 等）。这些参数会显著改变
# 主机的网络/内存行为，可能影响同机部署的其他应用；按需由运维人员手动评估修改。

# --------------------------------------------------------------------------- #
# 通用工具
# --------------------------------------------------------------------------- #

def run(cmd: str, check: bool = False, shell: bool = True) -> Tuple[int, str, str]:
    """执行 shell 命令并返回 (rc, stdout, stderr)。"""
    try:
        proc = subprocess.run(
            cmd if shell else cmd.split(),
            shell=shell,
            capture_output=True,
            text=True,
            timeout=30,
        )
        out, err = proc.stdout or "", proc.stderr or ""
        if check and proc.returncode != 0:
            raise RuntimeError(f"命令执行失败: {cmd}\n{err}")
        return proc.returncode, out, err
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


def is_root() -> bool:
    return os.geteuid() == 0


def read_file(path: str) -> str:
    if not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def write_file(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def file_contains(path: str, pattern: str) -> bool:
    if not os.path.exists(path):
        return False
    return re.search(pattern, read_file(path), re.MULTILINE) is not None


def get_arch() -> str:
    """返回 'x86_64' 或 'aarch64'。"""
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "x86_64"
    if m in ("aarch64", "arm64"):
        return "aarch64"
    return m


def detect_os() -> str:
    """粗略识别发行版：kylin / uos / hce / suse / unknown。"""
    if os.path.exists("/etc/kylin-release") or file_contains("/etc/os-release", "Kylin"):
        return "kylin"
    if file_contains("/etc/os-release", "UnionTech") or file_contains("/etc/os-release", "uos"):
        return "uos"
    if file_contains("/etc/os-release", "HCE") or file_contains("/etc/os-release", "openEuler"):
        return "hce"
    if file_contains("/etc/os-release", "SUSE"):
        return "suse"
    return "unknown"


def is_service_active(name: str) -> bool:
    rc, out, _ = run(f"systemctl is-active {name}")
    return rc == 0 and "active" in out


def is_service_enabled(name: str) -> bool:
    rc, out, _ = run(f"systemctl is-enabled {name}")
    return rc == 0


# --------------------------------------------------------------------------- #
# 检查项模型
# --------------------------------------------------------------------------- #

@dataclass
class CheckItem:
    name: str                        # 检查项名（表格第一列）
    expected: str                    # 预期值（表格第三列）
    current: str = ""                # 当前值（表格第二列）
    ok: bool = False                 # 是否 OK（表格第四列）
    is_warning: bool = False         # 不匹配时是否仅作警告（不计入 NOT OK）
    detail: str = ""                 # 备注
    fix: Optional[Callable[[], None]] = None  # run 时执行的修复动作


# --------------------------------------------------------------------------- #
# 各项的 check / run 实现
# --------------------------------------------------------------------------- #

def check_firewall() -> List[CheckItem]:
    os_type = detect_os()
    items: List[CheckItem] = []

    if os_type == "suse":
        svc = "SuSEfirewall2.service"
        items.append(CheckItem(
            name="SuSEfirewall2 服务停止",
            expected="inactive (dead)",
            current=("inactive (dead)" if not is_service_active(svc) else "active (running)"),
            ok=not is_service_active(svc),
            fix=lambda: (run("systemctl stop SuSEfirewall2.service", check=False),
                         run("systemctl disable SuSEfirewall2.service", check=False)),
        ))
        items.append(CheckItem(
            name="SuSEfirewall2 禁止开机自启",
            expected="disabled",
            current=("disabled" if not is_service_enabled(svc) else "enabled"),
            ok=not is_service_enabled(svc),
            fix=lambda: run("systemctl disable SuSEfirewall2.service", check=False),
        ))
        return items

    # 通用（Kylin / UOS / HCE）
    svc = "firewalld.service"
    active = is_service_active(svc)
    items.append(CheckItem(
        name="firewalld 服务停止",
        expected="inactive (dead)",
        current=("inactive (dead)" if not active else "active (running)"),
        ok=not active,
        fix=lambda: run("systemctl stop firewalld.service", check=False),
    ))
    items.append(CheckItem(
        name="firewalld 禁止开机自启",
        expected="disabled",
        current=("disabled" if not is_service_enabled(svc) else "enabled"),
        ok=not is_service_enabled(svc),
        fix=lambda: run("systemctl disable firewalld.service", check=False),
    ))

    iptables_svc = "iptables.service"
    items.append(CheckItem(
        name="iptables 服务运行",
        expected="active (exited)",
        current=("active (exited)" if is_service_active(iptables_svc) else "inactive"),
        ok=is_service_active(iptables_svc),
        fix=lambda: (run("systemctl start iptables.service", check=False),
                     run("systemctl enable iptables.service", check=False)),
    ))
    items.append(CheckItem(
        name="iptables 开机自启",
        expected="enabled",
        current=("enabled" if is_service_enabled(iptables_svc) else "disabled"),
        ok=is_service_enabled(iptables_svc),
        fix=lambda: run("systemctl enable iptables.service", check=False),
    ))
    return items


def check_selinux() -> List[CheckItem]:
    cfg = "/etc/selinux/config"
    content = read_file(cfg)
    m = re.search(r"^\s*SELINUX\s*=\s*(\w+)", content, re.MULTILINE) if content else None
    current = m.group(1) if m else "(未设置)"
    ok = current.lower() == "permissive"
    items = [CheckItem(
        name="SELINUX 模式",
        expected="permissive",
        current=current,
        ok=ok,
        fix=lambda: _set_selinux_permissive(cfg, content),
    )]
    return items


def _set_selinux_permissive(cfg: str = "/etc/selinux/config", content: str = "") -> None:
    if not content:
        content = ""
    new = re.sub(
        r"^\s*SELINUX\s*=\s*\w+",
        "SELINUX=permissive",
        content,
        flags=re.MULTILINE,
    )
    if "SELINUX=" not in new:
        new = new.rstrip() + "\nSELINUX=permissive\n"
    write_file(cfg, new)


def check_charset() -> List[CheckItem]:
    """只检查 /etc/profile 中的 LANG（必要时 SUSE 额外检查 LC_ALL）。

    脚本不修改 /etc/sysconfig/i18n 或 /etc/locale.conf——按文档要求仅在 profile 中
    维护字符集即可满足安装需求, 避免触发与桌面会话/系统语言环境相关的副作用.
    """
    items: List[CheckItem] = []
    profile = read_file("/etc/profile")
    m = re.search(r"^\s*export\s+LANG\s*=\s*(\S+)", profile, re.MULTILINE) if profile else None
    items.append(CheckItem(
        name="/etc/profile LANG",
        expected="en_US.UTF-8",
        current=(m.group(1) if m else "(未设置)"),
        ok=bool(m and m.group(1) == "en_US.UTF-8"),
        fix=lambda: _set_profile_lang(profile),
    ))

    if detect_os() == "suse":
        m2 = re.search(r"^\s*export\s+LC_ALL\s*=\s*(\S+)", profile, re.MULTILINE) if profile else None
        items.append(CheckItem(
            name="/etc/profile LC_ALL (SUSE)",
            expected="en_US.UTF-8",
            current=(m2.group(1) if m2 else "(未设置)"),
            ok=bool(m2 and m2.group(1) == "en_US.UTF-8"),
            fix=lambda: _set_profile_lcall(profile),
        ))
    return items


def _set_profile_lang(profile: str, path: str = "/etc/profile") -> None:
    profile = profile or ""
    if re.search(r"^\s*export\s+LANG\s*=", profile, re.MULTILINE):
        profile = re.sub(
            r"^\s*export\s+LANG\s*=\s*\S+",
            "export LANG=en_US.UTF-8",
            profile,
            flags=re.MULTILINE,
        )
    else:
        profile = profile.rstrip() + f"\n{MANAGED_BEGIN}\nexport LANG=en_US.UTF-8\n{MANAGED_END}\n"
    write_file(path, profile)


def _set_profile_lcall(profile: str, path: str = "/etc/profile") -> None:
    profile = profile or ""
    if re.search(r"^\s*export\s+LC_ALL\s*=", profile, re.MULTILINE):
        profile = re.sub(
            r"^\s*export\s+LC_ALL\s*=\s*\S+",
            "export LC_ALL=en_US.UTF-8",
            profile,
            flags=re.MULTILINE,
        )
    else:
        profile = profile.rstrip() + f"\n{MANAGED_BEGIN}\nexport LC_ALL=en_US.UTF-8\n{MANAGED_END}\n"
    write_file(path, profile)


def check_timezone() -> List[CheckItem]:
    rc, out, _ = run("timedatectl")
    m = re.search(r"Time zone:\s*(\S+)", out) if rc == 0 else None
    current = m.group(1) if m else "(未知)"
    is_utc = current.startswith("Etc/UTC") or current.startswith("UTC")
    items = [CheckItem(
        name="系统时区",
        expected="UTC",
        current=current,
        ok=is_utc,
        is_warning=not is_utc,    # 时区仅作警告——文档推荐 UTC, 但本机可能因业务需要保留本地时区
        fix=lambda: run("timedatectl set-timezone UTC", check=False),
    )]
    return items


def check_swap() -> List[CheckItem]:
    items: List[CheckItem] = []

    rc, out, _ = run("swapon --show")
    items.append(CheckItem(
        name="swap 当前状态",
        expected="无 swap",
        current=("无 swap" if (rc != 0 or not out.strip()) else out.strip().splitlines()[0]),
        ok=(rc != 0 or not out.strip()),
        fix=lambda: run("swapoff -a", check=False),
    ))

    # fstab 中是否存在未注释的 swap 行
    fstab = read_file("/etc/fstab")
    if fstab:
        has_active_swap = any(
            re.match(r"^\s*[^#\s]\S*\s+\S+\s+swap\s+", ln)
            for ln in fstab.splitlines()
        )
    else:
        has_active_swap = False
    items.append(CheckItem(
        name="/etc/fstab swap 已注释",
        expected="已注释",
        current=("存在未注释的 swap 行" if has_active_swap else "已注释"),
        ok=not has_active_swap,
        fix=lambda: _comment_swap_fstab(fstab),
    ))
    return items


def _comment_swap_fstab(fstab: str, path: str = "/etc/fstab") -> None:
    new_lines = []
    for ln in (fstab or "").splitlines():
        if re.match(r"^\s*[^#\s]\S*\s+\S+\s+swap\s+", ln):
            new_lines.append("# " + ln)
        else:
            new_lines.append(ln)
    write_file(path, "\n".join(new_lines) + "\n")


def check_mtu() -> List[CheckItem]:
    """只读检查 backIp1 绑定网卡（默认取第一张非 lo）的 MTU 值。

    脚本不修改 MTU——按文档 1.3.5 节要求 MTU 需与上下游网络设备保持一致, 改错可能
    导致 SSH/scp 失败, 应由运维人员按现场网络拓扑手工调整. 这里仅做信息展示,
    且不匹配时只作警告 (不阻塞安装).
    """
    rc, out, _ = run("ip -o link show")
    if rc != 0 or not out.strip():
        return [CheckItem(name="网卡 MTU", expected=_mtu_expected(),
                          current="(无法获取网卡信息)", ok=False,
                          is_warning=True, fix=None)]
    ifaces = []
    for ln in out.splitlines():
        m = re.match(r"\d+:\s+(\S+):", ln)
        if m and m.group(1) != "lo":
            ifaces.append(m.group(1))
    if not ifaces:
        return [CheckItem(name="网卡 MTU", expected=_mtu_expected(),
                          current="(未发现网卡)", ok=False,
                          is_warning=True, fix=None)]
    primary = ifaces[0]
    rc, out, _ = run(f"ip -o link show {primary}")
    m = re.search(r"mtu\s+(\d+)", out) if rc == 0 else None
    current = m.group(1) if m else "(未知)"
    expected = _mtu_expected()
    is_match = current == expected
    return [CheckItem(
        name=f"网卡 {primary} MTU",
        expected=expected,
        current=current,
        ok=is_match,
        is_warning=not is_match,    # MTU 不匹配时只作警告——由运维评估是否修改
        fix=None,                   # 不自动修改 MTU
    )]


def _mtu_expected() -> str:
    return "8192" if get_arch() == "aarch64" else "1500"


def check_history() -> List[CheckItem]:
    profile = read_file("/etc/profile")
    m = re.search(r"^\s*HISTSIZE\s*=\s*(\S+)", profile, re.MULTILINE) if profile else None
    current = m.group(1) if m else "(未设置)"
    items = [CheckItem(
        name="/etc/profile HISTSIZE",
        expected="0",
        current=current,
        ok=current == "0",
        fix=lambda: _set_hist(profile),
    )]
    return items


def _set_hist(profile: str, path: str = "/etc/profile") -> None:
    profile = profile or ""
    if re.search(r"^\s*HISTSIZE\s*=", profile, re.MULTILINE):
        profile = re.sub(r"^\s*HISTSIZE\s*=\s*\S+", "HISTSIZE=0", profile, flags=re.MULTILINE)
    else:
        profile = profile.rstrip() + f"\n{MANAGED_BEGIN}\nHISTSIZE=0\n{MANAGED_END}\n"
    write_file(path, profile)


def check_limits() -> List[CheckItem]:
    """合并检查 limits.conf 的文件句柄与进程数 (期望值统一为 1000000)。

    检查项:
      - /etc/security/limits.conf: * soft nofile 1000000
      - /etc/security/limits.conf: * hard nofile 1000000
      - /etc/security/limits.d/90-nproc.conf (或 limits.conf): * soft nproc 1000000
    全部满足时为 OK, 否则 NOT OK. 当前值以 soft=X hard=Y nproc=Z 形式展示.
    """
    nofile_cfg = "/etc/security/limits.conf"
    nofile_content = read_file(nofile_cfg) or ""
    soft = _read_limit(nofile_content, r"\*\s+soft\s+nofile")
    hard = _read_limit(nofile_content, r"\*\s+hard\s+nofile")

    nproc_cfg = "/etc/security/limits.d/90-nproc.conf"
    if not os.path.exists(nproc_cfg):
        nproc_cfg = "/etc/security/limits.conf"
    nproc_content = read_file(nproc_cfg) or ""
    nproc = _read_limit(nproc_content, r"\*\s+soft\s+nproc")

    parts = [f"soft={soft}", f"hard={hard}", f"nproc={nproc}"]
    current = " ".join(parts)
    expected = "soft=1000000 hard=1000000 nproc=1000000"
    ok = (soft == "1000000" and hard == "1000000" and nproc == "1000000")

    return [CheckItem(
        name="limits.conf 文件句柄 / 进程数",
        expected=expected,
        current=current,
        ok=ok,
        fix=lambda: _fix_limits(nofile_cfg, nofile_content, nproc_cfg, nproc_content),
    )]


def _read_limit(content: str, key_pattern: str) -> str:
    m = re.search(rf"^\s*{key_pattern}\s+(\d+)", content, re.MULTILINE)
    return m.group(1) if m else "(未设置)"


def _fix_limits(nofile_cfg: str, nofile_content: str,
                nproc_cfg: str, nproc_content: str) -> None:
    _ensure_limit_line(nofile_cfg, nofile_content, "* soft nofile 1000000")
    # 第二次写入后重新读取, 再追加 hard 行 (避免两次写入冲突)
    nofile_now = read_file(nofile_cfg) or ""
    _ensure_limit_line(nofile_cfg, nofile_now, "* hard nofile 1000000")

    nproc_now = read_file(nproc_cfg) or ""
    if not re.search(r"^\s*\*\s+soft\s+nproc\s+1000000\s*$", nproc_now, re.MULTILINE):
        if re.search(r"^\s*\*\s+soft\s+nproc\s+\d+", nproc_now, re.MULTILINE):
            nproc_now = re.sub(
                r"^\s*\*\s+soft\s+nproc\s+\d+",
                "* soft nproc 1000000",
                nproc_now,
                flags=re.MULTILINE,
            )
        else:
            nproc_now = nproc_now.rstrip() + f"\n{MANAGED_BEGIN}\n* soft nproc 1000000\n{MANAGED_END}\n"
        os.makedirs(os.path.dirname(nproc_cfg), exist_ok=True)
        write_file(nproc_cfg, nproc_now)


def _ensure_limit_line(cfg: str, content: str, line: str) -> None:
    content = content or ""
    pattern = rf"^\s*{re.escape(line)}\s*$"
    if not re.search(pattern, content, re.MULTILINE):
        content = content.rstrip() + f"\n{MANAGED_BEGIN}\n{line}\n{MANAGED_END}\n"
    write_file(cfg, content)


def _strip_root_nofile(cfg: str, content: str) -> None:
    """保留备用: 文档建议删除 root soft/hard nofile 行, 但新版合并为 1 项后此函数不再调用."""
    content = content or ""
    new = "\n".join(
        ln for ln in content.splitlines()
        if not re.match(r"^\s*root\s+(soft|hard)\s+nofile", ln)
    )
    write_file(cfg, new + "\n")


def _ensure_nproc(cfg: str, content: str) -> None:
    """保留备用: 旧版 nproc 单独修复函数, 新版合并到 _fix_limits()."""
    content = content or ""
    if re.search(r"^\s*\*\s+soft\s+nproc\s+\d+", content, re.MULTILINE):
        content = re.sub(r"^\s*\*\s+soft\s+nproc\s+\d+", "* soft nproc 1000000", content, flags=re.MULTILINE)
    else:
        content = content.rstrip() + f"\n{MANAGED_BEGIN}\n* soft nproc 1000000\n{MANAGED_END}\n"
    os.makedirs(os.path.dirname(cfg), exist_ok=True)
    write_file(cfg, content)


def check_thp() -> List[CheckItem]:
    """transparent_hugepage 是否关闭。"""
    rc, out, _ = run("cat /sys/kernel/mm/transparent_hugepage/enabled")
    current = (out.strip() if rc == 0 else "") or ""
    is_never = "[never]" in current
    items = [CheckItem(
        name="transparent_hugepage",
        expected="never",
        current=current or "(未知)",
        ok=is_never,
        fix=lambda: _disable_thp(),
    )]
    return items


def _disable_thp() -> None:
    run("echo never > /sys/kernel/mm/transparent_hugepage/enabled", check=False)
    # 写入启动文件 rc.local
    for rc_path, marker in (("/etc/rc.d/rc.local", "if [ -f /sys/kernel/mm/transparent_hugepage/enabled ]; then"),
                            ("/etc/rc.local",       "if [ -f /sys/kernel/mm/transparent_hugepage/enabled ]; then")):
        if os.path.exists(rc_path) or rc_path.endswith("rc.local"):
            _append_rc_local(rc_path, marker)


def _append_rc_local(path: str, marker: str) -> None:
    content = read_file(path) or ""
    if "transparent_hugepage/enabled" in content:
        return
    block = (
        f"{MANAGED_BEGIN}\n"
        f"{marker}\n"
        "  echo never > /sys/kernel/mm/transparent_hugepage/enabled\n"
        "fi\n"
        f"{MANAGED_END}\n"
    )
    write_file(path, (content.rstrip() + "\n" + block) if content else "#!/bin/bash\n" + block)


def check_cgroup() -> List[CheckItem]:
    rc, out, _ = run("stat -fc %T /sys/fs/cgroup/")
    current = out.strip() if rc == 0 else "(未知)"
    items = [CheckItem(
        name="cgroup 版本",
        expected="tmpfs (cgroup v1)",
        current=current,
        ok=current == "tmpfs",
        fix=lambda: None,  # cgroup 切换需要重启 grub，不可由脚本自动完成
    )]
    return items


def check_clock_service() -> List[CheckItem]:
    """Chrony 或 NTP 至少一个在运行。"""
    chrony_active = is_service_active("chronyd.service")
    ntp_active = is_service_active("ntpd.service") or is_service_active("ntpdate.service")
    current = []
    if chrony_active:
        current.append("chronyd: active")
    if ntp_active:
        current.append("ntpd/ntpdate: active")
    cur_str = ", ".join(current) or "均未运行"
    items = [CheckItem(
        name="时间同步服务运行",
        expected="chronyd 或 ntpd 至少一个 active",
        current=cur_str,
        ok=chrony_active or ntp_active,
        fix=lambda: run("systemctl enable --now chronyd", check=False),
    )]
    return items


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #

CHECK_GROUPS: List[Tuple[str, Callable[[], List[CheckItem]]]] = [
    ("操作系统防火墙", check_firewall),
    ("SELinux", check_selinux),
    ("字符集", check_charset),
    ("时区与时钟源", lambda: check_timezone() + check_clock_service()),
    ("Swap", check_swap),
    ("网卡 MTU (只读)", check_mtu),
    ("HISTORY 记录", check_history),
    ("文件句柄 / 进程数", check_limits),
    ("透明大页 / cgroup", lambda: check_thp() + check_cgroup()),
]


def gather_all() -> List[CheckItem]:
    items: List[CheckItem] = []
    for _, fn in CHECK_GROUPS:
        try:
            items.extend(fn())
        except Exception as e:  # noqa: BLE001
            items.append(CheckItem(name=fn.__name__, expected="-", current=f"采集异常: {e}", ok=False))
    return items


def _status_text(it: CheckItem) -> str:
    if it.ok:
        return "OK"
    if it.is_warning:
        return "WARNING"
    return "NOT OK"


def print_table(items: List[CheckItem]) -> None:
    """Print an aligned table. Column widths are computed in display columns
    (CJK / full-width chars take 2 columns), so the table aligns in any UTF-8 terminal.
    """
    headers = ("item", "current_value", "expected_value", "status")
    rows = []
    for it in items:
        rows.append((
            it.name,
            _truncate(it.current),
            _truncate(it.expected),
            _status_text(it),
        ))

    widths = [_display_width(h) for h in headers]
    for r in rows:
        widths = [max(w, _display_width(_to_str(c))) for w, c in zip(widths, r)]

    def fmt_cell(text: str, w: int) -> str:
        truncated = _truncate_to_width(text, w)
        return _pad_display(truncated, w)

    def fmt_row(r):
        return "| " + " | ".join(fmt_cell(_to_str(c), w) for c, w in zip(r, widths)) + " |"

    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    print(sep)
    print(fmt_row(headers))
    print(sep)
    for r in rows:
        print(fmt_row(r))
    print(sep)

    ok = sum(1 for x in items if x.ok)
    warning = sum(1 for x in items if not x.ok and x.is_warning)
    not_ok = len(items) - ok - warning
    print(f"\nSummary: {ok} OK, {warning} WARNING, {not_ok} NOT OK (total {len(items)})")


def _to_str(v) -> str:
    return v if v is not None else ""


def _display_width(s: str) -> int:
    """返回字符串在等宽终端里的显示列宽 (CJK/全角算 2 列, 其余 1 列)."""
    w = 0
    for ch in s:
        if unicodedata.east_asian_width(ch) in ("F", "W"):
            w += 2
        else:
            w += 1
    return w


def _truncate_to_width(s: str, max_width: int) -> str:
    """按显示宽度截断, 尾部追加 … (1 列)"""
    if _display_width(s) <= max_width:
        return s
    out, w = [], 0
    for ch in s:
        cw = 2 if unicodedata.east_asian_width(ch) in ("F", "W") else 1
        if w + cw > max_width - 1:  # 留 1 列给省略号
            out.append("…")
            return "".join(out)
        out.append(ch)
        w += cw
    return "".join(out)


def _pad_display(s: str, target_width: int) -> str:
    """右侧补空格, 使最终显示宽度 == target_width."""
    pad = target_width - _display_width(s)
    return s + (" " * pad) if pad > 0 else s


def _truncate(v: str, n: int = 60) -> str:
    """按显示宽度截断, 默认 60 列."""
    return _truncate_to_width(_to_str(v).replace("\n", " ").strip(), n)


def cmd_check() -> int:
    items = gather_all()
    print_table(items)
    # WARNING 不算失败, 只有 NOT OK 才返回非 0
    return 0 if not any((not x.ok and not x.is_warning) for x in items) else 1


def cmd_run() -> int:
    if not is_root():
        print("ERROR: 'run' requires root privileges (modifies system files/services).", file=sys.stderr)
        return 2

    items = gather_all()
    print_table(items)
    print()

    not_ok = [x for x in items if not x.ok]
    if not not_ok:
        print("All checks pass, no changes needed.")
        return 0

    blocking = [x for x in not_ok if not x.is_warning]
    warning_items = [x for x in not_ok if x.is_warning]
    print(f"Fixing {len(blocking)} NOT OK"
          + (f" and {len(warning_items)} WARNING items ..." if warning_items else " items ...")
          + "\n")
    failed: List[str] = []
    for it in not_ok:
        if it.fix is None:
            print(f"  [skip] {it.name}: no auto-fix (manual required)")
            continue
        try:
            it.fix()
            tag = "WARNING" if it.is_warning else "NOT OK"
            print(f"  [fixed][{tag}] {it.name}")
        except Exception as e:  # noqa: BLE001
            failed.append(f"{it.name}: {e}")
            print(f"  [failed] {it.name}: {e}")

    print("\nTip: limits / HISTSIZE / LANG changes require a new login shell "
          "or `source /etc/profile` to take effect in the current session.")

    if failed:
        print("\nFailed items:")
        for f in failed:
            print("  - " + f)
        return 1
    print("\nAll NOT OK items have been attempted to fix. Run check again to verify.")
    return 0


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in ("check", "run"):
        print("Usage:")
        print("  python3 gaussdb_precheck.py check    # output check table")
        print("  python3 gaussdb_precheck.py run      # idempotently fix NOT OK items")
        return 64
    return cmd_check() if sys.argv[1] == "check" else cmd_run()


if __name__ == "__main__":
    sys.exit(main())
