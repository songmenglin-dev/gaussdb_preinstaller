#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gaussdb_host_check - 主机管理标准化 检查/修复 执行器.

用法:
    python gaussdb_host_check.py check [--no-color] [--detail]
    python gaussdb_host_check.py fix   [--no-color] [--yes]
    python gaussdb_host_check.py list

子命令:
    check   按本脚本内嵌的检查项表跑检查，输出彩色表格报告
    fix     对所有 NOT OK 项执行对应的修复命令（来自配置方法章节）
    list    列出所有检查项 ID 和名称

数据来源：本文件 CHECKS / FIX_SECTIONS 常量。
两份 MD 文件（主机管理标准化检查项.md / 主机管理标准化配置方法.md）
为生成这些数据所用的事实参考，运行时不再读取。

退出码:
    0  所有检查通过（或没有 FAIL 项需要修复）
    1  check 模式下存在 FAIL
    2  fix 模式下存在 fix 失败
    3  参数错误
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Set, Tuple


# =============================================================
# 常量
# =============================================================

# ANSI 颜色
USE_COLOR = True

C_RESET = ""
C_BOLD = ""
C_DIM = ""
C_RED = ""
C_GREEN = ""
C_YELLOW = ""
C_BLUE = ""
C_MAGENTA = ""
C_CYAN = ""


def _ansi(code: str) -> str:
    return f"\033[{code}m" if USE_COLOR else ""


def set_color(enabled: bool) -> None:
    """开关 ANSI 颜色。C_* 常量在导入时已生成，切换时需一并重建。"""
    global USE_COLOR, C_RESET, C_BOLD, C_DIM, C_RED, C_GREEN, C_YELLOW
    global C_BLUE, C_MAGENTA, C_CYAN
    USE_COLOR = enabled
    C_RESET = _ansi("0")
    C_BOLD = _ansi("1")
    C_DIM = _ansi("2")
    C_RED = _ansi("31")
    C_GREEN = _ansi("32")
    C_YELLOW = _ansi("33")
    C_BLUE = _ansi("34")
    C_MAGENTA = _ansi("35")
    C_CYAN = _ansi("36")


set_color(True)


class Status(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"

    def color(self) -> str:
        return {
            Status.PASS: C_GREEN,
            Status.FAIL: C_RED,
            Status.ERROR: C_MAGENTA,
        }[self]

    def label(self) -> str:
        return f"{self.color()}{self.value:<5}{C_RESET}"


# 危险命令正则（fix 模式下默认拦截，需要 --yes 才执行）
_DANGEROUS_PATTERNS = [
    re.compile(r"^\s*rm\s+-r?f?\s+/"),
    re.compile(r"^\s*rm\s+-r?\s+/var"),
    re.compile(r"^\s*shutdown\b"),
    re.compile(r"^\s*poweroff\b"),
    re.compile(r"^\s*init\s+6\b"),
    re.compile(r"^\s*mklabel\b"),
    re.compile(r"^\s*kill\s+-9\b"),
    re.compile(r"^\s*pkill\s+-9\b"),
    re.compile(r"^\s*pkill\s+-u\b"),
    re.compile(r"^\s*vgremove\b"),
    re.compile(r"^\s*lvremove\b"),
    re.compile(r"^\s*pvremove\b"),
    re.compile(r"^\s*dd\s+if=.*of=/dev/"),
    re.compile(r"^\s*mkfs\."),
    re.compile(r"^\s*parted\s+/dev/"),
    re.compile(r">\s*/dev/sd"),
    re.compile(r">\s*/dev/vd"),
    re.compile(r">\s*/dev/nvme"),
    re.compile(r"^\s*crontab\s+-r\b"),
    re.compile(r"iptables\s+-F\b"),
    re.compile(r"iptables\s+--flush\b"),
    re.compile(r"setenforce\s+0"),
]


def is_dangerous(cmd: str) -> bool:
    return any(p.search(cmd) for p in _DANGEROUS_PATTERNS)


# =============================================================
# 操作系统/权限 探测
# =============================================================

@dataclass
class HostInfo:
    os_id: str = "unknown"           # kylin / uos / hce / sle / bclinux / unknown
    os_version: str = ""
    is_root: bool = False
    package_manager: str = ""        # yum / dnf / zypper / apt


def _read_os_release() -> Dict[str, str]:
    """解析 /etc/os-release，返回 KEY -> VALUE（值已去引号）。"""
    data: Dict[str, str] = {}
    if not os.path.exists("/etc/os-release"):
        return data
    try:
        for line in open("/etc/os-release", encoding="utf-8", errors="ignore"):
            if "=" in line and not line.strip().startswith("#"):
                k, v = line.split("=", 1)
                data[k.strip()] = v.strip().strip('"')
    except Exception:
        pass
    return data


def detect_host() -> HostInfo:
    info = HostInfo()
    info.is_root = (os.geteuid() == 0)
    # os
    data = _read_os_release()
    info.os_id = data.get("ID", "unknown").lower()
    info.os_version = data.get("VERSION_ID", "")
    # package manager
    for pm, path in (("yum", "/usr/bin/yum"), ("dnf", "/usr/bin/dnf"),
                     ("zypper", "/usr/bin/zypper"), ("apt", "/usr/bin/apt")):
        if os.path.exists(path):
            info.package_manager = pm
            break
    return info


# =============================================================
# 工具：执行 shell 命令
# =============================================================

def run_shell(cmd: str, timeout: int = 30) -> Tuple[int, str, str]:
    """执行 shell 命令，返回 (exit_code, stdout, stderr)."""
    try:
        p = subprocess.run(
            cmd, shell=True, executable="/bin/bash",
            capture_output=True, text=True, timeout=timeout,
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except Exception as e:
        return 1, "", f"{type(e).__name__}: {e}"


def which(cmd: str) -> str:
    return shutil.which(cmd) or ""


# =============================================================
# 检查项定义
# =============================================================

@dataclass
class CheckDef:
    id: int
    name: str                      # 人读名称
    category: str                  # 分组
    check_type: str                # 见下表
    expected: str = ""             # 期望值（人读）
    fix_refs: List[str] = field(default_factory=list)
    # type-specific fields:
    key: str = ""                  # ulimit type / service / package / port
    port: int = 0
    path: str = ""
    value: str = ""
    mandatory: bool = False


# ---------------------------------------------------------------
# CHECKS 数据
# 字段格式: (id, name, type, expected, fix_ref, **kwargs)
# type:
#   ulimit_min         kwargs: key (-Sn/-Hn), value
#   ulimit_eq          kwargs: key (-s), value
#   service_active     kwargs: key (服务名)
#   service_inactive   kwargs: key (服务名)
#   pkg                kwargs: key (包名)
#   port_free          kwargs: port
#   ports_free         kwargs: key (逗号分隔端口)
#   cgroup_v1          kwargs: -
#   profile_source     kwargs: -
#   hosts_ipv6         kwargs: -
#   sftp               kwargs: -
#   security_perm      kwargs: -
#   timezone_utc       kwargs: -
#   swap_active        kwargs: -
#   swap_fstab         kwargs: -
#   thp_never          kwargs: -
#   selinux_mode       kwargs: -
#   python_link        kwargs: -
#   cpu_cores          kwargs: value (最小核数)
#   cpu_model          kwargs: value (推荐型号关键字，逗号分隔)
#   mem_gb             kwargs: value (最小内存 GB)
#   cpu_mem_ratio      kwargs: value (允许的 内存/核数，逗号分隔)
#   disk_rotational    kwargs: -
#   data_disk_clean    kwargs: -
#   disk_naming        kwargs: -
#   sysdisk_single     kwargs: -
#   sysdisk_not_nvme   kwargs: -
#   os_supported       kwargs: -
#   locale_utf8        kwargs: -
#   mtu_ok             kwargs: value (允许的 MTU，逗号分隔)
#   histsize_zero      kwargs: -
#   dir_empty          kwargs: path
#   tpops_unbound      kwargs: path
#   hwclock_sync       kwargs: -
#   ping_localhost     kwargs: -
#   python_version     kwargs: -  (按 os-release ID 查期望版本)
#   path_perm_min      kwargs: path (glob，逗号分隔), value (八进制最小权限)
#   pkgmgr_ok          kwargs: -
#   numa_balanced      kwargs: -
#   ssh_port           kwargs: -
# ---------------------------------------------------------------

# 所有检查项都由 _check_one() 自动判定，结果只有三种：
#   OK       符合预期（强制项和非强制项相同）
#   NOT OK   不符合预期且 mandatory=True
#   WARNING  不符合预期且 mandatory=False
# mandatory 的取值以 主机管理标准化检查项.md 的「是否强制校验」列为准。

CHECKS: List[CheckDef] = [
    # ===== CPU 和内存 =====
    CheckDef(100001, "vCPU核数 >= 4", "CPU和内存", "cpu_cores",
             expected=">= 4",
             value="4"),
    CheckDef(100002, "CPU型号为推荐", "CPU和内存", "cpu_model",
             expected="Kunpeng 920, Intel Xeon Gold 6248R/5318Y, Hygon 7280",
             value="Kunpeng 920,Xeon Gold 6248R,Xeon Gold 5318Y,Hygon 7280"),
    CheckDef(100003, "内存 >= 16G", "CPU和内存", "mem_gb",
             expected=">= 16G",
             value="16"),
    CheckDef(100004, "CPU内存比 1:4 或 1:8", "CPU和内存", "cpu_mem_ratio",
             expected="内存/核数 = 4 或 8 (±0.5)",
             value="4,8"),

    # ===== 磁盘 =====
    CheckDef(100005, "磁盘类型推荐", "磁盘", "disk_rotational",
             expected="所有磁盘 rota=0 (SSD)",
             fix_refs=["准备数据盘", "准备系统盘"]),
    CheckDef(100006, "数据盘无分区无挂载", "磁盘", "data_disk_clean",
             expected="无分区无挂载",
             mandatory=False,   # 涉及数据销毁风险，fix 不自动处理，仅检查
             fix_refs=["准备数据盘"]),
    CheckDef(100009, "磁盘盘符不混用", "磁盘", "disk_naming",
             expected="不要 sd 和 vd 混用",
             mandatory=False,   # 无对应 fix 命令，仅检查
             fix_refs=["准备数据盘", "准备系统盘"]),
    CheckDef(100069, "系统盘非多磁盘", "磁盘", "sysdisk_single",
             expected="单盘",
             mandatory=False,   # 需重装或选 DM 模式，仅检查
             fix_refs=["准备系统盘"]),
    CheckDef(100070, "系统盘非 NVMe", "磁盘", "sysdisk_not_nvme",
             expected="SAS/SATA SSD",
             mandatory=False,   # 硬件层面要求，仅检查
             fix_refs=["准备系统盘"]),

    # ===== 操作系统版本 =====
    CheckDef(100011, "OS 版本受支持", "操作系统版本", "os_supported",
             expected="麒麟V10 SP1-3 / 统信V20 / HCE 2.0 / SUSE 12 SP5 / BCLINUX 21.10",
             mandatory=False,   # 需重装 OS，fix 无法处理，仅检查
             fix_refs=["准备系统盘"]),

    # ===== 系统服务 =====
    CheckDef(100012, "iptables active & enabled", "系统服务", "service_active",
             expected="active+enabled",
             key="iptables",
             mandatory=True,
             fix_refs=["配置操作系统防火墙", "配置系统服务-iptables"]),
    CheckDef(100061, "cgconfig active & enabled", "系统服务", "service_active",
             expected="active+enabled",
             key="cgconfig",
             fix_refs=["配置系统服务-cgconfig"]),
    CheckDef(100013, "firewalld 关闭", "系统服务", "service_inactive",
             expected="inactive",
             key="firewalld",
             mandatory=True,
             fix_refs=["配置操作系统防火墙"]),
    CheckDef(100078, "rngd/haveged 开启", "系统服务", "service_active",
             expected="active+enabled",
             key="rngd",
             mandatory=True,
             fix_refs=["配置系统服务-rngd/haveged"]),

    # ===== 时间同步 =====
    CheckDef(100014, "NTP/Chrony 启用 & 同步", "时间同步", "service_active",
             expected="chronyd or ntpd active+enabled, drift < 1s",
             key="chronyd",
             mandatory=True,
             fix_refs=["设置时钟源"]),
    CheckDef(100054, "硬件时钟已同步", "时间同步", "hwclock_sync",
             expected="System clock synchronized: yes",
             fix_refs=["设置时钟源"]),

    # ===== 字符集 =====
    CheckDef(100015, "字符集 en_US.UTF-8", "字符集参数", "locale_utf8",
             expected="en_US.UTF-8",
             mandatory=True,
             fix_refs=["设置字符集参数"]),

    # ===== MTU =====
    CheckDef(100016, "万兆网卡 MTU 1500/8192", "网卡MTU值", "mtu_ok",
             expected="X86: 1500, ARM: 8192",
             value="1500,8192",
             fix_refs=["设置网卡MTU值"]),

    # ===== HISTORY =====
    CheckDef(100017, "/etc/profile HISTSIZE=0", "HISTORY记录", "histsize_zero",
             expected="HISTSIZE=0",
             fix_refs=["关闭HISTORY记录"]),

    # ===== Python3 =====
    CheckDef(100018, "Python3 版本正确", "Python3", "python_version",
             expected="麒麟/统信/BCLINUX: 3.7.9, HCE: 3.9.9, SUSE: 3.8.5",
             mandatory=True,
             fix_refs=["安装主机的Python3"]),
    CheckDef(100071, "Python3 沿路权限 >= 555", "Python3", "path_perm_min",
             expected=">= 555",
             value="555",
             path="/usr/lib/python3*,/usr/lib64/python3*,/usr/local/lib/python3*,"
                  "/usr/local/lib64/python3*,/usr/local/python3/lib/python3*",
             mandatory=True,
             fix_refs=["Python3第三方库和模块的沿路权限"]),

    # ===== Cgroup =====
    CheckDef(100019, "Cgroup V1", "Cgroup版本", "cgroup_v1",
             expected="tmpfs (V1)",
             mandatory=True,
             fix_refs=["安装主机的Python3"]),  # 文档未给 cgroup 安装章节，挂此处仅占位

    # ===== 文件系统参数 ulimit =====
    CheckDef(100051, "ulimit -Sn >= 1000000", "文件系统参数", "ulimit_min",
             key="-Sn", value="1000000",
             expected=">= 1000000",
             mandatory=True,
             fix_refs=["配置文件系统参数"]),
    CheckDef(100052, "ulimit -Hn >= 1000000", "文件系统参数", "ulimit_min",
             key="-Hn", value="1000000",
             expected=">= 1000000",
             mandatory=True,
             fix_refs=["配置文件系统参数"]),
    CheckDef(100053, "stack size = 3072", "文件系统参数", "ulimit_eq",
             key="stack", value="3072",
             expected="3072",
             fix_refs=["配置文件系统参数"]),

    # ===== 工具类包 =====
    CheckDef(100055, "expect 已安装", "expect", "pkg",
             key="expect", expected="installed",
             mandatory=True,
             fix_refs=["安装Expect"]),
    CheckDef(100056, "sftp 可用", "SFTP", "sftp",
             expected="available",
             mandatory=False,   # 依赖 openssh-clients 包，无对应 fix 命令，仅检查
             fix_refs=[]),
    CheckDef(100010, "unzip 已安装", "unzip", "pkg",
             key="unzip", expected="installed",
             mandatory=True,
             fix_refs=["安装unzip"]),
    CheckDef(100057, "软件包管理器已配置", "软件包管理器", "pkgmgr_ok",
             expected="yum/dnf/zypper 仓库可用",
             mandatory=True,
             fix_refs=["配置软件包管理器"]),

    # ===== 沙箱目录 =====
    CheckDef(100008, "沙箱目录 /var/chroot 为空", "沙箱目录", "dir_empty",
             expected="目录不存在或为空",
             path="/var/chroot",
             mandatory=True,
             fix_refs=["清空沙箱目录"]),

    # ===== /etc/profile =====
    CheckDef(100060, "source /etc/profile 成功", "/etc/profile", "profile_source",
             expected="exit 0, no errors",
             mandatory=True,
             fix_refs=["配置/etc/profile文件"]),

    # ===== NUMA =====
    CheckDef(100062, "NUMA 分布均衡", "NUMA分布情况", "numa_balanced",
             expected="各 NUMA 节点内存差异 <= 20%",
             fix_refs=[]),

    CheckDef(100080, "SSH 服务运行端口", "系统服务", "ssh_port",
             expected="SSH 服务端口号",
             fix_refs=[]),

    CheckDef(100065, "ping localhost 成功", "网络通信检查", "ping_localhost",
             expected="0% loss",
             mandatory=True,
             fix_refs=["网络通信检查"]),

    # ===== 网络端口占用检查 =====
    CheckDef(100066, "8000 端口未被占用", "网络端口占用检查", "port_free",
             port=8000, expected="free"),
    CheckDef(100068, "12017 端口未被占用", "网络端口占用检查", "port_free",
             port=12017, expected="free",
             mandatory=True,
             fix_refs=["网络端口占用检查"]),
    CheckDef(100079, "8635/9200/9300 端口未被占用", "网络端口占用检查", "ports_free",
             key="8635,9200,9300", expected="free",
             mandatory=True,
             fix_refs=["网络端口占用检查"]),

    # ===== hosts =====
    CheckDef(100072, "/etc/hosts 不同时配置 IPv4+IPv6", "hosts文件", "hosts_ipv6",
             expected="仅 IPv4 或仅 IPv6，不能同时",
             mandatory=True,
             fix_refs=["检查hosts文件"]),

    # ===== TPOPS 标识码 =====
    CheckDef(100075, "主机未在其他 TPOPS 上添加", "TPOPS标识码", "tpops_unbound",
             expected="host_unique_code 不存在或为空",
             path="/dbs/osPatch/host_unique_code",
             mandatory=True,
             fix_refs=["检查TPOPS标识码"]),

    # ===== /etc/security =====
    CheckDef(100081, "/etc/security 权限正确", "/etc/security", "security_perm",
             expected="dir 755, files 644",
             mandatory=True,
             fix_refs=["检查/etc/security"]),

    # ===== 扩展项 (从 precheck 移植, ID 100082+) =====
    CheckDef(100082, "系统时区", "扩展项", "timezone_utc",
             expected="UTC",
             mandatory=False,   # 时区仅作警告——可能因业务保留本地时区
             fix_refs=["设置时区"]),
    CheckDef(100083, "swap 当前状态", "扩展项", "swap_active",
             expected="无 swap",
             mandatory=True,
             fix_refs=["关闭swap"]),
    CheckDef(100084, "/etc/fstab swap 已注释", "扩展项", "swap_fstab",
             expected="已注释",
             mandatory=True,
             fix_refs=["关闭swap"]),
    CheckDef(100085, "transparent_hugepage", "扩展项", "thp_never",
             expected="never",
             mandatory=True,
             fix_refs=["关闭THP"]),
    CheckDef(100086, "SELINUX 模式", "扩展项", "selinux_mode",
             expected="permissive",
             mandatory=True,
             fix_refs=["设置SELinux"]),
    CheckDef(100087, "python 软链接", "Python3", "python_link",
             expected="python → python3",
             mandatory=True,
             fix_refs=["创建Python软链接"]),
]


# =============================================================
# 修复章节数据
# =============================================================

# 每个章节的（标题, OS 过滤, 命令列表）
# OS 过滤: None = 通用, "suse" = SUSE 专属, "non_suse" = 麒麟/统信/HCE/BCLINUX
# 命令列表中的 {'os': 'suse'/'non_suse', 'cmd': '...'} 只会运行匹配 OS 的命令

FIX_SECTIONS: Dict[str, Dict] = {
    "配置软件包管理器": {
        "os_filter": None,
        "commands": [
            # 通用步骤：清理 / 创建 local.repo
            {"os": "non_suse", "cmd": "rm -r /etc/yum.repos.d/*"},
            {"os": "non_suse", "cmd": "echo -e '[local]\\nname=local\\nbaseurl=file:///mnt\\ngpgcheck=0\\nenabled=1' > /etc/yum.repos.d/local.repo"},
            {"os": "non_suse", "cmd": "yum clean all"},
            {"os": "non_suse", "cmd": "yum makecache"},
            {"os": "suse", "cmd": "rm -r /etc/zypp/repos.d/*"},
            {"os": "suse", "cmd": "zypper ar -fcg http://mirrors.huaweicloud.com/opensuse/distribution/leap/15.2/repo/oss HuaWeiCloud:15.2:OSS"},
            {"os": "suse", "cmd": "zypper ar -fcg http://mirrors.huaweicloud.com/opensuse/distribution/leap/15.2/repo/non-oss HuaWeiCloud:15.2:NON-OSS"},
            {"os": "suse", "cmd": "zypper ref"},
        ],
    },
    "准备数据盘": {
        "os_filter": None,
        "commands": [
            # 数据盘清理与初始化（注意：需要明确设备名，不能盲目执行）
            {"os": None, "cmd": "lsblk -f"},  # 仅查看，不破坏
        ],
    },
    "准备系统盘": {
        "os_filter": None,
        "commands": [],  # 文档无 shell 命令，仅建议重装或选 DM 模式
    },
    "配置操作系统防火墙": {
        "os_filter": None,
        "commands": [
            {"os": "non_suse", "cmd": "systemctl stop firewalld.service 2>/dev/null || true"},
            {"os": "non_suse", "cmd": "systemctl disable firewalld.service 2>/dev/null || true"},
            {"os": "non_suse", "cmd": "systemctl unmask iptables 2>/dev/null || true"},
            {"os": "non_suse", "cmd": "systemctl start iptables 2>/dev/null || true"},
            {"os": "non_suse", "cmd": "systemctl enable iptables 2>/dev/null || true"},
            {"os": "suse", "cmd": "systemctl stop SuSEfirewall2.service 2>/dev/null || true"},
            {"os": "suse", "cmd": "systemctl disable SuSEfirewall2.service 2>/dev/null || true"},
            {"os": None, "cmd": "sed -i 's/^SELINUX=.*/SELINUX=permissive/' /etc/selinux/config 2>/dev/null || true"},
        ],
    },
    "配置系统服务-iptables": {
        "os_filter": None,
        "commands": [
            {"os": None, "cmd": "systemctl start iptables 2>/dev/null || true"},
            {"os": None, "cmd": "systemctl enable iptables 2>/dev/null || true"},
            {"os": None, "cmd": "systemctl unmask iptables 2>/dev/null || true"},
        ],
    },
    "配置系统服务-cgconfig": {
        "os_filter": None,
        "commands": [
            {"os": None, "cmd": "systemctl start cgconfig 2>/dev/null || true"},
            {"os": None, "cmd": "systemctl enable cgconfig 2>/dev/null || true"},
            {"os": None, "cmd": "systemctl unmask cgconfig 2>/dev/null || true"},
        ],
    },
    "配置系统服务-rngd/haveged": {
        "os_filter": None,
        "commands": [
            {"os": None, "cmd": "systemctl start rngd 2>/dev/null || true"},
            {"os": None, "cmd": "systemctl enable rngd 2>/dev/null || true"},
            {"os": None, "cmd": "systemctl start haveged 2>/dev/null || true"},
            {"os": None, "cmd": "systemctl enable haveged 2>/dev/null || true"},
        ],
    },
    "设置时钟源": {
        "os_filter": None,
        "commands": [
            {"os": None, "cmd": "{PKG_INSTALL_CHRONY}"},
            {"os": None, "cmd": "systemctl enable chronyd 2>/dev/null || true"},
            {"os": None, "cmd": "systemctl restart chronyd 2>/dev/null || true"},
        ],
    },
    "设置字符集参数": {
        "os_filter": None,
        "commands": [
            # 幂等：去重已有 LANG 行后写回；不重复追加
            {"os": None, "cmd": "f=/etc/profile; sed -i '/^[[:space:]]*\\(export[[:space:]]\\+\\)\\{0,1\\}LANG=/d' $f && echo 'export LANG=en_US.UTF-8' >> $f"},
            {"os": None, "cmd": "echo 'LANG=en_US.UTF-8' > /etc/locale.conf 2>/dev/null || true"},
            {"os": None, "cmd": "echo 'LANG=en_US.UTF-8' > /etc/sysconfig/i18n 2>/dev/null || true"},
            # 验证：source 后无报错且 LANG 取到正确值
            {"os": None, "cmd": "bash -c 'set -e; source /etc/profile >/dev/null 2>&1; [ \"$LANG\" = \"en_US.UTF-8\" ] && echo OK'"},
        ],
    },
    "设置网卡MTU值": {
        "os_filter": None,
        "commands": [
            # 修改 ifcfg-* 文件的 MTU=1500（X86），不重启网络以免断连
            {"os": None, "cmd": "for f in /etc/sysconfig/network-scripts/ifcfg-*; do grep -q '^MTU=' \"$f\" 2>/dev/null && sed -i 's/^MTU=.*/MTU=1500/' \"$f\" || echo 'MTU=1500' >> \"$f\"; done 2>/dev/null || true"},
            {"os": "suse", "cmd": "for f in /etc/sysconfig/network/ifcfg-*; do grep -q '^MTU=' \"$f\" 2>/dev/null && sed -i 's/^MTU=.*/MTU=1500/' \"$f\" || echo 'MTU=1500' >> \"$f\"; done 2>/dev/null || true"},
        ],
    },
    "关闭HISTORY记录": {
        "os_filter": None,
        "commands": [
            {"os": None, "cmd": "sed -i 's/^HISTSIZE=.*/HISTSIZE=0/' /etc/profile 2>/dev/null || echo 'HISTSIZE=0' >> /etc/profile"},
        ],
    },
    "安装主机的Python3": {
        "os_filter": None,
        "commands": [
            {"os": None, "cmd": "{PKG_INSTALL_PYTHON3}"},
        ],
    },
    "Python3第三方库和模块的沿路权限": {
        "os_filter": None,
        "commands": [
            {"os": None, "cmd": "chmod -R 755 /usr/lib/python3* 2>/dev/null || true"},
            {"os": None, "cmd": "chmod -R 755 /usr/lib64/python3* 2>/dev/null || true"},
            {"os": None, "cmd": "chmod -R 755 /usr/local/lib/python3* 2>/dev/null || true"},
            {"os": None, "cmd": "chmod -R 755 /usr/local/lib64/python3* 2>/dev/null || true"},
        ],
    },
    "配置文件系统参数": {
        "os_filter": None,
        "commands": [
            {"os": None, "cmd": "f=/etc/security/limits.conf; grep -q '^[*][[:space:]]\\+soft[[:space:]]\\+nofile' $f 2>/dev/null && sed -i 's|^[*][[:space:]]\\+soft[[:space:]]\\+nofile.*|* soft nofile 1000000|' $f || echo '* soft nofile 1000000' >> $f"},
            {"os": None, "cmd": "f=/etc/security/limits.conf; grep -q '^[*][[:space:]]\\+hard[[:space:]]\\+nofile' $f 2>/dev/null && sed -i 's|^[*][[:space:]]\\+hard[[:space:]]\\+nofile.*|* hard nofile 1000000|' $f || echo '* hard nofile 1000000' >> $f"},
            {"os": None, "cmd": "f=/etc/security/limits.conf; grep -q '^[*][[:space:]]\\+soft[[:space:]]\\+stack' $f 2>/dev/null && sed -i 's|^[*][[:space:]]\\+soft[[:space:]]\\+stack.*|* soft stack 3072|' $f || echo '* soft stack 3072' >> $f"},
            {"os": None, "cmd": "f=/etc/security/limits.conf; grep -q '^[*][[:space:]]\\+hard[[:space:]]\\+stack' $f 2>/dev/null && sed -i 's|^[*][[:space:]]\\+hard[[:space:]]\\+stack.*|* hard stack 3072|' $f || echo '* hard stack 3072' >> $f"},
        ],
    },
    "安装Expect": {
        "os_filter": None,
        "commands": [
            {"os": None, "cmd": "{PKG_INSTALL_EXPECT}"},
        ],
    },
    "清空沙箱目录": {
        "os_filter": None,
        "commands": [
            # 仅在沙箱目录存在且为空时安全；不直接 rm -r，需要先确认
            {"os": None, "cmd": "ls -Al /var/chroot 2>&1 | head -3"},
        ],
    },
    "安装unzip": {
        "os_filter": None,
        "commands": [
            {"os": None, "cmd": "{PKG_INSTALL_UNZIP}"},
        ],
    },
    "配置/etc/profile文件": {
        "os_filter": None,
        "commands": [
            # 仅注释掉 TMOUT 之类可能导致 source 失败的配置
            {"os": None, "cmd": "sed -i 's/^TMOUT=.*/#TMOUT=300/' /etc/profile 2>/dev/null || true"},
            {"os": None, "cmd": "bash -n /etc/profile && echo 'syntax OK'"},
        ],
    },
    "网络通信检查": {
        "os_filter": None,
        "commands": [
            # 仅为示例：尝试连接到 TPOPS 节点（需要环境变量 TPOPS_IP）
            {"os": None, "cmd": "(timeout 3 bash -c \"</dev/tcp/${TPOPS_IP:-127.0.0.1}/8601\" 2>/dev/null && echo '8601 OK' || echo '8601 unreachable')"},
            {"os": None, "cmd": "(timeout 3 bash -c \"</dev/tcp/${TPOPS_IP:-127.0.0.1}/10022\" 2>/dev/null && echo '10022 OK' || echo '10022 unreachable')"},
        ],
    },
    "网络端口占用检查": {
        "os_filter": None,
        "commands": [],  # 仅检查，不自动 kill
    },
    "检查hosts文件": {
        "os_filter": None,
        "commands": [
            # 仅在确实需要时由用户手动操作
            {"os": None, "cmd": "cat /etc/hosts | grep -E 'localhost|ipv'"},
        ],
    },
    "检查TPOPS标识码": {
        "os_filter": None,
        "commands": [],  # 仅检查
    },
    "检查/etc/security": {
        "os_filter": None,
        "commands": [
            {"os": None, "cmd": "chmod 755 /etc/security"},
            {"os": None, "cmd": "chmod 644 /etc/security/*.conf 2>/dev/null || true"},
        ],
    },
    # 扩展项 fix 章节
    "设置时区": {
        "os_filter": None,
        "commands": [
            {"os": None, "cmd": "timedatectl set-timezone UTC 2>/dev/null || (rm -f /etc/localtime && ln -sf /usr/share/zoneinfo/UTC /etc/localtime)"},
        ],
    },
    "关闭swap": {
        "os_filter": None,
        "commands": [
            {"os": None, "cmd": "swapoff -a 2>/dev/null || true"},
            {"os": None, "cmd": "sed -i.bak '/\\bswap\\b/s/^/#/' /etc/fstab 2>/dev/null || true"},
        ],
    },
    "关闭THP": {
        "os_filter": None,
        "commands": [
            {"os": None, "cmd": "echo never > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true"},
            {"os": None, "cmd": "echo never > /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null || true"},
            {"os": None, "cmd": "(grep -q transparent_hugepage /etc/rc.d/rc.local 2>/dev/null || echo -e '\\n# Disable THP\\nif test -f /sys/kernel/mm/transparent_hugepage/enabled; then\\n  echo never > /sys/kernel/mm/transparent_hugepage/enabled\\n  echo never > /sys/kernel/mm/transparent_hugepage/defrag\\nfi' >> /etc/rc.d/rc.local) 2>/dev/null || true"},
        ],
    },
    "设置SELinux": {
        "os_filter": None,
        "commands": [
            {"os": None, "cmd": "sed -i 's/^SELINUX=.*/SELINUX=permissive/' /etc/selinux/config 2>/dev/null || true"},
            {"os": None, "cmd": "setenforce 0 2>/dev/null || true"},
        ],
    },
    "创建Python软链接": {
        "os_filter": None,
        "commands": [
            # 直接把 python 指向 python3（一层软链，绝不会形成环）
            {"os": None, "cmd": "ln -sf /usr/bin/python3 /usr/bin/python"},
        ],
    },
}


# =============================================================
# 运行时：检查执行器
# =============================================================

@dataclass
class CheckResult:
    id: int
    name: str
    status: Status
    current: str = ""
    expected: str = ""
    message: str = ""
    fix_refs: List[str] = field(default_factory=list)
    mandatory: bool = False  # 是否强制校验

    @property
    def is_not_ok(self) -> bool:
        """是否需要修复（FAIL 且 强制校验 → NOT OK；FAIL 且 非强制 → WARNING）."""
        return self.status == Status.FAIL

    @property
    def severity_label(self) -> str:
        """根据状态 + 强制标志返回严重程度标签."""
        if self.status == Status.PASS:
            return "OK"
        if self.status == Status.ERROR:
            return "ERROR"
        # FAIL
        return "NOT OK" if self.mandatory else "WARNING"

    @property
    def display_item(self) -> str:
        """表格中的"item"列：只用中文名，不带 ID."""
        return self.name

    @property
    def display_current(self) -> str:
        """表格中的"current_value"列（清理多空白/换行，便于对齐）."""
        v = (self.current or "").strip()
        v = re.sub(r"\s+", " ", v)   # 多个空白/换行合并为单个空格
        if not v:
            return "(空)"
        return v

    @property
    def display_expected(self) -> str:
        """表格中的"expected_value"列（清理多空白/换行，便于对齐）."""
        v = (self.expected or "").strip()
        v = re.sub(r"\s+", " ", v)   # 多个空白/换行合并为单个空格
        if not v:
            return "-"
        return v

    @property
    def display_status_colored(self) -> str:
        """带 ANSI 颜色的状态字符串."""
        s = self.severity_label
        if s == "OK":
            return f"{C_GREEN}{s}{C_RESET}"
        if s == "WARNING":
            return f"{C_YELLOW}{s}{C_RESET}"
        if s == "NOT OK":
            return f"{C_RED}{C_BOLD}{s}{C_RESET}"
        return f"{C_MAGENTA}{s}{C_RESET}"


def _is_port_listening(port: int) -> bool:
    rc, out, _ = run_shell(f"ss -tunlp 2>/dev/null | grep -E ':{port}\\b'")
    if rc == 0 and out.strip():
        return True
    rc2, out2, _ = run_shell(f"netstat -tunlp 2>/dev/null | grep -E ':{port}\\b'")
    return rc2 == 0 and out2.strip() != ""


# ---------------------------------------------------------------
# 主机信息采集工具（供 check_type 分支复用）
# ---------------------------------------------------------------

_SUPPORTED_OS_HUMAN = "麒麟V10 SP1-3 / 统信V20 / HCE 2.0 / SUSE 12 SP5 / BCLINUX 21.10"
# os-release ID -> 允许的 VERSION_ID 集合
_SUPPORTED_OS: Dict[str, Set[str]] = {
    "kylin": {"V10", "(V10)"},
    "uos": {"20", "20.0"},
    "hce": {"2.0", "2"},
    "sles": {"12.5"},
    "bclinux": {"21.10"},
}
# os-release ID -> 期望的 python3 版本
_PYTHON_BY_OS: Dict[str, str] = {
    "kylin": "3.7.9",
    "uos": "3.7.9",
    "bclinux": "3.7.9",
    "hce": "3.9.9",
    "sles": "3.8.5",
}


def _cpu_cores() -> int:
    """逻辑核数。"""
    rc, out, _ = run_shell("nproc 2>/dev/null")
    try:
        return int(out.strip())
    except ValueError:
        pass
    rc, out, _ = run_shell("grep -c '^processor' /proc/cpuinfo 2>/dev/null")
    try:
        return int(out.strip())
    except ValueError:
        return 0


def _cpu_model() -> str:
    rc, out, _ = run_shell("lscpu 2>/dev/null | grep -m1 'Model name'")
    if rc != 0 or not out.strip():
        rc, out, _ = run_shell("grep -m1 'model name' /proc/cpuinfo 2>/dev/null")
    m = re.search(r":\s*(.+)", out.strip())
    return m.group(1).strip() if m else out.strip()


def _mem_total_gb() -> float:
    """物理内存总量 (GB)，取 /proc/meminfo 的 MemTotal。"""
    try:
        for line in open("/proc/meminfo", encoding="utf-8", errors="ignore"):
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) / (1024 * 1024)
    except Exception:
        pass
    rc, out, _ = run_shell("free -g 2>/dev/null | awk '/^Mem:/{print $2}'")
    try:
        return float(out.strip())
    except ValueError:
        return 0.0


def _lsblk_disks() -> List[Tuple[str, str]]:
    """返回 [(盘名, rota)]，只取 TYPE=disk 的物理盘（已剔除 loop/rom）。"""
    rc, out, _ = run_shell(
        "lsblk -d -n -o NAME,ROTA,TYPE 2>/dev/null | awk '$3==\"disk\"{print $1, $2}'")
    disks: List[Tuple[str, str]] = []
    for line in out.strip().splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] not in ("loop", "rom", "sr"):
            disks.append((parts[0], parts[1]))
    return disks


def _mount_source_for(path: str) -> str:
    """路径所在的底层块设备名（/dev/sda -> sda），非块设备返回 ""。"""
    try:
        real = os.path.realpath(path)
        name = os.path.basename(real)
        if not name:
            return ""
        # 去掉分区号后缀：sda1 -> sda, nvme0n1p1 -> nvme0n1
        m = re.match(r"^(.+?)(?:p?\d+)$", name)
        return m.group(1) if m else name
    except Exception:
        return ""


def _system_disks() -> List[str]:
    """承载根目录 "/" 的物理盘列表。"""
    sysdisk = _mount_source_for("/")
    disks = [n for n, _ in _lsblk_disks()]
    if sysdisk and sysdisk in disks:
        return [sysdisk]
    # 根在 overlay/网络文件系统等场景下，回退为所有物理盘
    return disks


def _dirty_data_disks() -> List[str]:
    """有分区或被挂载的数据盘（非系统盘）。"""
    sysdisk = _mount_source_for("/")
    rc, out, _ = run_shell(
        "lsblk -n -o NAME,TYPE,MOUNTPOINT 2>/dev/null")
    dirty: List[str] = []
    for line in out.strip().splitlines():
        parts = line.split()
        if not parts:
            continue
        name, ntype = parts[0], (parts[1] if len(parts) > 1 else "")
        if ntype != "disk" or name == sysdisk:
            continue
        mounted = " ".join(parts[2:]).strip()
        if mounted:
            dirty.append(f"{name}(已挂载:{mounted})")
            continue
        # 该盘下是否有分区
        rc2, out2, _ = run_shell(f"lsblk -n -o TYPE {name} 2>/dev/null | tail -n +2")
        if any(t.strip() == "part" for t in out2.strip().splitlines()):
            dirty.append(f"{name}(有分区)")
    return dirty


# 已知盘符前缀，从长到短匹配；必须先匹配长的（避免 "sd" 截走 "nvme"）
_DISK_PREFIXES = ("nvme", "xvd", "sd", "vd", "hd")


def _disk_name_kind(name: str) -> str:
    """取盘符前缀。nvme0n1→nvme, sda→sd, sdb1→sd, vda→vd, xvdb→xvd。"""
    for p in _DISK_PREFIXES:
        if name.startswith(p):
            return p
    # 未知前缀：去掉尾部字母直到首字符为字母 + 后续至少一位字母
    m = re.match(r"^([a-z]+?)(?=\d|$)", name)
    return m.group(1) if m else name


def _disk_name_kinds() -> Set[str]:
    """磁盘盘符前缀集合：sd / vd / xvd / nvme / hd ..."""
    return {_disk_name_kind(n) for n, _ in _lsblk_disks()}


def _os_version_supported(os_id: str, ver: str) -> Tuple[bool, str]:
    allowed = _SUPPORTED_OS.get(os_id)
    human = f"{os_id or 'unknown'} {ver}".strip()
    if not allowed:
        return False, human
    norm = ver.strip().upper()
    return norm in allowed or norm.lstrip("(").rstrip(")") in allowed, human


def _expected_python_version(host: HostInfo) -> str:
    return _PYTHON_BY_OS.get(host.os_id.lower(), "")


def _current_lang() -> str:
    """当前 LANG，依次查环境变量 / /etc/locale.conf / /etc/locale。"""
    lang = os.environ.get("LANG", "")
    if lang:
        return lang.strip()
    for p in ("/etc/locale.conf", "/etc/locale"):
        if os.path.exists(p):
            try:
                for line in open(p, encoding="utf-8", errors="ignore"):
                    if line.strip().startswith("LANG="):
                        return line.split("=", 1)[1].strip().strip('"')
            except Exception:
                pass
    rc, out, _ = run_shell("locale 2>/dev/null | grep -m1 '^LANG='")
    return out.strip().replace("LANG=", "").strip()


def _nic_mtus() -> List[int]:
    """所有非 lo 网卡的 MTU 列表。"""
    rc, out, _ = run_shell(
        "ip -o link show 2>/dev/null | awk -F': ' '{print $2, $NF}'")
    mtus: List[int] = []
    for line in out.strip().splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0] == "lo":
            continue
        m = re.search(r"mtu\s+(\d+)", line)
        if m:
            mtus.append(int(m.group(1)))
    if not mtus:  # 老系统无 ip 命令，回退 ifconfig
        rc, out, _ = run_shell("ifconfig 2>/dev/null | grep -o 'MTU:[0-9]*'")
        for line in out.strip().splitlines():
            m = re.search(r"(\d+)", line)
            if m:
                mtus.append(int(m.group(1)))
    return mtus


def _numa_mem_sizes_mb() -> List[int]:
    """各 NUMA 节点的内存大小 (MB)。无法获取时返回空列表。"""
    rc, out, _ = run_shell("numactl --hardware 2>/dev/null")
    sizes: List[int] = []
    if rc == 0 and out.strip():
        for line in out.splitlines():
            m = re.match(r"^node\s+\d+\s+size:\s+(\d+)\s*MB", line.strip(), re.I)
            if m:
                sizes.append(int(m.group(1)))
        if sizes:
            return sizes
    # 回退：/sys/devices/system/node/nodeN/meminfo
    try:
        for d in sorted(os.listdir("/sys/devices/system/node")):
            m = re.match(r"^node(\d+)$", d)
            if not m:
                continue
            with open(f"/sys/devices/system/node/{d}/meminfo",
                      encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    if "MemTotal" in line:
                        sizes.append(int(line.split()[-2]) // 1024)
                        break
    except Exception:
        pass
    return sizes


def _ssh_listening_port() -> str:
    """SSH 服务当前监听端口（字符串）。检测失败返回空串。

    优先读 /etc/ssh/sshd_config 的 Port 指令，否则扫 ss 输出中的 sshd 进程。
    """
    # 1) 从 sshd_config 解析 Port 指令
    try:
        with open("/etc/ssh/sshd_config", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                m = re.match(r"^Port\s+(\d+)", s, re.I)
                if m:
                    return m.group(1)
    except Exception:
        pass
    # 2) 回退：扫描 ss 中 sshd 监听端口
    rc, out, _ = run_shell("ss -tlnp 2>/dev/null | grep -i sshd")
    if rc == 0 and out.strip():
        m = re.search(r":(\d+)\s", out)
        if m:
            return m.group(1)
    return ""


def _check_one(c: CheckDef, host: HostInfo) -> CheckResult:
    """执行单个 check，返回结果."""
    try:
        if c.check_type == "ulimit_min":
            rc, out, _ = run_shell(f"ulimit {c.key}")
            actual = out.strip()
            try:
                ok = int(actual) >= int(c.value)
            except ValueError:
                ok = False
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=actual, expected=f">= {c.value}",
                message="OK" if ok else f"ulimit {c.key} = {actual}, 期望 >= {c.value}",
                fix_refs=c.fix_refs,
                mandatory=c.mandatory,
            )

        if c.check_type == "ulimit_eq":
            rc, out, _ = run_shell(f"ulimit {c.key}")
            actual = out.strip()
            ok = (actual == c.value)
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=actual, expected=c.value,
                message="OK" if ok else f"期望 {c.value} 实际 {actual}",
                fix_refs=c.fix_refs,
                mandatory=c.mandatory,
            )

        if c.check_type == "service_active":
            rc_a, out_a, _ = run_shell(f"systemctl is-active {c.key}")
            rc_e, out_e, _ = run_shell(f"systemctl is-enabled {c.key}")
            active = out_a.strip()
            enabled = out_e.strip()
            # is-enabled 接受 enabled/static/alias（Ubuntu 上 chronyd 即为 alias）
            ok = (active == "active" and enabled in (
                "enabled", "static", "enabled-runtime", "alias",
                "indirect", "generated",
            ))
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=f"{c.key}: active={active}, enabled={enabled}",
                expected=c.expected,
                message="OK" if ok else f"需要 active+enabled，当前 active={active}, enabled={enabled}",
                fix_refs=c.fix_refs,
                mandatory=c.mandatory,
            )

        if c.check_type == "service_inactive":
            rc_a, out_a, _ = run_shell(f"systemctl is-active {c.key}")
            active = out_a.strip()
            ok = (active in ("inactive", "unknown", "failed", "not-found"))
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=f"{c.key}: {active}",
                expected=c.expected,
                message="OK" if ok else f"需要 inactive，实际 {active}",
                fix_refs=c.fix_refs,
                mandatory=c.mandatory,
            )

        if c.check_type == "ssh_port":
            port = _ssh_listening_port()
            return CheckResult(
                c.id, c.name,
                Status.PASS,
                current=port if port else "未监听",
                expected=c.expected,
                message="OK" if port else "未检测到 SSH 监听端口",
                fix_refs=c.fix_refs,
                mandatory=c.mandatory,
            )

        if c.check_type == "pkg":
            rc, out, _ = run_shell(f"command -v {c.key} || rpm -q {c.key} 2>/dev/null")
            installed = (rc == 0 and out.strip() != "")
            return CheckResult(
                c.id, c.name,
                Status.PASS if installed else Status.FAIL,
                current=out.strip() or "(not found)",
                expected=c.expected,
                message="OK" if installed else f"{c.key} 未安装",
                fix_refs=c.fix_refs,
                mandatory=c.mandatory,
            )

        if c.check_type == "port_free":
            listening = _is_port_listening(c.port)
            ok = not listening
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=f"port {c.port} {'IN USE' if listening else 'free'}",
                expected=c.expected,
                message="OK" if ok else f"端口 {c.port} 已被占用",
                fix_refs=c.fix_refs,
                mandatory=c.mandatory,
            )

        if c.check_type == "ports_free":
            ports = [int(p) for p in c.key.split(",") if p.strip().isdigit()]
            occupied = [p for p in ports if _is_port_listening(p)]
            ok = not occupied
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=f"占用: {occupied}" if occupied else "全部 free",
                expected=c.expected,
                message="OK" if ok else f"端口 {occupied} 已被占用",
                fix_refs=c.fix_refs,
                mandatory=c.mandatory,
            )

        if c.check_type == "cgroup_v1":
            rc, out, _ = run_shell("stat -fc %T /sys/fs/cgroup/ 2>/dev/null")
            ver = out.strip()
            ok = (ver == "tmpfs")
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=ver or "(unknown)",
                expected=c.expected,
                message="OK (V1)" if ok else f"非 V1，实际 {ver}",
                fix_refs=c.fix_refs,
                mandatory=c.mandatory,
            )

        if c.check_type == "profile_source":
            rc, out, err = run_shell("bash -c 'set -e; source /etc/profile >/dev/null 2>&1 && echo OK || echo FAIL'")
            ok = (rc == 0 and "OK" in out)
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current="OK" if ok else (err.strip() or out.strip()),
                expected=c.expected,
                message="OK" if ok else f"source 失败: {err.strip() or out.strip()}",
                fix_refs=c.fix_refs,
                mandatory=c.mandatory,
            )

        if c.check_type == "hosts_ipv6":
            rc, out, _ = run_shell("cat /etc/hosts 2>/dev/null")
            text = out.lower()
            has_v4 = ("localhost4" in text or "ipv4-localhost" in text)
            has_v6 = ("localhost6" in text or "ipv6-localhost" in text)
            ok = not (has_v4 and has_v6)
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=f"v4={has_v4} v6={has_v6}",
                expected=c.expected,
                message="OK" if ok else "同时配置了 IPv4 和 IPv6，请删除 IPv6 localhost 行",
                fix_refs=c.fix_refs,
                mandatory=c.mandatory,
            )

        if c.check_type == "sftp":
            rc, out, _ = run_shell("command -v sftp")
            ok = (rc == 0 and out.strip() != "")
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=out.strip() or "(not found)",
                expected=c.expected,
                message="OK" if ok else "sftp 命令未找到",
                fix_refs=c.fix_refs,
                mandatory=c.mandatory,
            )

        if c.check_type == "security_perm":
            rc1, out1, _ = run_shell("stat -c '%a' /etc/security 2>/dev/null")
            rc2, out2, _ = run_shell("ls -1 /etc/security/*.conf 2>/dev/null | xargs -I{} stat -c '%a {}' {} 2>/dev/null | head -5")
            dir_perm = out1.strip()
            ok_dir = (dir_perm in ("755", "775"))
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok_dir else Status.FAIL,
                current=f"dir={dir_perm}",
                expected=c.expected,
                message="OK" if ok_dir else f"/etc/security 权限 {dir_perm} 非 755/775",
                fix_refs=c.fix_refs,
                mandatory=c.mandatory,
            )

        # ---------- CPU 和内存 ----------
        if c.check_type == "cpu_cores":
            cores = _cpu_cores()
            want = int(c.value or 4)
            ok = cores >= want
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=f"{cores} 核",
                expected=c.expected,
                message="OK" if ok else f"vCPU {cores} < {want}",
                fix_refs=c.fix_refs, mandatory=c.mandatory,
            )

        if c.check_type == "cpu_model":
            model = _cpu_model()
            keys = [k.strip() for k in (c.value or "").split(",") if k.strip()]
            ok = any(k.lower() in model.lower() for k in keys)
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=model or "(未知)",
                expected=c.expected,
                message="OK" if ok else f"CPU 型号不在推荐列表: {model or '(未知)'}",
                fix_refs=c.fix_refs, mandatory=c.mandatory,
            )

        if c.check_type == "mem_gb":
            mem_gb = _mem_total_gb()
            want = float(c.value or 16)
            ok = mem_gb >= want
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=f"{mem_gb:.1f} G",
                expected=c.expected,
                message="OK" if ok else f"内存 {mem_gb:.1f}G < {want:g}G",
                fix_refs=c.fix_refs, mandatory=c.mandatory,
            )

        if c.check_type == "cpu_mem_ratio":
            cores = _cpu_cores()
            mem_gb = _mem_total_gb()
            targets = [float(x) for x in (c.value or "4,8").split(",") if x.strip()]
            ratio = mem_gb / cores if cores else 0.0
            ok = any(abs(ratio - t) <= 0.5 for t in targets)
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=f"1:{ratio:.1f} ({cores} 核 / {mem_gb:.1f}G)",
                expected=c.expected,
                message="OK" if ok else f"内存/核数 = 1:{ratio:.1f}，推荐 1:4 或 1:8 (±0.5)",
                fix_refs=c.fix_refs, mandatory=c.mandatory,
            )

        # ---------- 磁盘 ----------
        if c.check_type == "disk_rotational":
            rota = [n for n, r in _lsblk_disks() if r == "1"]
            ok = not rota
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current="全部 SSD" if ok else f"机械盘: {', '.join(rota)}",
                expected=c.expected,
                message="OK" if ok else f"存在机械盘 (rota=1): {', '.join(rota)}",
                fix_refs=c.fix_refs, mandatory=c.mandatory,
            )

        if c.check_type == "data_disk_clean":
            bad = _dirty_data_disks()
            ok = not bad
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current="数据盘干净" if ok else f"不干净: {', '.join(bad)}",
                expected=c.expected,
                message="OK" if ok else f"以下数据盘存在分区或挂载: {', '.join(bad)}",
                fix_refs=c.fix_refs, mandatory=c.mandatory,
            )

        if c.check_type == "disk_naming":
            kinds = _disk_name_kinds()
            ok = len(kinds) <= 1
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=", ".join(sorted(kinds)) or "(无磁盘)",
                expected=c.expected,
                message="OK" if ok else f"盘符前缀混用: {', '.join(sorted(kinds))}",
                fix_refs=c.fix_refs, mandatory=c.mandatory,
            )

        if c.check_type == "sysdisk_single":
            sysdisks = _system_disks()
            ok = len(sysdisks) == 1
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=", ".join(sysdisks) or "(未找到)",
                expected=c.expected,
                message="OK" if ok else f"系统盘应为单盘，实际 {len(sysdisks)} 块: {', '.join(sysdisks)}",
                fix_refs=c.fix_refs, mandatory=c.mandatory,
            )

        if c.check_type == "sysdisk_not_nvme":
            sysdisks = _system_disks()
            nvme = [d for d in sysdisks if d.startswith("nvme")]
            ok = not nvme
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=", ".join(sysdisks) or "(未找到)",
                expected=c.expected,
                message="OK" if ok else f"系统盘不能使用 NVMe: {', '.join(nvme)}",
                fix_refs=c.fix_refs, mandatory=c.mandatory,
            )

        # ---------- 操作系统 ----------
        if c.check_type == "os_supported":
            data = _read_os_release()
            os_id = data.get("ID", "").lower()
            ver = data.get("VERSION_ID", "")
            ok, human = _os_version_supported(os_id, ver)
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=f"{os_id or 'unknown'} {ver}".strip(),
                expected=c.expected,
                message="OK" if ok else f"不支持的操作系统: {human}；支持: " + _SUPPORTED_OS_HUMAN,
                fix_refs=c.fix_refs, mandatory=c.mandatory,
            )

        if c.check_type == "locale_utf8":
            lang = _current_lang()
            # 大小写、连字符、点号、下划线都视为等价
            # en_US.UTF-8 == en_us.utf-8 == enusutf8
            lang_norm = lang.lower().replace("-", "").replace(".", "").replace("_", "")
            ok = "enusutf8" in lang_norm
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=lang or "(未设置)",
                expected=c.expected,
                message="OK" if ok else f"LANG={lang or '(未设置)'}，应为 en_US.UTF-8",
                fix_refs=c.fix_refs, mandatory=c.mandatory,
            )

        # ---------- 网络 / 时钟 ----------
        if c.check_type == "mtu_ok":
            mtus = _nic_mtus()
            allowed = {int(x) for x in (c.value or "1500,8192").split(",") if x.strip()}
            bad = sorted(m for m in mtus if m not in allowed)
            ok = bool(mtus) and not bad
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=", ".join(str(m) for m in mtus) or "(未找到网卡)",
                expected=c.expected,
                message="OK" if ok else (
                    f"MTU 非法: {bad}" if bad else "未找到任何网卡 MTU"),
                fix_refs=c.fix_refs, mandatory=c.mandatory,
            )

        if c.check_type == "hwclock_sync":
            rc, out, _ = run_shell("timedatectl 2>/dev/null")
            m = re.search(r"System clock synchronized:\s*(\S+)", out) if rc == 0 else None
            current = m.group(1) if m else "(未知)"
            ok = (current == "yes")
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=current,
                expected=c.expected,
                message="OK" if ok else f"System clock synchronized = {current}",
                fix_refs=c.fix_refs, mandatory=c.mandatory,
            )

        if c.check_type == "ping_localhost":
            rc, out, _ = run_shell("ping -c 2 -W 2 localhost 2>&1", timeout=15)
            m = re.search(r"(\d+(?:\.\d+)?)% packet loss", out)
            loss = f"{float(m.group(1)):g}%" if m else "(未知)"
            ok = (rc == 0 and m is not None and float(m.group(1)) == 0)
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=f"loss={loss}",
                expected=c.expected,
                message="OK" if ok else f"ping localhost 丢包率 {loss}",
                fix_refs=c.fix_refs, mandatory=c.mandatory,
            )

        # ---------- 系统文件 ----------
        if c.check_type == "histsize_zero":
            rc, out, _ = run_shell("grep -E '^\\s*HISTSIZE\\s*=' /etc/profile 2>/dev/null")
            raw = out.strip().splitlines()
            if not raw:
                return CheckResult(c.id, c.name, Status.FAIL, current="(未设置)",
                                   expected=c.expected,
                                   message="/etc/profile 中未设置 HISTSIZE",
                                   fix_refs=c.fix_refs, mandatory=c.mandatory)
            current = raw[-1].strip()
            val = re.sub(r"^\s*HISTSIZE\s*=\s*", "", current).strip()
            ok = val in ("0", '"0"', "'0'")
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=current,
                expected=c.expected,
                message="OK" if ok else f"{current}，应为 HISTSIZE=0",
                fix_refs=c.fix_refs, mandatory=c.mandatory,
            )

        if c.check_type == "dir_empty":
            p = c.path
            if not os.path.isdir(p):
                return CheckResult(c.id, c.name, Status.PASS, current="目录不存在",
                                   expected=c.expected, message="OK (目录不存在)",
                                   fix_refs=c.fix_refs, mandatory=c.mandatory)
            entries = os.listdir(p)
            ok = not entries
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=f"{len(entries)} 个条目" if entries else "空",
                expected=c.expected,
                message="OK" if ok else f"{p} 非空: {', '.join(entries[:5])}"
                                          + (" ..." if len(entries) > 5 else ""),
                fix_refs=c.fix_refs, mandatory=c.mandatory,
            )

        if c.check_type == "tpops_unbound":
            p = c.path
            code = ""
            if os.path.exists(p):
                try:
                    code = open(p, encoding="utf-8", errors="ignore").read().strip()
                except Exception:
                    code = ""
            ok = not code
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=code or "(不存在/为空)",
                expected=c.expected,
                message="OK" if ok else f"{p} 存在标识码 {code}，主机可能已在其他 TPOPS 上添加",
                fix_refs=c.fix_refs, mandatory=c.mandatory,
            )

        # ---------- Python3 / 软件包 / NUMA ----------
        if c.check_type == "python_version":
            rc, out, err = run_shell("python3 --version 2>&1", timeout=15)
            ver = ""
            m = re.search(r"Python\s+(\d+\.\d+\.\d+)", out or err or "")
            if m:
                ver = m.group(1)
            want = _expected_python_version(host)
            ok = bool(want) and ver == want
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=ver or "(未安装)",
                expected=c.expected,
                message="OK" if ok else (
                    f"Python3 {ver or '(未安装)'}，{host.os_id} 应为 {want}"
                    if want else f"无法确定 {host.os_id} 对应的期望 Python3 版本"),
                fix_refs=c.fix_refs, mandatory=c.mandatory,
            )

        if c.check_type == "path_perm_min":
            patterns = [p for p in c.path.split(",") if p]
            worst = None
            detail = ""
            for pat in patterns:
                rc, out, _ = run_shell(f"stat -c '%a %n' {pat} 2>/dev/null")
                for line in out.strip().splitlines():
                    parts = line.split(None, 1)
                    if len(parts) != 2 or not parts[0].isdigit():
                        continue
                    perm = int(parts[0], 8)
                    if worst is None or perm < worst:
                        worst = perm
                        detail = line.strip()
            want = int(c.value or "555", 8)
            ok = worst is not None and worst >= want
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=(f"{worst:o} ({detail})" if worst is not None else "(未找到目录)"),
                expected=c.expected,
                message="OK" if ok else (
                    f"最小权限 {worst:o} < {want:o}" if worst is not None
                    else "未找到任何 Python3 库目录"),
                fix_refs=c.fix_refs, mandatory=c.mandatory,
            )

        if c.check_type == "pkgmgr_ok":
            tried, ok_pm = [], None
            for pm, probe in (("yum", "yum repolist 2>&1 | tail -5"),
                              ("dnf", "dnf repolist 2>&1 | tail -5"),
                              ("zypper", "zypper lr 2>&1 | tail -5")):
                rc, out, _ = run_shell(probe, timeout=30)
                tried.append(pm)
                if rc == 0 and out.strip():
                    ok_pm = pm
                    break
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok_pm else Status.FAIL,
                current=ok_pm or f"({'/'.join(tried)} 均不可用)",
                expected=c.expected,
                message="OK" if ok_pm else f"{'/'.join(tried)} 仓库查询均失败",
                fix_refs=c.fix_refs, mandatory=c.mandatory,
            )

        if c.check_type == "numa_balanced":
            sizes = _numa_mem_sizes_mb()
            if len(sizes) <= 1:
                current = f"{len(sizes)} 个 NUMA 节点"
                msg, ok = "OK (单 NUMA 节点)", True
            else:
                lo, hi = min(sizes), max(sizes)
                diff = (hi - lo) / hi * 100 if hi else 0.0
                current = f"{len(sizes)} 节点, 差异 {diff:.1f}%"
                ok = diff <= 20.0
                msg = "OK" if ok else f"各 NUMA 节点内存差异 {diff:.1f}% > 20%"
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=current, expected=c.expected, message=msg,
                fix_refs=c.fix_refs, mandatory=c.mandatory,
            )

        if c.check_type == "timezone_utc":
            rc, out, _ = run_shell("timedatectl 2>/dev/null")
            m = re.search(r"Time zone:\s*(\S+)", out) if rc == 0 else None
            current = m.group(1) if m else "(未知)"
            is_utc = current.startswith("Etc/UTC") or current.startswith("UTC") or current == "UTC"
            return CheckResult(
                c.id, c.name,
                Status.PASS if is_utc else Status.FAIL,
                current=current, expected=c.expected,
                message="OK" if is_utc else f"时区 {current} != UTC",
                fix_refs=c.fix_refs,
                mandatory=c.mandatory,
            )

        if c.check_type == "swap_active":
            rc, out, _ = run_shell("swapon --show 2>/dev/null")
            has = (rc == 0 and bool(out.strip()))
            current = out.strip().splitlines()[0] if has else "无 swap"
            return CheckResult(
                c.id, c.name,
                Status.PASS if not has else Status.FAIL,
                current=current, expected=c.expected,
                message="OK" if not has else f"存在活动 swap: {current}",
                fix_refs=c.fix_refs,
                mandatory=c.mandatory,
            )

        if c.check_type == "swap_fstab":
            has_active = False
            try:
                for ln in open("/etc/fstab", encoding="utf-8", errors="ignore"):
                    if re.match(r"^\s*[^#\s]\S*\s+\S+\s+swap\s+", ln):
                        has_active = True
                        break
            except FileNotFoundError:
                pass
            current = "存在未注释的 swap 行" if has_active else "已注释"
            return CheckResult(
                c.id, c.name,
                Status.PASS if not has_active else Status.FAIL,
                current=current, expected=c.expected,
                message="OK" if not has_active else "/etc/fstab 中存在未注释的 swap",
                fix_refs=c.fix_refs,
                mandatory=c.mandatory,
            )

        if c.check_type == "thp_never":
            rc, out, _ = run_shell("cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null")
            current = out.strip() if rc == 0 else ""
            ok = "[never]" in current
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=current or "(未知)", expected=c.expected,
                message="OK" if ok else f"transparent_hugepage={current} != never",
                fix_refs=c.fix_refs,
                mandatory=c.mandatory,
            )

        if c.check_type == "selinux_mode":
            try:
                content = open("/etc/selinux/config", encoding="utf-8", errors="ignore").read()
                m = re.search(r"^\s*SELINUX\s*=\s*(\w+)", content, re.MULTILINE)
            except FileNotFoundError:
                content = ""
                m = None
            current = m.group(1) if m else "(未设置)"
            ok = current.lower() in ("permissive", "disabled")
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=current, expected=c.expected,
                message="OK" if ok else f"SELINUX={current} 应为 permissive 或 disabled",
                fix_refs=c.fix_refs,
                mandatory=c.mandatory,
            )

        if c.check_type == "python_link":
            rc, out, _ = run_shell("command -v python 2>/dev/null")
            if rc != 0 or not out.strip():
                return CheckResult(
                    c.id, c.name, Status.FAIL,
                    current="(不存在)", expected=c.expected,
                    message="缺少 /usr/bin/python 软链",
                    fix_refs=c.fix_refs,
                    mandatory=c.mandatory,
                )
            py_path = out.strip().splitlines()[0]
            _, target, _ = run_shell(f"readlink -f {py_path} 2>/dev/null")
            rc_v, v_out, _ = run_shell("python -V 2>&1")
            version = v_out.strip() if rc_v == 0 else "(无法获取版本)"
            is_py3 = version.startswith("Python 3")
            current = f"{py_path} → {target or '(?)'} ({version})"
            return CheckResult(
                c.id, c.name,
                Status.PASS if is_py3 else Status.FAIL,
                current=current, expected=c.expected,
                message="OK" if is_py3 else f"python 指向 {version}，应指向 Python 3",
                fix_refs=c.fix_refs,
                mandatory=c.mandatory,
            )

        return CheckResult(c.id, c.name, Status.ERROR,
                           message=f"unknown check_type: {c.check_type}",
                             mandatory=c.mandatory)
    except Exception as e:
        return CheckResult(c.id, c.name, Status.ERROR,
                           message=f"{type(e).__name__}: {e}",
                           mandatory=c.mandatory)


# 类别显示顺序（数字越小越靠前；未列出的归入"其它"放最后）
CATEGORY_ORDER = {
    "CPU和内存":      1,
    "NUMA分布情况":   2,
    "系统服务":       3,
    "时间同步":       4,
    "磁盘":           6,    # swap 项（按名字匹配，优先级 5）排在它前面
    "Python3":        7,
    "expect":         7,
    "SFTP":           7,
    "unzip":          7,
    "软件包管理器":   7,
}
DEFAULT_CATEGORY_PRIORITY = 99


def _category_priority(c) -> int:
    """返回 check 的类别显示优先级。

    用户指定的显示顺序：
      CPU → 内存(RAM) → 系统服务 → swap → 磁盘 → 软件包 → 其它
    """
    # swap 相关项放在"系统服务"之后、"磁盘"之前
    if "swap" in c.name.lower():
        return 5
    return CATEGORY_ORDER.get(c.category, DEFAULT_CATEGORY_PRIORITY)


def _python3_sub_order(c) -> int:
    """Python3 类内的子排序：版本正确 → 软链接 → 沿路权限 → 其它。"""
    n = c.name
    if "版本" in n:
        return 0
    if "软链接" in n:
        return 1
    if "沿路权限" in n:
        return 2
    return 3


def run_all_checks(host: HostInfo, ids: Optional[List[int]] = None) -> List[CheckResult]:
    """跑所有（或指定 ID 的）check. 强制校验项排在前面；同组内按类别 + id 排序."""
    targets = list(CHECKS)
    if ids:
        targets = [c for c in CHECKS if c.id in ids]
    # 强制分组：所有 Y 项（mandatory=True）排在前，再排所有 n 项；
    # 同组内按 类别优先级 + 子排序 + id 升序。
    mandatory = sorted(
        [c for c in targets if c.mandatory],
        key=lambda c: (_category_priority(c), _python3_sub_order(c), c.id),
    )
    optional = sorted(
        [c for c in targets if not c.mandatory],
        key=lambda c: (_category_priority(c), _python3_sub_order(c), c.id),
    )
    targets = mandatory + optional
    return [_check_one(c, host) for c in targets]


# =============================================================
# 运行时：修复执行器
# =============================================================

@dataclass
class FixStep:
    cmd: str
    section: str
    rc: int
    stdout: str
    stderr: str


def _pm_install_cmd(host: HostInfo, pkg: str) -> str:
    """根据 host.package_manager 返回安装命令."""
    if host.package_manager == "apt":
        return f"DEBIAN_FRONTEND=noninteractive apt-get install -y {pkg} 2>/dev/null"
    if host.package_manager == "zypper":
        return f"zypper -n install {pkg} 2>/dev/null"
    if host.package_manager in ("yum", "dnf"):
        return f"{host.package_manager} install -y {pkg} 2>/dev/null"
    # unknown: try apt first, then yum
    return f"(command -v apt-get >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y {pkg}) || (command -v yum >/dev/null && yum install -y {pkg}) 2>/dev/null"


def _matches_os(item: dict, host: HostInfo) -> bool:
    """根据 os 标签决定是否运行该命令."""
    tag = item.get("os")
    if tag is None:
        return True
    if tag == "suse":
        return host.os_id in ("sles", "suse", "opensuse", "sle")
    if tag == "non_suse":
        return host.os_id not in ("sles", "suse", "opensuse", "sle")
    return True


def run_fix(results: List[CheckResult], host: HostInfo,
            assume_yes: bool = False) -> List[FixStep]:
    """对每个 FAIL 项按映射执行修复，返回执行步骤列表."""
    steps: List[FixStep] = []
    seen_sections: Set[str] = set()
    for r in results:
        if r.status != Status.FAIL:
            continue
        for section in r.fix_refs:
            if section in seen_sections:
                continue
            sec = FIX_SECTIONS.get(section)
            if not sec:
                steps.append(FixStep(
                    cmd=f"(无对应章节: {section})", section=section,
                    rc=1, stdout="", stderr=f"no fix section named {section!r}",
                ))
                continue
            seen_sections.add(section)
            for item in sec["commands"]:
                if not _matches_os(item, host):
                    continue
                # Substitute package manager placeholders
                cmd = item["cmd"]
                if "{PKG_INSTALL_EXPECT}" in cmd:
                    cmd = cmd.replace("{PKG_INSTALL_EXPECT}", _pm_install_cmd(host, "expect"))
                if "{PKG_INSTALL_UNZIP}" in cmd:
                    cmd = cmd.replace("{PKG_INSTALL_UNZIP}", _pm_install_cmd(host, "unzip"))
                if "{PKG_INSTALL_PYTHON3}" in cmd:
                    cmd = cmd.replace("{PKG_INSTALL_PYTHON3}",
                                       _pm_install_cmd(host, "python3 python3-devel make gcc-c++"))
                if "{PKG_INSTALL_CHRONY}" in cmd:
                    cmd = cmd.replace("{PKG_INSTALL_CHRONY}", _pm_install_cmd(host, "chrony"))
                if is_dangerous(cmd) and not assume_yes:
                    steps.append(FixStep(
                        cmd=cmd, section=section, rc=1, stdout="",
                        stderr="SKIP: dangerous command (need --yes)",
                    ))
                    continue
                rc, out, err = run_shell(cmd, timeout=60)
                steps.append(FixStep(cmd=cmd, section=section,
                                    rc=rc, stdout=out, stderr=err))
    return steps


# =============================================================
# 报告输出
# =============================================================

def _truncate(s: str, n: int) -> str:
    """按视觉宽度截断到 n，末尾加 "…"，截断前清理尾部空白."""
    vw = _vwidth(s)
    if vw <= n:
        return s
    # 按视觉宽度截取到 n-1（为 "…" 留位置）
    out = []
    used = 0
    target = n - 1
    for ch in _strip_ansi(s):
        cw = 2 if ord(ch) > 0x2E80 else 1
        if used + cw > target:
            break
        out.append(ch)
        used += cw
    # 清理截断片段的尾部空白，再追加 "…"
    return "".join(out).rstrip() + "…"


def _sev_label(r: CheckResult) -> str:
    """返回彩色化的严重程度标签."""
    if r.status == Status.PASS:
        return f"{C_GREEN}OK       {C_RESET}"
    if r.status == Status.ERROR:
        return f"{C_MAGENTA}ERROR    {C_RESET}"
    # FAIL → NOT OK (强制) 或 WARNING (非强制)
    if r.mandatory:
        return f"{C_RED}{C_BOLD}NOT OK   {C_RESET}"
    return f"{C_YELLOW}WARNING  {C_RESET}"


def _strip_ansi(s: str) -> str:
    """去掉 ANSI 颜色码，用于计算显示宽度."""
    return re.sub(r"\033\[[0-9;]*m", "", s)


def _vwidth(s: str) -> int:
    """计算字符串的可见显示宽度（CJK 字符按 2 计算）."""
    w = 0
    for ch in _strip_ansi(s):
        if ord(ch) > 0x2E80:  # CJK 区段
            w += 2
        else:
            w += 1
    return w


def _cell(s: str, width: int, align: str = "<") -> str:
    """填充单元格到指定宽度（按可见字符数）."""
    visible = _strip_ansi(s)
    vw = _vwidth(s)
    pad = width - vw
    if pad < 0:
        # 按可见宽度截断到 width-1，然后加 "…"
        out = ""
        used = 0
        for ch in visible:
            cw = 2 if ord(ch) > 0x2E80 else 1
            if used + cw + 1 > width:
                break
            out += ch
            used += cw
        out += "…"
        return out + " " * max(width - used - 1, 0)
    if align == "<":
        return s + " " * pad
    return " " * pad + s


def _row_border(widths: List[int]) -> str:
    """绘制 +---+---+ 风格的分隔行."""
    return "+" + "+".join("-" * (w + 2) for w in widths) + "+"


def print_check_table(results: List[CheckResult], host: HostInfo,
                     detail: bool = False) -> None:
    """打印检查报告.

    布局顺序:
      1) 标题 + 时间 + 环境
      2) 详细表格（强制项在前）
      3) 底部汇总（总览结论 + 状态计数 + 强制/非强制分组，数字上下对齐）
      4) NOT OK 详情（仅 --detail 时输出）
      5) WARNING 详情（仅 --detail 时输出）
    """
    # ---------- 1. 标题 ----------
    # 标签按视觉宽度对齐（CJK=2，ASCII=1），让冒号上下对齐且每行标签后至少 1 个空格
    def _pad_label(s: str, width: int) -> str:
        return s + " " * (width - _vwidth(s))
    label_w = max(_vwidth(s) for s in ("时间", "操作系统", "权限")) + 1
    print(f"\n{C_BOLD}主机标准化检查报告{C_RESET}")
    print(f"  {_pad_label('时间', label_w)}: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {_pad_label('操作系统', label_w)}: {C_CYAN}{host.os_id} {host.os_version}{C_RESET}")
    print(f"  {_pad_label('权限', label_w)}: {C_CYAN}root={host.is_root}{C_RESET}")

    # ---------- 2. 详细表格 ----------
    # 固定列宽：item 优先，current/expected 给足
    headers = ["#", "item", "current_value", "expected_value", "M", "status"]
    widths = [4, 30, 41, 52, 2, 8]   # M 列只放 1 字符的 Y/n
    # 终端太窄时压缩 current/expected
    term_w = shutil.get_terminal_size((160, 40)).columns
    total_w = sum(widths) + 7 * 2  # 每列两侧 " | " 加首尾 "| "
    if total_w > term_w:
        overflow = total_w - term_w
        for i in (2, 3):
            if widths[i] > 12:
                cut = min(overflow // 2, widths[i] - 12)
                widths[i] -= cut
                overflow -= cut
        if overflow > 0 and widths[1] > 18:
            cut = min(overflow, widths[1] - 18)
            widths[1] -= cut

    print(_row_border(widths))
    print("| " + " | ".join(_cell(h, w) for h, w in zip(headers, widths)) + " |")
    print(_row_border(widths))
    not_ok: List[CheckResult] = []
    warning: List[CheckResult] = []
    for idx, r in enumerate(results, start=1):
        item = _truncate(r.display_item, widths[1] - 1)
        cur = _truncate(r.display_current, widths[2] - 1)
        exp = _truncate(r.display_expected, widths[3] - 1)
        mand_colored = (f"{C_RED}{C_BOLD}Y{C_RESET}" if r.mandatory
                        else f"{C_DIM}n{C_RESET}")
        st_colored = r.display_status_colored
        print("| " + " | ".join([
            _cell(str(idx), widths[0], align=">"),
            _cell(item, widths[1]),
            _cell(cur, widths[2]),
            _cell(exp, widths[3]),
            _cell(mand_colored, widths[4]),
            _cell(st_colored, widths[5]),
        ]) + " |")
        if r.status == Status.FAIL:
            (not_ok if r.mandatory else warning).append(r)
    print(_row_border(widths))

    # ---------- 3. 底部汇总（数字上下对齐） ----------
    ok_n = sum(1 for r in results if r.status == Status.PASS)
    not_ok_n = len(not_ok)
    warn_n = len(warning)
    err_n = sum(1 for r in results if r.status == Status.ERROR)
    total = len(results)
    # 数字按宽度对齐（按最大项数 4 位 + label 对齐）
    # 模板：OK=<N>  NOT OK=<N>  WARNING=<N>  ERROR=<N>
    num_w = max(len(str(max(ok_n, not_ok_n, warn_n, err_n, total))), 2)

    if not_ok_n > 0:
        verdict = f"{C_RED}{C_BOLD}存在 {not_ok_n} 项强制项不达标，必须修复后才能安装 GaussDB{C_RESET}"
    elif err_n > 0:
        verdict = f"{C_MAGENTA}{C_BOLD}存在 {err_n} 项检查异常，请人工排查{C_RESET}"
    elif warn_n > 0:
        verdict = f"{C_YELLOW}{C_BOLD}强制项已通过，但有 {warn_n} 项非强制项建议修复{C_RESET}"
    else:
        verdict = f"{C_GREEN}{C_BOLD}全部通过{C_RESET}"

    bar = "═" * 64
    print(f"\n{C_DIM}{bar}{C_RESET}")
    print(f"  {verdict}")
    # 4 个数字用同一 num_w 宽度对齐
    print(f"  共 {C_BOLD}{total:>{num_w}}{C_RESET} 项    "
          f"{C_GREEN}OK={ok_n:>{num_w}}{C_RESET}    "
          f"{C_RED}{C_BOLD}NOT OK={not_ok_n:>{num_w}}{C_RESET}    "
          f"{C_YELLOW}WARNING={warn_n:>{num_w}}{C_RESET}    "
          f"{C_MAGENTA}ERROR={err_n:>{num_w}}{C_RESET}")
    # 末尾只保留：verdict + 总数统计（按用户要求，不显示分类统计）
    print(f"{C_DIM}{bar}{C_RESET}")

    # ---------- 4. NOT OK 详情（仅 --detail 时输出） ----------
    if detail and not_ok:
        print(f"\n{C_RED}{C_BOLD}=== NOT OK（强制项不达标，必须修复）[{len(not_ok)} 项] ==={C_RESET}")
        for r in not_ok:
            print(f"  {C_BOLD}{r.display_item}{C_RESET}")
            print(f"      current : {r.display_current}")
            print(f"      expected: {r.display_expected}")
            print(f"      detail  : {r.message}")
            if r.fix_refs:
                print(f"      fix     : {', '.join(r.fix_refs)}")

    # ---------- 5. WARNING 详情（仅 --detail 时输出） ----------
    if detail and warning:
        print(f"\n{C_YELLOW}{C_BOLD}=== WARNING（非强制项不达标，建议修复）[{len(warning)} 项] ==={C_RESET}")
        for r in warning:
            print(f"  {C_BOLD}{r.display_item}{C_RESET}")
            print(f"      current : {r.display_current}")
            print(f"      expected: {r.display_expected}")
            if r.fix_refs:
                print(f"      fix     : {', '.join(r.fix_refs)}")


def print_fix_report(steps: List[FixStep]) -> int:
    """输出 fix 报告；返回失败步骤数."""
    print(f"\n{C_BOLD}修复执行报告{C_RESET}")
    print()
    if not steps:
        print(f"{C_GREEN}没有可执行的修复。{C_RESET}")
        return 0
    fails = 0
    for s in steps:
        ok = (s.rc == 0)
        if not ok:
            fails += 1
        tag = f"{C_GREEN}OK{C_RESET}" if ok else f"{C_RED}FAIL{C_RESET}"
        print(f"[{tag}] [{s.section}]")
        print(f"  CMD: {s.cmd}")
        if s.stdout.strip():
            first = s.stdout.strip().splitlines()[0]
            print(f"  STDOUT: {first[:120]}")
        if s.stderr.strip():
            first = s.stderr.strip().splitlines()[0]
            print(f"  STDERR: {first[:120]}")
        if not ok and s.stderr:
            print(f"  {C_RED}报错原因:{C_RESET} {s.stderr.strip().splitlines()[0][:200]}")
        print()
    print(f"修复步骤: 总={len(steps)}, 失败={fails}")
    return fails


# =============================================================
# CLI 入口
# =============================================================

def cmd_list() -> int:
    print(f"\n{C_BOLD}主机标准化检查项清单{C_RESET}  共 {len(CHECKS)} 项\n")
    # 与 check 表格相同的列宽与对齐策略（视觉宽度，CJK=2）
    headers = ["ID", "Category", "Name", "Type", "M"]
    widths = [7, 14, 44, 16, 2]
    term_w = shutil.get_terminal_size((140, 40)).columns
    total_w = sum(widths) + 6 * 2  # 5 列 + 5 个 " | " + 首尾 "| "
    if total_w > term_w and widths[2] > 20:
        widths[2] -= min(total_w - term_w, widths[2] - 20)

    print(_row_border(widths))
    print("| " + " | ".join(_cell(h, w) for h, w in zip(headers, widths)) + " |")
    print(_row_border(widths))
    # 与 check 完全一致的顺序：强制项在前 → 组内按 (类别优先级, Python3 子序, id)
    mandatory = sorted(
        [c for c in CHECKS if c.mandatory],
        key=lambda c: (_category_priority(c), _python3_sub_order(c), c.id),
    )
    optional = sorted(
        [c for c in CHECKS if not c.mandatory],
        key=lambda c: (_category_priority(c), _python3_sub_order(c), c.id),
    )
    sorted_checks = mandatory + optional
    for c in sorted_checks:
        mand_colored = (f"{C_RED}{C_BOLD}Y{C_RESET}" if c.mandatory
                        else f"{C_DIM}n{C_RESET}")
        print("| " + " | ".join([
            _cell(str(c.id), widths[0], align=">"),
            _cell(c.category, widths[1]),
            _cell(_truncate(c.name, widths[2] - 1), widths[2]),
            _cell(c.check_type, widths[3]),
            _cell(mand_colored, widths[4]),
        ]) + " |")
    print(_row_border(widths))
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    host = detect_host()
    results = run_all_checks(host)
    print_check_table(results, host, detail=getattr(args, "detail", False))
    not_ok = sum(1 for r in results if r.status == Status.FAIL and r.mandatory)
    return 2 if not_ok else (0 if not any(r.status == Status.FAIL for r in results) else 1)


def cmd_fix(args: argparse.Namespace) -> int:
    host = detect_host()
    if not host.is_root:
        print(f"{C_RED}ERROR: fix 子命令需要 root 权限 (current euid={os.geteuid()}){C_RESET}")
        return 3
    results = run_all_checks(host)
    all_fails = [r for r in results if r.status == Status.FAIL]
    not_ok_n = sum(1 for r in all_fails if r.mandatory)
    warn_n = len(all_fails) - not_ok_n
    # 默认只修 NOT OK（强制 FAIL）；加 --all 才一并修 WARNING
    if getattr(args, "all", False):
        fails = all_fails
        if warn_n:
            print(f"{C_YELLOW}有 {not_ok_n} 项 NOT OK + {warn_n} 项 WARNING（--all 模式全部修复），开始执行修复...{C_RESET}\n")
        else:
            print(f"{C_YELLOW}有 {not_ok_n} 项 NOT OK，开始执行修复...{C_RESET}\n")
    else:
        fails = [r for r in all_fails if r.mandatory]
        if warn_n:
            print(f"{C_DIM}另有 {warn_n} 项 WARNING（非强制）跳过修复；如需一并修复请加 --all / -A{C_RESET}")
        if not fails:
            print(f"{C_GREEN}没有 NOT OK 项需要修复。{C_RESET}")
            return 0
        print(f"{C_YELLOW}有 {not_ok_n} 项 NOT OK（强制），开始执行修复...{C_RESET}\n")
    steps = run_fix(fails, host, assume_yes=args.yes)
    failed = print_fix_report(steps)
    if failed:
        print(f"\n{C_RED}存在 {failed} 条修复失败，请查看上方报错原因和对应 fix 项后手动处理。{C_RESET}")
        return 2
    # 重新跑一遍检查
    print(f"\n{C_BOLD}重新跑一遍 check 验证...{C_RESET}")
    new_results = run_all_checks(host)
    print_check_table(new_results, host)
    new_not_ok = sum(1 for r in new_results if r.status == Status.FAIL and r.mandatory)
    new_warn = sum(1 for r in new_results if r.status == Status.FAIL and not r.mandatory)
    if new_not_ok == 0 and new_warn == 0:
        print(f"\n{C_GREEN}所有项已 OK。{C_RESET}")
        return 0
    if new_not_ok == 0:
        print(f"\n{C_YELLOW}强制项都已 OK，仍有 {new_warn} 项 WARNING（可能需要人工干预）。{C_RESET}")
        return 0
    print(f"\n{C_RED}仍有 {new_not_ok} 项 NOT OK（可能需要人工干预或运行多次）。{C_RESET}")
    return 1


def main(argv: Optional[List[str]] = None) -> int:
    global USE_COLOR
    p = argparse.ArgumentParser(
        prog="gaussdb_host_check",
        description="主机管理标准化 检查/修复 执行器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # 让顶层 --help 同时展示三个子命令的完整参数
    p.add_argument("--no-color", action="store_true", help="禁用 ANSI 颜色")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_check = sub.add_parser("check", help="运行所有检查并打印报告")
    p_check.add_argument("--detail", "-d", action="store_true",
                         help="显示 NOT OK 和 WARNING 项的详情（默认不输出）")
    p_check.set_defaults(func=cmd_check)

    p_fix = sub.add_parser("fix", help="对 NOT OK 项执行修复命令")
    p_fix.add_argument("--yes", action="store_true",
                       help="允许执行危险命令（默认拒绝 rm -r / 磁盘操作等）")
    p_fix.add_argument("--all", "-A", "-a", action="store_true", dest="all",
                       help="一并修复 WARNING（非强制）项，默认只修 NOT OK")
    p_fix.set_defaults(func=cmd_fix)

    p_list = sub.add_parser("list", help="列出所有检查项")
    p_list.set_defaults(func=lambda a: cmd_list())

    # 自定义 help：打印顶层 + 三个子命令完整用法
    class _AllHelpAction(argparse.Action):
        def __init__(self, option_strings, dest, **kwargs):
            super().__init__(option_strings, dest, nargs=0, **kwargs)
        def __call__(self, parser, namespace, values, option_string=None):
            p.print_help()
            for name, sp in (("check", p_check), ("fix", p_fix), ("list", p_list)):
                print(f"\n子命令 `{name}` 的参数：")
                sp.print_help()
            parser.exit()
    for action in p._actions:
        if action.dest == "help":
            action.__class__ = _AllHelpAction
            break

    args = p.parse_args(argv)
    if args.no_color:
        set_color(False)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
