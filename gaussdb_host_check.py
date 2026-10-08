#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gaussdb_host_check - 主机管理标准化 检查/修复 执行器.

用法:
    python gaussdb_host_check.py check [--id N]... [--no-color] [--json] [--verbose]
    python gaussdb_host_check.py fix   [--id N]... [--no-color] [--yes] [--verbose]
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


def _ansi(code: str) -> str:
    return f"\033[{code}m" if USE_COLOR else ""


C_RESET = _ansi("0")
C_BOLD = _ansi("1")
C_DIM = _ansi("2")
C_RED = _ansi("31")
C_GREEN = _ansi("32")
C_YELLOW = _ansi("33")
C_BLUE = _ansi("34")
C_MAGENTA = _ansi("35")
C_CYAN = _ansi("36")


class Status(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"

    def color(self) -> str:
        return {
            Status.PASS: C_GREEN,
            Status.FAIL: C_RED,
            Status.SKIP: C_YELLOW,
            Status.ERROR: C_MAGENTA,
        }[self]

    def label(self) -> str:
        return f"{self.color()}{self.value:<5}{C_RESET}"


# 危险命令正则（fix 模式下默认拦截，需要 --yes 才执行）
_DANGEROUS_PATTERNS = [
    re.compile(r"^\s*rm\s+-r?f?\s+/"),
    re.compile(r"^\s*rm\s+-r?\s+/var"),
    re.compile(r"^\s*reboot\b"),
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
# 操作系统/容器/权限 探测
# =============================================================

@dataclass
class HostInfo:
    os_id: str = "unknown"           # kylin / uos / hce / sle / bclinux / unknown
    os_version: str = ""
    is_root: bool = False
    is_container: bool = False
    package_manager: str = ""        # yum / dnf / zypper / apt


def detect_host() -> HostInfo:
    info = HostInfo()
    info.is_root = (os.geteuid() == 0)
    # container
    info.is_container = (
        os.path.exists("/.dockerenv")
        or os.path.exists("/run/.containerenv")
        or (os.path.exists("/proc/1/cgroup")
            and any(x in open("/proc/1/cgroup", errors="ignore").read()
                    for x in ("docker", "containerd", "kubepods")))
    )
    # os
    if os.path.exists("/etc/os-release"):
        try:
            data = {}
            for line in open("/etc/os-release", encoding="utf-8", errors="ignore"):
                if "=" in line:
                    k, v = line.split("=", 1)
                    data[k.strip()] = v.strip().strip('"')
            info.os_id = data.get("ID", "unknown").lower()
            info.os_version = data.get("VERSION_ID", "")
        except Exception:
            pass
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
    key: str = ""                  # sysctl key / ulimit type / service / package / port
    port: int = 0
    path: str = ""
    value: str = ""
    cmd: str = ""                  # raw command for show-output
    mandatory: bool = False
    container_check: bool = True


def _sysctl_value(key: str) -> str:
    rc, out, _ = run_shell(f"sysctl -n {key} 2>/dev/null")
    return out.strip() if rc == 0 else ""


def _sysctl_eq(key: str, value: str) -> bool:
    return _sysctl_value(key) == value


# ---------------------------------------------------------------
# CHECKS 数据（74 项）
# 字段格式: (id, name, type, expected, fix_ref, **kwargs)
# type:
#   sysctl_eq      kwargs: key, value
#   ulimit         kwargs: key (-Sn/-Hn/-s), value
#   service_active kwargs: name
#   service_inactive kwargs: name
#   service_enabled kwargs: name
#   pkg            kwargs: name
#   port_in_use    kwargs: port  (PASS when port is in use, FAIL when free)
#   port_free      kwargs: port  (PASS when port is free, FAIL when in use)
#   cgroup_v1      kwargs: -
#   cpu_cores      kwargs: value
#   mem_gb         kwargs: value
#   path_perm      kwargs: path, value (octal string like "755")
#   path_exists    kwargs: path
#   hosts_ipv6     kwargs: -
#   python_version kwargs: name (麒麟/统信/HCE/SUSE/BCLINUX -> 期望版本)
#   expect         kwargs: -
#   sftp           kwargs: -
#   profile_source kwargs: -
#   om_agent       kwargs: -
#   hosts_unique   kwargs: -
#   security_perm  kwargs: -
#   show           kwargs: cmd  (run cmd, just display stdout, expect user judgement)
# ---------------------------------------------------------------

# 这里数据分两部分：
# - 自动可判定的（带 predicate）: 大部分 sysctl/ulimit/service/pkg/port 等
# - 仅展示原命令输出的: 物理机特定 / 需要人工核对的

CHECKS: List[CheckDef] = [
    # ===== CPU 和内存 =====
    CheckDef(100001, "vCPU核数 >= 4", "CPU和内存", "show",
             expected=">= 4",
             cmd="lscpu | grep '^CPU(s):' | awk '{print $2}'"),
    CheckDef(100002, "CPU型号为推荐", "CPU和内存", "show",
             expected="Intel Xeon Gold 6248R/5318Y, Hygon 7280, Kunpeng 920",
             cmd="lscpu | grep 'Model name'"),
    CheckDef(100003, "内存 >= 16G", "CPU和内存", "show",
             expected=">= 16G",
             cmd="free -g | grep Mem"),
    CheckDef(100004, "CPU内存比 1:4 或 1:8", "CPU和内存", "show",
             expected="1:4 or 1:8",
             cmd="lscpu | grep '^CPU(s):'"),

    # ===== 磁盘 =====
    CheckDef(100005, "磁盘类型推荐", "磁盘", "show",
             expected="SAS/SATA/NVMe SSD",
             cmd="lsblk -d -o name,rota",
             fix_refs=["准备数据盘", "准备系统盘"]),
    CheckDef(100006, "数据盘无分区无挂载", "磁盘", "show",
             expected="无分区无挂载",
             cmd="lsblk -f",
             mandatory=True, container_check=False,
             fix_refs=["准备数据盘"]),
    CheckDef(100009, "磁盘盘符不混用", "磁盘", "show",
             expected="不要 sd 和 vd 混用",
             cmd="lsblk -d -o name",
             mandatory=True, container_check=False,
             fix_refs=["准备数据盘", "准备系统盘"]),
    CheckDef(100069, "系统盘非多磁盘", "磁盘", "show",
             expected="单盘",
             cmd="lsblk -d -o name | grep -v loop",
             mandatory=True, container_check=False,
             fix_refs=["准备系统盘"]),
    CheckDef(100070, "系统盘非 NVMe", "磁盘", "show",
             expected="SAS/SATA SSD",
             cmd="lsblk -d -o name,rota",
             mandatory=True, container_check=False,
             fix_refs=["准备系统盘"]),

    # ===== 操作系统版本 =====
    CheckDef(100011, "OS 版本受支持", "操作系统版本", "show",
             expected="麒麟V10 SP1-3 / 统信V20 / HCE 2.0 / SUSE 12 SP5 / BCLINUX 21.10",
             cmd="cat /etc/os-release",
             mandatory=True,
             fix_refs=["准备系统盘"]),

    # ===== 系统服务 =====
    CheckDef(100012, "iptables active & enabled", "系统服务", "service_active",
             expected="active+enabled",
             key="iptables",
             mandatory=True, container_check=False,
             fix_refs=["配置操作系统防火墙", "配置系统服务"]),
    CheckDef(100061, "cgconfig active & enabled", "系统服务", "service_active",
             expected="active+enabled",
             key="cgconfig",
             mandatory=True, container_check=False,
             fix_refs=["配置系统服务"]),
    CheckDef(100013, "firewalld 关闭", "系统服务", "service_inactive",
             expected="inactive",
             key="firewalld",
             mandatory=True, container_check=False,
             fix_refs=["配置操作系统防火墙"]),
    CheckDef(100078, "rngd/haveged 开启", "系统服务", "service_active",
             expected="active+enabled",
             key="rngd",
             mandatory=True, container_check=False,
             fix_refs=["配置系统服务"]),

    # ===== 时间同步 =====
    CheckDef(100014, "NTP/Chrony 启用 & 同步", "时间同步", "service_active",
             expected="chronyd or ntpd active+enabled, drift < 1s",
             key="chronyd",
             mandatory=True, container_check=False,
             fix_refs=["设置时钟源"]),
    CheckDef(100054, "硬件时钟已同步", "时间同步", "show",
             expected="System clock synchronized: yes",
             cmd="timedatectl status | grep 'System clock synchronized'",
             container_check=False,
             fix_refs=["设置时钟源"]),
    CheckDef(100073, "主机与 TPOPS 时钟源一致", "时间同步", "show",
             expected="时钟源 IP 与 TPOPS 节点一致",
             cmd="chronyc sources",
             container_check=False,
             fix_refs=["设置时钟源"]),

    # ===== 字符集 =====
    CheckDef(100015, "字符集 en_US.UTF-8", "字符集参数", "show",
             expected="en_US.UTF-8",
             cmd="locale | grep LANG",
             mandatory=True,
             fix_refs=["设置字符集参数"]),

    # ===== MTU =====
    CheckDef(100016, "万兆网卡 MTU 1500/8192", "网卡MTU值", "show",
             expected="X86: 1500, ARM: 8192",
             cmd="ifconfig | grep -i mtu",
             container_check=True,
             fix_refs=["设置网卡MTU值"]),

    # ===== HISTORY =====
    CheckDef(100017, "/etc/profile HISTSIZE=0", "HISTORY记录", "show",
             expected="HISTSIZE=0",
             cmd="grep -E '^HISTSIZE=' /etc/profile",
             container_check=True,
             fix_refs=["关闭HISTORY记录"]),

    # ===== Python3 =====
    CheckDef(100018, "Python3 版本正确", "Python3", "show",
             expected="麒麟/统信/BCLINUX: 3.7.9, HCE: 3.9.9, SUSE: 3.8.5",
             cmd="python3 --version",
             mandatory=True,
             fix_refs=["安装主机的Python3"]),
    CheckDef(100071, "Python3 沿路权限 >= 555", "Python3", "show",
             expected=">= 555",
             cmd="ls -ld /usr/lib/python3* /usr/lib64/python3* /usr/local/lib/python3* /usr/local/lib64/python3* /usr/local/python3/lib/python3* 2>/dev/null",
             mandatory=True, container_check=False,
             fix_refs=["Python3第三方库和模块的沿路权限"]),

    # ===== Cgroup =====
    CheckDef(100019, "Cgroup V1", "Cgroup版本", "cgroup_v1",
             expected="tmpfs (V1)",
             mandatory=True,
             fix_refs=["安装主机的Python3"]),  # 文档未给 cgroup 安装章节，挂此处仅占位

    # ===== 操作系统参数 sysctl =====
    CheckDef(100020, "net.ipv4.tcp_max_tw_buckets = 10000", "操作系统参数", "sysctl_eq",
             key="net.ipv4.tcp_max_tw_buckets", value="10000",
             expected="10000",
             fix_refs=["配置操作系统参数"]),
    CheckDef(100021, "net.ipv4.tcp_tw_reuse = 1", "操作系统参数", "sysctl_eq",
             key="net.ipv4.tcp_tw_reuse", value="1",
             expected="1",
             fix_refs=["配置操作系统参数"]),
    CheckDef(100022, "net.ipv4.tcp_tw_recycle = 1", "操作系统参数", "sysctl_eq",
             key="net.ipv4.tcp_tw_recycle", value="1",
             expected="1",
             fix_refs=["配置操作系统参数"]),
    CheckDef(100023, "net.ipv4.tcp_keepalive_time = 30", "操作系统参数", "sysctl_eq",
             key="net.ipv4.tcp_keepalive_time", value="30",
             expected="30",
             fix_refs=["配置操作系统参数"]),
    CheckDef(100024, "net.ipv4.tcp_keepalive_probes = 9", "操作系统参数", "sysctl_eq",
             key="net.ipv4.tcp_keepalive_probes", value="9",
             expected="9",
             fix_refs=["配置操作系统参数"]),
    CheckDef(100025, "net.ipv4.tcp_keepalive_intvl = 30", "操作系统参数", "sysctl_eq",
             key="net.ipv4.tcp_keepalive_intvl", value="30",
             expected="30",
             fix_refs=["配置操作系统参数"]),
    CheckDef(100026, "net.ipv4.tcp_retries1 = 5", "操作系统参数", "sysctl_eq",
             key="net.ipv4.tcp_retries1", value="5",
             expected="5",
             fix_refs=["配置操作系统参数"]),
    CheckDef(100027, "net.ipv4.tcp_syn_retries = 5", "操作系统参数", "sysctl_eq",
             key="net.ipv4.tcp_syn_retries", value="5",
             expected="5",
             fix_refs=["配置操作系统参数"]),
    CheckDef(100028, "net.ipv4.tcp_synack_retries = 5", "操作系统参数", "sysctl_eq",
             key="net.ipv4.tcp_synack_retries", value="5",
             expected="5",
             fix_refs=["配置操作系统参数"]),
    CheckDef(100029, "net.ipv4.tcp_retries2 = 12", "操作系统参数", "sysctl_eq",
             key="net.ipv4.tcp_retries2", value="12",
             expected="12",
             fix_refs=["配置操作系统参数"]),
    CheckDef(100030, "vm.overcommit_memory = 0", "操作系统参数", "sysctl_eq",
             key="vm.overcommit_memory", value="0",
             expected="0",
             fix_refs=["配置操作系统参数"]),
    CheckDef(100031, "net.ipv4.tcp_rmem = 8192 250000 16777216", "操作系统参数", "sysctl_eq",
             key="net.ipv4.tcp_rmem", value="8192\t250000\t16777216",
             expected="8192 250000 16777216",
             fix_refs=["配置操作系统参数"]),
    CheckDef(100032, "net.ipv4.tcp_wmem = 8192 250000 16777216", "操作系统参数", "sysctl_eq",
             key="net.ipv4.tcp_wmem", value="8192\t250000\t16777216",
             expected="8192 250000 16777216",
             fix_refs=["配置操作系统参数"]),
    CheckDef(100033, "net.core.wmem_max = 21299200", "操作系统参数", "sysctl_eq",
             key="net.core.wmem_max", value="21299200",
             expected="21299200",
             container_check=False,
             fix_refs=["配置操作系统参数"]),
    CheckDef(100034, "net.core.rmem_max = 21299200", "操作系统参数", "sysctl_eq",
             key="net.core.rmem_max", value="21299200",
             expected="21299200",
             container_check=False,
             fix_refs=["配置操作系统参数"]),
    CheckDef(100035, "net.core.wmem_default = 21299200", "操作系统参数", "sysctl_eq",
             key="net.core.wmem_default", value="21299200",
             expected="21299200",
             container_check=False,
             fix_refs=["配置操作系统参数"]),
    CheckDef(100036, "net.core.rmem_default = 21299200", "操作系统参数", "sysctl_eq",
             key="net.core.rmem_default", value="21299200",
             expected="21299200",
             container_check=False,
             fix_refs=["配置操作系统参数"]),
    CheckDef(100037, "net.ipv4.ip_local_port_range = 26000 65535", "操作系统参数", "sysctl_eq",
             key="net.ipv4.ip_local_port_range", value="26000\t65535",
             expected="26000 65535",
             fix_refs=["配置操作系统参数"]),
    CheckDef(100038, "kernel.sem = 250 6400000 1000 25600", "操作系统参数", "sysctl_eq",
             key="kernel.sem", value="250\t6400000\t1000\t25600",
             expected="250 6400000 1000 25600",
             fix_refs=["配置操作系统参数"]),
    CheckDef(100039, "vm.min_free_kbytes >= 5% 内存", "操作系统参数", "show",
             expected="min_free_kbytes * 100 / MemTotal >= 5",
             cmd="sysctl vm.min_free_kbytes; echo '---'; grep MemTotal /proc/meminfo",
             fix_refs=["配置操作系统参数"]),
    CheckDef(100040, "net.core.somaxconn = 65535", "操作系统参数", "sysctl_eq",
             key="net.core.somaxconn", value="65535",
             expected="65535",
             fix_refs=["配置操作系统参数"]),
    CheckDef(100041, "net.ipv4.tcp_syncookies = 1", "操作系统参数", "sysctl_eq",
             key="net.ipv4.tcp_syncookies", value="1",
             expected="1",
             fix_refs=["配置操作系统参数"]),
    CheckDef(100042, "net.core.netdev_max_backlog = 65535", "操作系统参数", "sysctl_eq",
             key="net.core.netdev_max_backlog", value="65535",
             expected="65535",
             container_check=False,
             fix_refs=["配置操作系统参数"]),
    CheckDef(100043, "net.ipv4.tcp_max_syn_backlog = 65535", "操作系统参数", "sysctl_eq",
             key="net.ipv4.tcp_max_syn_backlog", value="65535",
             expected="65535",
             fix_refs=["配置操作系统参数"]),
    CheckDef(100044, "net.ipv4.tcp_fin_timeout = 60", "操作系统参数", "sysctl_eq",
             key="net.ipv4.tcp_fin_timeout", value="60",
             expected="60",
             fix_refs=["配置操作系统参数"]),
    CheckDef(100045, "kernel.shmall = 1152921504606846720", "操作系统参数", "sysctl_eq",
             key="kernel.shmall", value="1152921504606846720",
             expected="1152921504606846720",
             fix_refs=["配置操作系统参数"]),
    CheckDef(100046, "kernel.shmmax = 18446744073709551615", "操作系统参数", "sysctl_eq",
             key="kernel.shmmax", value="18446744073709551615",
             expected="18446744073709551615",
             fix_refs=["配置操作系统参数"]),
    CheckDef(100047, "net.ipv4.tcp_sack = 1", "操作系统参数", "sysctl_eq",
             key="net.ipv4.tcp_sack", value="1",
             expected="1",
             fix_refs=["配置操作系统参数"]),
    CheckDef(100048, "net.ipv4.tcp_timestamps = 1", "操作系统参数", "sysctl_eq",
             key="net.ipv4.tcp_timestamps", value="1",
             expected="1",
             fix_refs=["配置操作系统参数"]),
    CheckDef(100049, "vm.extfrag_threshold = 500", "操作系统参数", "sysctl_eq",
             key="vm.extfrag_threshold", value="500",
             expected="500",
             fix_refs=["配置操作系统参数"]),
    CheckDef(100050, "vm.overcommit_ratio = 90", "操作系统参数", "sysctl_eq",
             key="vm.overcommit_ratio", value="90",
             expected="90",
             fix_refs=["配置操作系统参数"]),

    # ===== 文件系统参数 ulimit =====
    CheckDef(100051, "ulimit -Sn >= 1000000", "文件系统参数", "ulimit_min",
             key="-Sn", value="1000000",
             expected=">= 1000000",
             container_check=False,
             fix_refs=["配置文件系统参数"]),
    CheckDef(100052, "ulimit -Hn >= 1000000", "文件系统参数", "ulimit_min",
             key="-Hn", value="1000000",
             expected=">= 1000000",
             container_check=False,
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
             mandatory=True,
             fix_refs=[]),
    CheckDef(100010, "unzip 已安装", "unzip", "pkg",
             key="unzip", expected="installed",
             mandatory=True,
             fix_refs=["安装unzip"]),
    CheckDef(100057, "软件包管理器已配置", "软件包管理器", "show",
             expected="yum list libtar / zypper lr",
             cmd="yum list libtar 2>/dev/null || zypper lr 2>/dev/null",
             mandatory=True, container_check=False,
             fix_refs=["配置软件包管理器"]),

    # ===== 沙箱目录 =====
    CheckDef(100008, "沙箱目录 /var/chroot 为空", "沙箱目录", "show",
             expected="目录不存在或为空",
             cmd="ls -Al /var/chroot 2>&1 | head -3",
             mandatory=True, container_check=False,
             fix_refs=["清空沙箱目录"]),

    # ===== /etc/profile =====
    CheckDef(100060, "source /etc/profile 成功", "/etc/profile", "profile_source",
             expected="exit 0, no errors",
             mandatory=True,
             fix_refs=["配置/etc/profile文件"]),

    # ===== NUMA =====
    CheckDef(100062, "NUMA 分布均衡", "NUMA分布情况", "show",
             expected="各 NUMA 节点内存均匀",
             cmd="lscpu | grep NUMA",
             mandatory=True, container_check=False,
             fix_refs=[]),

    # ===== 网络通信 =====
    CheckDef(100063, "TPOPS 8601 端口可达", "网络通信检查", "show",
             expected="curl 成功",
             cmd="ss -tunlp 2>/dev/null | grep :8601 || echo 'no listener'",
             mandatory=True,
             fix_refs=["网络通信检查"]),
    CheckDef(100064, "TPOPS 10022 端口可达", "网络通信检查", "show",
             expected="curl 成功",
             cmd="ss -tunlp 2>/dev/null | grep :10022 || echo 'no listener'",
             mandatory=True,
             fix_refs=["网络通信检查"]),
    CheckDef(100065, "ping localhost 成功", "网络通信检查", "show",
             expected="0% loss",
             cmd="ping -c 2 -W 2 localhost 2>&1 | tail -2",
             mandatory=True, container_check=False,
             fix_refs=["网络通信检查"]),

    # ===== 网络端口占用检查 =====
    CheckDef(100066, "8000 端口未被占用", "网络端口占用检查", "port_free",
             port=8000, expected="free",
             fix_refs=["网络端口占用检查"]),
    CheckDef(100067, "9000 / 20050 端口未被占用", "网络端口占用检查", "ports_free",
             key="9000,20050", expected="free",
             mandatory=True,
             fix_refs=["网络端口占用检查"]),
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
             mandatory=True, container_check=False,
             fix_refs=["检查hosts文件"]),

    # ===== om_agent =====
    CheckDef(100074, "无 om_agent 进程残留", "om_agent进程", "om_agent",
             expected="无残留",
             mandatory=True, container_check=False,
             fix_refs=["检查om_agent进程"]),

    # ===== TPOPS 标识码 =====
    CheckDef(100075, "主机未在其他 TPOPS 上添加", "TPOPS标识码", "show",
             expected="host_unique_code 不存在或已解绑",
             cmd="cat /dbs/osPatch/host_unique_code 2>/dev/null || echo 'not exist'",
             mandatory=True,
             fix_refs=["检查TPOPS标识码"]),

    # ===== 添加主机机房名 =====
    CheckDef(100080, "机房名与数据库 AZ 一致", "添加主机时所选的机房名称", "show",
             expected="机房名 = cm_ctl query 中的 AZ",
             cmd="(su - omm -c 'source ~/gauss_env_file 2>/dev/null; cm_ctl query -CvzALL 2>/dev/null' | grep -i az) || echo 'no db installed'",
             mandatory=True,
             fix_refs=["检查实例安装使用的AZ名称"]),

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
    CheckDef(100087, "python 软链接", "扩展项", "python_link",
             expected="python → python3",
             mandatory=False,
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
    "配置系统服务": {
        "os_filter": None,
        "commands": [
            {"os": None, "cmd": "systemctl start iptables 2>/dev/null || true"},
            {"os": None, "cmd": "systemctl enable iptables 2>/dev/null || true"},
            {"os": None, "cmd": "systemctl unmask iptables 2>/dev/null || true"},
            {"os": None, "cmd": "systemctl start cgconfig 2>/dev/null || true"},
            {"os": None, "cmd": "systemctl enable cgconfig 2>/dev/null || true"},
            {"os": None, "cmd": "systemctl unmask cgconfig 2>/dev/null || true"},
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
            {"os": None, "cmd": "echo 'export LANG=en_US.UTF-8' >> /etc/profile"},
            {"os": None, "cmd": "echo 'LANG=en_US.UTF-8' > /etc/locale.conf 2>/dev/null || true"},
            {"os": None, "cmd": "echo 'LANG=en_US.UTF-8' > /etc/sysconfig/i18n 2>/dev/null || true"},
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
    "配置操作系统参数": {
        "os_filter": None,
        "commands": [
            # 在 /etc/sysctl.conf 末尾追加所有期望值（仅当缺失时追加）
            # 每个 key=value 用一行内联命令实现 grep+sed 或 echo append
            {"os": None, "cmd": "k=net.ipv4.tcp_max_tw_buckets; v=10000; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=net.ipv4.tcp_tw_reuse; v=1; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=net.ipv4.tcp_keepalive_time; v=30; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=net.ipv4.tcp_keepalive_probes; v=9; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=net.ipv4.tcp_keepalive_intvl; v=30; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=net.ipv4.tcp_retries1; v=5; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=net.ipv4.tcp_syn_retries; v=5; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=net.ipv4.tcp_synack_retries; v=5; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=net.ipv4.tcp_retries2; v=12; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=vm.overcommit_memory; v=0; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=net.ipv4.tcp_rmem; v='8192 250000 16777216'; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=net.ipv4.tcp_wmem; v='8192 250000 16777216'; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=net.core.wmem_max; v=21299200; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=net.core.rmem_max; v=21299200; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=net.core.wmem_default; v=21299200; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=net.core.rmem_default; v=21299200; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=net.ipv4.ip_local_port_range; v='26000 65535'; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=kernel.sem; v='250 6400000 1000 25600'; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=net.core.somaxconn; v=65535; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=net.ipv4.tcp_syncookies; v=1; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=net.core.netdev_max_backlog; v=65535; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=net.ipv4.tcp_max_syn_backlog; v=65535; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=net.ipv4.tcp_fin_timeout; v=60; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=kernel.shmall; v=1152921504606846720; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=kernel.shmmax; v=18446744073709551615; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=net.ipv4.tcp_sack; v=1; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=net.ipv4.tcp_timestamps; v=1; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=vm.extfrag_threshold; v=500; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "k=vm.overcommit_ratio; v=90; grep -q \"^${k}\" /etc/sysctl.conf 2>/dev/null && sed -i \"s|^${k}=.*|${k}=${v}|\" /etc/sysctl.conf || echo \"${k}=${v}\" >> /etc/sysctl.conf"},
            {"os": None, "cmd": "sysctl -p 2>/dev/null || true"},
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
    "检查om_agent进程": {
        "os_filter": None,
        "commands": [],  # 不自动 kill，仅检查
    },
    "检查TPOPS标识码": {
        "os_filter": None,
        "commands": [],  # 仅检查
    },
    "检查实例安装使用的AZ名称": {
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
            {"os": None, "cmd": "ln -sf /usr/bin/python3 /usr/bin/python 2>/dev/null || true"},
            {"os": None, "cmd": "ln -sf /usr/bin/python3 /usr/bin/python3.7 2>/dev/null || true"},
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
        if self.status == Status.SKIP:
            return "SKIP"
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
        if s == "SKIP":
            return f"{C_DIM}{s}{C_RESET}"
        return f"{C_MAGENTA}{s}{C_RESET}"


def _is_port_listening(port: int) -> bool:
    rc, out, _ = run_shell(f"ss -tunlp 2>/dev/null | grep -E ':{port}\\b'")
    if rc == 0 and out.strip():
        return True
    rc2, out2, _ = run_shell(f"netstat -tunlp 2>/dev/null | grep -E ':{port}\\b'")
    return rc2 == 0 and out2.strip() != ""


def _check_one(c: CheckDef, host: HostInfo) -> CheckResult:
    """执行单个 check，返回结果."""
    # Container/物理机过滤
    if c.container_check is False and host.is_container:
        return CheckResult(c.id, c.name, Status.SKIP, message="容器环境跳过（仅物理机检查）",
                             mandatory=c.mandatory)
    if c.container_check is True and not host.is_container and c.check_type == "show":
        # 物理机非容器的项不强制过滤；保留
        pass

    try:
        if c.check_type == "sysctl_eq":
            actual = _sysctl_value(c.key)
            ok = (actual == c.value)
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current=actual, expected=c.value,
                message="OK" if ok else f"期望 {c.value} 实际 {actual}",
                fix_refs=c.fix_refs,
                mandatory=c.mandatory,
            )

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

        if c.check_type == "om_agent":
            rc, out, _ = run_shell("ps -ef | grep -v grep | grep om_agent || true")
            has = bool(out.strip())
            ok = not has
            return CheckResult(
                c.id, c.name,
                Status.PASS if ok else Status.FAIL,
                current="存在残留" if has else "无残留",
                expected=c.expected,
                message="OK" if ok else "有 om_agent 进程残留",
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

        if c.check_type == "show":
            rc, out, err = run_shell(c.cmd, timeout=15)
            current = (out.strip().splitlines() or [""])[0][:80]
            return CheckResult(
                c.id, c.name, Status.SKIP,
                current=current, expected=c.expected,
                message=f"(手工核对) rc={rc}; first line: {current}",
                fix_refs=c.fix_refs,
                mandatory=c.mandatory,
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


def run_all_checks(host: HostInfo, ids: Optional[List[int]] = None) -> List[CheckResult]:
    """跑所有（或指定 ID 的）check. 强制校验项排在前面."""
    targets = list(CHECKS)
    if ids:
        targets = [c for c in CHECKS if c.id in ids]
    # 强制分组：所有 Y 项（mandatory=True）排在前，再排所有 n 项；同组内按 id 升序
    mandatory = sorted([c for c in targets if c.mandatory], key=lambda c: c.id)
    optional = sorted([c for c in targets if not c.mandatory], key=lambda c: c.id)
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
    if r.status == Status.SKIP:
        return f"{C_YELLOW}SKIP     {C_RESET}"
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
                     verbose: bool = False) -> None:
    """打印检查报告.

    布局顺序:
      1) 标题 + 时间 + 环境
      2) 顶部状态条（总览结论 + 状态计数）
      3) 详细表格（强制项在前）
      4) NOT OK 详情（完整信息，便于修复）
      5) WARNING 列表（精简：单行展示，非 verbose 时只列 item + 当前值）
      6) 底部汇总（按 强制 / 非强制 分组统计）
    """
    # ---------- 1. 标题 ----------
    print(f"\n{C_BOLD}主机标准化检查报告{C_RESET}")
    print(f"  时间    : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  操作系统  : {C_CYAN}{host.os_id} {host.os_version}{C_RESET}")
    print(f"  权限    : {C_CYAN}root={host.is_root}{C_RESET}    "
          f"环境: {C_CYAN}{'容器' if host.is_container else '物理机'}{C_RESET}")

    # ---------- 2. 顶部状态条 ----------
    ok_n = sum(1 for r in results if r.status == Status.PASS)
    not_ok_n = sum(1 for r in results if r.status == Status.FAIL and r.mandatory)
    warn_n = sum(1 for r in results if r.status == Status.FAIL and not r.mandatory)
    skip_n = sum(1 for r in results if r.status == Status.SKIP)
    err_n = sum(1 for r in results if r.status == Status.ERROR)
    total = len(results)

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
    print(f"  共 {C_BOLD}{total}{C_RESET} 项   "
          f"{C_GREEN}OK={ok_n}{C_RESET}   "
          f"{C_RED}{C_BOLD}NOT OK={not_ok_n}{C_RESET}   "
          f"{C_YELLOW}WARNING={warn_n}{C_RESET}   "
          f"{C_DIM}SKIP={skip_n}{C_RESET}   "
          f"{C_MAGENTA}ERROR={err_n}{C_RESET}")
    print(f"{C_DIM}{bar}{C_RESET}\n")

    # ---------- 3. 详细表格 ----------
    # 固定列宽：item 优先，current/expected 给足
    headers = ["#", "item", "current_value", "expected_value", "M", "status"]
    widths = [4, 30, 26, 22, 2, 8]   # M 列只放 1 字符的 Y/n
    # 终端太窄时压缩 current/expected
    term_w = shutil.get_terminal_size((140, 40)).columns
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

    # ---------- 4. NOT OK 详情（完整） ----------
    if not_ok:
        print(f"\n{C_RED}{C_BOLD}=== NOT OK（强制项不达标，必须修复）[{len(not_ok)} 项] ==={C_RESET}")
        for r in not_ok:
            print(f"  {C_BOLD}{r.display_item}{C_RESET}")
            print(f"      current : {r.display_current}")
            print(f"      expected: {r.display_expected}")
            print(f"      detail  : {r.message}")
            if r.fix_refs:
                print(f"      fix     : {', '.join(r.fix_refs)}")

    # ---------- 5. WARNING 列表（默认不输出，仅 --verbose 时显示） ----------
    if warning and verbose:
        print(f"\n{C_YELLOW}{C_BOLD}=== WARNING（非强制项不达标，建议修复）[{len(warning)} 项] ==={C_RESET}")
        for r in warning:
            print(f"  {C_BOLD}{r.display_item}{C_RESET}")
            print(f"      current : {r.display_current}")
            print(f"      expected: {r.display_expected}")
            if r.fix_refs:
                print(f"      fix     : {', '.join(r.fix_refs)}")

    # ---------- 6. 底部汇总（按 强制 / 非强制 分组） ----------
    mand = [r for r in results if r.mandatory]
    optional = [r for r in results if not r.mandatory]
    m_pass = sum(1 for r in mand if r.status == Status.PASS)
    m_fail = sum(1 for r in mand if r.status == Status.FAIL)
    m_skip = sum(1 for r in mand if r.status == Status.SKIP)
    m_err = sum(1 for r in mand if r.status == Status.ERROR)
    o_pass = sum(1 for r in optional if r.status == Status.PASS)
    o_fail = sum(1 for r in optional if r.status == Status.FAIL)
    o_skip = sum(1 for r in optional if r.status == Status.SKIP)
    o_err = sum(1 for r in optional if r.status == Status.ERROR)

    print(f"\n{C_DIM}{'─' * 64}{C_RESET}")
    print(f"{C_BOLD}分类统计{C_RESET}")
    print(f"  强制项   ({len(mand):>2} 项):  "
          f"{C_GREEN}OK={m_pass}{C_RESET}   "
          f"{C_RED}{C_BOLD}NOT OK={m_fail}{C_RESET}   "
          f"{C_DIM}SKIP={m_skip}{C_RESET}   "
          f"{C_MAGENTA}ERROR={m_err}{C_RESET}")
    print(f"  非强制项 ({len(optional):>2} 项):  "
          f"{C_GREEN}OK={o_pass}{C_RESET}   "
          f"{C_YELLOW}WARNING={o_fail}{C_RESET}   "
          f"{C_DIM}SKIP={o_skip}{C_RESET}   "
          f"{C_MAGENTA}ERROR={o_err}{C_RESET}")
    print(f"{C_DIM}{'─' * 64}{C_RESET}")


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
    print(f"{C_BOLD}共 {len(CHECKS)} 项检查{C_RESET}")
    print(f"  {'ID':<7} {'Category':<14} {'Name':<48} {'Type':<14} Container")
    print(f"  {'-'*7} {'-'*14} {'-'*48} {'-'*14} {'-'*10}")
    for c in CHECKS:
        con = "容器" if c.container_check else "物理机"
        print(f"  {c.id:<7} {c.category:<14} {_truncate(c.name, 47):<48} {c.check_type:<14} {con}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    host = detect_host()
    ids = args.ids if args.ids else None
    results = run_all_checks(host, ids)
    if args.json:
        import json as _json
        print(_json.dumps([{
            "id": r.id, "name": r.name, "status": r.status.value,
            "severity": r.severity_label,
            "mandatory": r.mandatory,
            "current": r.current, "expected": r.expected,
            "message": r.message, "fix_refs": r.fix_refs,
        } for r in results], ensure_ascii=False, indent=2))
    else:
        print_check_table(results, host, verbose=getattr(args, "verbose", False))
    not_ok = sum(1 for r in results if r.status == Status.FAIL and r.mandatory)
    return 2 if not_ok else (0 if not any(r.status == Status.FAIL for r in results) else 1)


def cmd_fix(args: argparse.Namespace) -> int:
    host = detect_host()
    if not host.is_root:
        print(f"{C_RED}ERROR: fix 子命令需要 root 权限 (current euid={os.geteuid()}){C_RESET}")
        return 3
    ids = args.ids if args.ids else None
    results = run_all_checks(host, ids)
    fails = [r for r in results if r.status == Status.FAIL]
    if not fails:
        print(f"{C_GREEN}所有 check 项都已 PASS，无需 fix。{C_RESET}")
        return 0
    not_ok_n = sum(1 for r in fails if r.mandatory)
    warn_n = len(fails) - not_ok_n
    print(f"{C_YELLOW}有 {not_ok_n} 项 NOT OK（强制）+ {warn_n} 项 WARNING（非强制），开始执行修复...{C_RESET}\n")
    steps = run_fix(fails, host, assume_yes=args.yes)
    failed = print_fix_report(steps)
    if failed:
        print(f"\n{C_RED}存在 {failed} 条修复失败，请查看上方报错原因和对应 fix 项后手动处理。{C_RESET}")
        return 2
    # 重新跑一遍检查
    print(f"\n{C_BOLD}重新跑一遍 check 验证...{C_RESET}")
    new_results = run_all_checks(host, ids)
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
    )
    p.add_argument("--no-color", action="store_true", help="禁用 ANSI 颜色")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_check = sub.add_parser("check", help="运行所有检查并打印报告")
    p_check.add_argument("--id", type=int, action="append", dest="ids",
                         help="仅检查指定 ID（可多次）")
    p_check.add_argument("--json", action="store_true", help="JSON 输出")
    p_check.add_argument("--verbose", "-v", action="store_true",
                         help="同时显示非强制 WARNING 项的详情（默认仅显示 NOT OK）")
    p_check.set_defaults(func=cmd_check)

    p_fix = sub.add_parser("fix", help="对 FAIL 项执行修复命令")
    p_fix.add_argument("--id", type=int, action="append", dest="ids",
                       help="仅修复指定 ID（可多次）")
    p_fix.add_argument("--yes", action="store_true",
                       help="允许执行危险命令（rm -r / reboot 等）")
    p_fix.set_defaults(func=cmd_fix)

    p_list = sub.add_parser("list", help="列出所有检查项")
    p_list.set_defaults(func=lambda a: cmd_list())

    args = p.parse_args(argv)
    if args.no_color:
        USE_COLOR = False
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
