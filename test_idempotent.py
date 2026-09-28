#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gaussdb_precheck.py 文件修改函数的幂等性测试。

每个函数都连续执行 3 次——每次都把"当前文件内容"作为输入——最终文件内容
应当与执行 1 次后完全一致，且不会出现重复段落 / 重复行。
"""

import importlib.util
import os
import re
import tempfile

spec = importlib.util.spec_from_file_location(
    "gpc", os.path.join(os.path.dirname(__file__), "gaussdb_precheck.py")
)
gpc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gpc)


def thrice(func, initial: str, *args, **kwargs) -> str:
    """调用 func 三次, 每次读取上一轮的文件内容作为输入. kwargs 用于传文件路径等. 返回最终内容.

    `initial` 是文件初始内容；首次调用前先写入 target, 之后每次调用都把当前文件内容作为第一参数.
    """
    target = kwargs.pop("_target")
    with open(target, "w") as f:
        f.write(initial)
    for _ in range(3):
        current = open(target).read()
        func(current, *args, **kwargs)
    return open(target).read()


def main():
    passed = []

    # 1. _set_profile_lang: 默认写到 /etc/profile, 这里把路径改成临时文件
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, "profile")
        body = thrice(gpc._set_profile_lang, "", _target=target, path=target)
        assert body.count("export LANG=en_US.UTF-8") == 1, body
        assert body.count(gpc.MANAGED_BEGIN) == 1, body
    passed.append("_set_profile_lang")

    # 2. _set_profile_lcall
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, "profile")
        body = thrice(gpc._set_profile_lcall, "", _target=target, path=target)
        assert body.count("export LC_ALL=en_US.UTF-8") == 1, body
    passed.append("_set_profile_lcall")

    # 3. _set_hist
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, "profile")
        body = thrice(gpc._set_hist, "", _target=target, path=target)
        assert body.count("HISTSIZE=0") == 1, body
    passed.append("_set_hist")

    # 4. /etc/sysconfig/i18n 与 /etc/locale.conf 不再被本脚本修改
    passed.append("(locale 不再修改, 跳过)")

    # 5. _set_selinux_permissive
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, "selinux.config")
        for _ in range(3):
            current = open(target).read() if os.path.exists(target) else ""
            gpc._set_selinux_permissive(target, current)
        body = open(target).read()
        assert body.count("SELINUX=permissive") == 1, body
    passed.append("_set_selinux_permissive")

    # 6. _ensure_limit_line
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, "limits.conf")
        line = "* soft nofile 1000000"
        for _ in range(3):
            current = open(target).read() if os.path.exists(target) else ""
            gpc._ensure_limit_line(target, current, line)
        body = open(target).read()
        assert body.count(line) == 1, body
    passed.append("_ensure_limit_line")

    # 7. _strip_root_nofile
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, "limits.conf")
        initial = "root soft nofile 4096\n* soft nofile 1000000\n"
        with open(target, "w") as f:
            f.write(initial)
        for _ in range(3):
            current = open(target).read()
            gpc._strip_root_nofile(target, current)
        body = open(target).read()
        assert "root soft nofile" not in body, body
        assert body.count("* soft nofile 1000000") == 1, body
    passed.append("_strip_root_nofile")

    # 8. _ensure_nproc
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, "90-nproc.conf")
        for _ in range(3):
            current = open(target).read() if os.path.exists(target) else ""
            gpc._ensure_nproc(target, current)
        body = open(target).read()
        assert body.count("* soft nproc 60000") == 1, body
    passed.append("_ensure_nproc")

    # 9. _comment_swap_fstab
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, "fstab")
        body = thrice(
            gpc._comment_swap_fstab,
            "UUID=abc swap swap defaults 0 0\n/dev/sda1 / ext4 defaults 0 0\n",
            _target=target,
            path=target,
        )
        assert body.count("# UUID=abc swap swap defaults 0 0") == 1, body
    passed.append("_comment_swap_fstab")

    # 10. sysctl 已不再被本脚本修改, 故不测试.
    passed.append("(sysctl 不再修改, 跳过)")

    # 11. _append_rc_local
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, "rc.local")
        marker = "if [ -f /sys/kernel/mm/transparent_hugepage/enabled ]; then"
        for _ in range(3):
            gpc._append_rc_local(target, marker)
        body = open(target).read()
        # block 内字符串出现两次（if 行 + echo 行）; 验证整个 managed block 只出现 1 次
        assert body.count(gpc.MANAGED_BEGIN) == 1, body
        assert body.count(gpc.MANAGED_END) == 1, body
    passed.append("_append_rc_local")

    print(f"✅ {len([p for p in passed if not p.startswith('(')])} 个文件修改函数全部幂等通过:")
    for name in passed:
        print(f"   - {name}")


if __name__ == "__main__":
    main()
