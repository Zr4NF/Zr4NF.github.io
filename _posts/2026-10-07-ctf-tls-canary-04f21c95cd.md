---
layout: post
title: "TLS canary"
date: 2026-10-07 20:05:00 +0800
tags: ["CTF", "PWN"]
---
{% raw %}

### 介绍：TLS的基本概念

  TLS（线程本地存储）是一种在线程内存中存储特定数据的机制。每个线程都有自己**独立的TLS区域**，用于存储与该线程相关的数据。

  在堆栈保护方面，TLS常被用于存储堆栈canary值。

  对于多线程的canary来说，每个线程的canary都是独立存在的。当一个线程被创建时，操作系统会为该线程分配一个独立的TLS区域（在libc中），这个区域通常通过某种线程控制块（TCB）来管理。每个线程都有一个独立的TCB，从而确保了每个线程的canary值的独立性和安全性。

### 多线程环境中的TLS和Canary

  在多线程环境中，每个线程的栈上都会有一个**独立的**canary值。操作系统或运行时库在为每个线程分配堆栈时，会在栈的适当位置插入一个canary值，以**防止缓冲区溢出攻击**。

  每个线程都有自己的TLS区域和独立的canary值，从而确保了多线程程序的安全性。

  但是，多线程的canary通常也有被利用的时候，当程序创建线程的时候会创建TLS，TLS里面会存储有canary的值，而TLS会保存在stack高地址的地方那么就是说，如果我们可以通过溢出覆盖到TLS的位置那么就可以绕过canary，但是这个条件比较苛刻。

```
高地址
+-------------------------+
| TLS / TCB               |  <- fs 指向的区域附近
+-------------------------+
| thread stack top        |
|                         |
| 栈向下增长              |
|                         |
| 当前函数栈帧             |
+-------------------------+
低地址
```

- **溢出字节够大，通常至少一个page（4K）**

- **创建一个线程，在线程内栈溢出**
主线程的 TLS 位置通常比较随机，而子线程的 TLS 通常作为线程栈的一部分被分配，其好处是避免额外的内存分配。

所以一般来说还是比较安全的，但是不排除，有些疏忽的漏洞导致攻击者可以修改到**stack_guard**字段的内容，要了解**stack_guard**首先先看两个结构体。

### **struct pthread结构体解析**

```cpp
#include <stddef.h> // 为了使用 size_t
​
/* Definition of the tcbhead_t structure (hypothetical) */
typedef struct {
    void *tcb;            /* 指向线程控制块（TCB）的指针 */
    dtv_t *dtv;           /* 线程特定数据的指针 */
    void *self;           /* 指向线程描述符的指针 */
    int multiple_threads; /* 标识是否有多个线程 */
    int gscope_flag;      /* 全局作用域标志 */
    uintptr_t sysinfo;    /* 系统信息 */
    uintptr_t stack_guard;/* 堆栈保护 */
    uintptr_t pointer_guard; /* 指针保护 */
​
    /* 其他可能的字段... */
} tcbhead_t;
​
​
/* Define the pthread structure */
struct pthread {
#if !TLS_DTV_AT_TP
    /* This overlaps the TCB as used for TLS without threads (see tls.h).  */
    tcbhead_t header; // 可能与TLS相关的头部信息
#else
    struct {
        // 更复杂的结构体定义
        // 可能包含与TLS相关的更多详细信息
        // ...
    } header;
#endif
​
    /* Extra padding for alignment and potential future use */
    void *__padding[24]; // 填充数组，用于对齐和可能的未来扩展
};
​
```

在这个结构体中，我们看到第一个字段是`tcbhead_t`，它包含了线程控制块（TCB）的相关信息。

在这个结构体中，`stack_guard`字段存放的就是单线程的canary值。攻击者通常可以通过覆盖这个值的内容来绕过canary保护。

汇编中的取用：
```asm
fs:0x00  TCB 自引用相关字段
fs:0x08  DTV 指针
fs:0x10  self 指针相关字段
fs:0x28  stack canary
fs:0x30  pointer_guard
```

### 整体结构

```asm
高地址
+--------------------------------------------------+
| pthread descriptor / struct pthread              |
|   - tid                                          |
|   - join/detach state                            |
|   - stack info                                   |
|   - 线程管理信息                                 |
|                                                  |
|   [其中头部/附近通常包含 TCB]                     |
|   - fs:0x28 = stack canary 原始值                |
|   - fs:0x30 = pointer_guard                      |
+--------------------------------------------------+
| TLS                                              |
|   - __thread 变量                                |
|   - errno                                        |
|   - DTV                                          |
|   - 线程私有数据                                 |
+--------------------------------------------------+
| thread stack top                                 |
|                                                  |
|    栈向低地址增长                                |
|                                                  |
|    当前函数栈帧：                                 |
|      ret addr                                    |
|      saved rbp                                   |
|      canary 副本  <- [rbp-0x8]                   |
|      local buf   <- [rbp-0x1010]                 |
|                                                  |
+--------------------------------------------------+
| guard page (PROT_NONE)                           |
+--------------------------------------------------+
低地址
```
# 测试程序

```c
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <asm/prctl.h>

__thread int tls_var = 0x12345678;

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
int global_counter = 0;

static long get_tid(void)
{
    return syscall(SYS_gettid);
}

static unsigned long get_fs_base(void)
{
    unsigned long fs_base = 0;
    syscall(SYS_arch_prctl, ARCH_GET_FS, &fs_base);
    return fs_base;
}

static unsigned long read_canary(void)
{
    unsigned long canary;

#if defined(__x86_64__)
    __asm__("mov %%fs:0x28, %0" : "=r"(canary));
#else
    canary = 0;
#endif

    return canary;
}

void show_thread_info(const char *name)
{
    pthread_attr_t attr;
    void *stack_addr = NULL;
    size_t stack_size = 0;
    size_t guard_size = 0;

    pthread_getattr_np(pthread_self(), &attr);
    pthread_attr_getstack(&attr, &stack_addr, &stack_size);
    pthread_attr_getguardsize(&attr, &guard_size);

    char local_buf[0x100];

    printf("\n========== %s ==========\n", name);
    printf("pthread_self()      = %p\n", (void *)pthread_self());
    printf("gettid()            = %ld\n", get_tid());

    printf("stack_addr          = %p\n", stack_addr);
    printf("stack_size          = 0x%lx\n", stack_size);
    printf("stack_end           = %p\n", (char *)stack_addr + stack_size);
    printf("guard_size          = 0x%lx\n", guard_size);

    printf("&local_buf          = %p\n", local_buf);
    printf("&tls_var            = %p\n", &tls_var);

    printf("fs_base / TCB       = 0x%lx\n", get_fs_base());
    printf("fs:0x28 canary      = 0x%lx\n", read_canary());
    printf("tls_var value       = 0x%x\n", tls_var);

    pthread_attr_destroy(&attr);
}

void *worker(void *arg)
{
    int idx = *(int *)arg;

    char name[0x20];
    snprintf(name, sizeof(name), "thread-%d", idx);

    tls_var += idx;

    show_thread_info(name);

    for (int i = 0; i < 5; i++)
    {
        pthread_mutex_lock(&lock);

        global_counter++;
        printf("[%s] loop=%d, global_counter=%d\n",
               name, i, global_counter);

        pthread_mutex_unlock(&lock);

        sleep(1);
    }

    printf("[%s] finished\n", name);

    return (void *)(uintptr_t)(0xdead0000 + idx);
}

int main(void)
{
    pthread_t t1;
    pthread_t t2;

    int arg1 = 1;
    int arg2 = 2;

    void *ret1 = NULL;
    void *ret2 = NULL;

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf("[main] pid = %d\n", getpid());
    printf("[main] tid = %ld\n", get_tid());

    show_thread_info("main-thread");

    printf("\n[main] creating threads...\n");

    pthread_create(&t1, NULL, worker, &arg1);
    pthread_create(&t2, NULL, worker, &arg2);

    printf("[main] pthread_create done\n");

    pthread_join(t1, &ret1);
    pthread_join(t2, &ret2);

    printf("\n[main] pthread_join done\n");
    printf("[main] thread-1 return = %p\n", ret1);
    printf("[main] thread-2 return = %p\n", ret2);
    printf("[main] global_counter  = %d\n", global_counter);

    return 0;
}
```



```asm
[main] pid = 3747
[main] tid = 3747

========== main-thread ==========
pthread_self()      = 0x7ffff7fa8740
gettid()            = 3747
stack_addr          = 0x7fffff7ff000
stack_size          = 0x7ff000
stack_end           = 0x7fffffffe000
guard_size          = 0x0
&local_buf          = 0x7fffffffd9a0
&tls_var            = 0x7ffff7fa873c
fs_base / TCB       = 0x7ffff7fa8740
fs:0x28 canary      = 0x9a201e92cd2c6600
tls_var value       = 0x12345678

[main] creating threads...
[New Thread 0x7ffff7bff6c0 (LWP 3748)]

========== thread-1 ==========
pthread_self()      = 0x7ffff7bff6c0
gettid()            = 3748
stack_addr          = 0x7ffff7400000
stack_size          = 0x800000
stack_end           = 0x7ffff7c00000
guard_size          = 0x1000
&local_buf          = 0x7ffff7bfed50
&tls_var            = 0x7ffff7bff6bc
fs_base / TCB       = 0x7ffff7bff6c0
fs:0x28 canary      = 0x9a201e92cd2c6600
tls_var value       = 0x12345679
[thread-1] loop=0, global_counter=1
[New Thread 0x7ffff73fe6c0 (LWP 3749)]
[main] pthread_create done

========== thread-2 ==========
pthread_self()      = 0x7ffff73fe6c0
gettid()            = 3749
stack_addr          = 0x7ffff6bff000
stack_size          = 0x800000
stack_end           = 0x7ffff73ff000
guard_size          = 0x1000
&local_buf          = 0x7ffff73fdd50
&tls_var            = 0x7ffff73fe6bc
fs_base / TCB       = 0x7ffff73fe6c0
fs:0x28 canary      = 0x9a201e92cd2c6600
tls_var value       = 0x1234567a
[thread-2] loop=0, global_counter=2
[thread-1] loop=1, global_counter=3
[thread-2] loop=1, global_counter=4
[thread-1] loop=2, global_counter=5
[thread-2] loop=2, global_counter=6
[thread-1] loop=3, global_counter=7
[thread-2] loop=3, global_counter=8
[thread-1] loop=4, global_counter=9
[thread-2] loop=4, global_counter=10
[thread-1] finished
[thread-2] finished
[Thread 0x7ffff7bff6c0 (LWP 3748) exited]

[main] pthread_join done
[main] thread-1 return = 0xdead0001
[main] thread-2 return = 0xdead0002
[main] global_counter  = 10
[Thread 0x7ffff73fe6c0 (LWP 3749) exited]

```


### 攻击思路

- 由于新建线程的`pthread_self()`与其栈底相近，所以如果有新建线程，可以通过大 size 溢出写覆盖 canary 进行绕过。

- 如果没有新建线程，那只能通过任意写修改tls，因tls一般由`nmap()`分配，由该函数分配的地址一般在 libc 上下，所以可以通过 libc 地址进行偏移计算。

*anon为`nmap()`申请部分：*
```asm
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size  Offset File (set vmmap-prefer-relpaths on)
    0x555555554000     0x555555555000 r--p     1000       0 a
    0x555555555000     0x555555556000 r-xp     1000    1000 a
    0x555555556000     0x555555557000 r--p     1000    2000 a
    0x555555557000     0x555555558000 r--p     1000    2000 a
    0x555555558000     0x555555559000 rw-p     1000    3000 a
    0x555555559000     0x55555557a000 rw-p    21000       0 [heap]
    0x7fffe8000000     0x7fffe8021000 rw-p    21000       0 [anon_7fffe8000]
    0x7fffe8021000     0x7fffec000000 ---p  3fdf000       0 [anon_7fffe8021]
    0x7ffff0000000     0x7ffff0021000 rw-p    21000       0 [anon_7ffff0000]
    0x7ffff0021000     0x7ffff4000000 ---p  3fdf000       0 [anon_7ffff0021]
    0x7ffff6bfe000     0x7ffff6bff000 ---p     1000       0 [anon_7ffff6bfe]
    0x7ffff6bff000     0x7ffff73ff000 rw-p   800000       0 [anon_7ffff6bff]
    0x7ffff73ff000     0x7ffff7400000 ---p     1000       0 [anon_7ffff73ff]
    0x7ffff7400000     0x7ffff7c00000 rw-p   800000       0 [anon_7ffff7400]
    0x7ffff7c00000     0x7ffff7c28000 r--p    28000       0 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7c28000     0x7ffff7db0000 r-xp   188000   28000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7db0000     0x7ffff7dff000 r--p    4f000  1b0000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7dff000     0x7ffff7e03000 r--p     4000  1fe000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7e03000     0x7ffff7e05000 rw-p     2000  202000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7e05000     0x7ffff7e12000 rw-p     d000       0 [anon_7ffff7e05]
    0x7ffff7fa8000     0x7ffff7fab000 rw-p     3000       0 [anon_7ffff7fa8]
    0x7ffff7fbb000     0x7ffff7fbd000 rw-p     2000       0 [anon_7ffff7fbb]
    0x7ffff7fbd000     0x7ffff7fc1000 r--p     4000       0 [vvar]
    0x7ffff7fc1000     0x7ffff7fc3000 r--p     2000       0 [vvar_vclock]
    0x7ffff7fc3000     0x7ffff7fc5000 r-xp     2000       0 [vdso]
    0x7ffff7fc5000     0x7ffff7fc6000 r--p     1000       0 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7fc6000     0x7ffff7ff1000 r-xp    2b000    1000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ff1000     0x7ffff7ffb000 r--p     a000   2c000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffb000     0x7ffff7ffd000 r--p     2000   36000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffd000     0x7ffff7fff000 rw-p     2000   38000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffffffdd000     0x7ffffffff000 rw-p    22000       0 [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000       0 [vsyscall]

```

{% endraw %}
