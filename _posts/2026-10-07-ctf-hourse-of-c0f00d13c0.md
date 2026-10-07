---
layout: post
title: "House of Techniques"
date: 2026-10-07 20:05:00 +0800
tags: ["CTF", "PWN"]
description: "整理 House of 系列堆利用技巧。"
source_folder: "PWN/Heap Exploitation"
lang: zh-CN
---
{% raw %}

## 1 - 前言[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#1-%e5%89%8d%e8%a8%80)

`Glibc` 的 `house of` 系列攻击手法基于都是围绕着堆利用和 `IO FILE` 利用。还有很多堆利用手法也非常经典，但是由于其没有被冠以 `house of xxxx`，故没有收录到本文中。如果想学习所有的详细的堆攻击手法，强烈建议 `follow` 仓库 [how2heap](https://github.com/shellphish/how2heap)进行学习。我相信，只要把 `how2heap` 里面的每一个堆利用手法都学懂学透了，`glibc` 堆利用你将尽在掌握。

在开始系列总结之前，我会给出一个表格，表格里面分别是 `house of xxxx` 和对应的优秀的解析文章，在此非常感谢各位师傅们的总结。如果你在阅读本文的过程中想完整地查看某一个手法地详细利用过程，那么可以直接回到表格，点击对应的链接进行学习。目前的最新版本为 `2.37`，但是，目前的 `ubuntu:23.04` 还没开始用 `glibc-2.37`，使用的仍然是 `glibc-2.36`。

如果还有哪些 `house of xxxx` 的利用手法没有收录进来，或你对本文存有一些疑问，或者你发现本文某些内容编写错误，还请留言指正。

需要注意的是，除了关注各种 `house of` 利用技巧本身，更重要的是，需要关注该利用技巧背后的思想和原理。如果你能从这一系列的利用手法中提炼出一些通用的攻击向量或者攻击思想，日后在面对其他的场景，你也能更快的找到系统的漏洞点并加以利用。学习 `glibc` 堆利用更多的是为了举一反三，为了更好地掌握漏洞挖掘模式、漏洞分析方法，而不仅仅是为了比赛。

`house of` 系列的表格如下，适用版本不考虑低于 `glibc-2.23` 的版本。我将在下文中进一步阐述每一个利用手法的原理、使用场景与适用范围。

| 攻击方法               | 影响范围       | 学习链接                                                                                                                                                                                                                                        |
| ------------------ | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| house of spirit    | 2.23—— 至今  | [堆利用系列之 house of spirit - 安全客 - 安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/244158)                                                                                                                                             |
| house of einherjar | 2.23—— 至今  | [PWN——House Of Einherjar CTF Wiki 例题详解 - 安全客 - 安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/251596)                                                                                                                              |
| house of force     | 2.23——2.29 | [Top chunk 劫持：House of force 攻击 - 安全客 - 安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/175630)                                                                                                                                     |
| house of lore      | 2.23—— 至今  | [House of Lore - CTF Wiki (ctf-wiki.org)](https://ctf-wiki.org/pwn/linux/user-mode/heap/ptmalloc2/house-of-lore/)                                                                                                                           |
| house of orange    | 2.23——2.26 | [House of orange - 安全客 - 安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/218887)                                                                                                                                                    |
| house of rabbit    | 2.23——2.28 | [http://p4nda.top/2018/04/18/house-of-rabbit/](http://p4nda.top/2018/04/18/house-of-rabbit/)                                                                                                                                                |
| house of roman     | 2.23——2.29 | [House of Roman - CTF Wiki (ctf-wiki.org)](https://ctf-wiki.org/pwn/linux/user-mode/heap/ptmalloc2/house-of-roman/)                                                                                                                         |
| house of storm     | 2.23——2.29 | [House of storm 原理及利用 - 安全客 - 安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/203096)                                                                                                                                               |
| house of corrosion | 2.23—— 至今  | [House-of-Corrosion 一种新的堆利用技巧 - 先知社区 (aliyun.com)](https://xz.aliyun.com/t/6862#toc-5)                                                                                                                                                      |
| house of husk      | 2.23—— 至今  | [house-of-husk 学习笔记 - 安全客 - 安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/202387)                                                                                                                                                 |
| house of atum      | 2.26——2.30 | [https://abf1ag.github.io/2021/06/11/house-of-atum/](https://abf1ag.github.io/2021/06/11/house-of-atum/)                                                                                                                                    |
| house of kauri     | 2.26——2.32 | [Overview of GLIBC heap exploitation techniques (0x434b.dev)](https://0x434b.dev/overview-of-glibc-heap-exploitation-techniques/#house-of-kauri)                                                                                            |
| house of fun       | 2.23——2.30 | [Overview of GLIBC heap exploitation techniques (0x434b.dev)](https://0x434b.dev/overview-of-glibc-heap-exploitation-techniques/#house-of-fun)                                                                                              |
| house of mind      | 2.23—— 至今  | [how2heap/house_of_mind_fastbin.c at master · shellphish/how2heap (github.com)](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_mind_fastbin.c)                                                                      |
| house of muney     | 2.23—— 至今  | [House of Muney 分析 - 安全客 - 安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/254797)                                                                                                                                                  |
| house of botcake   | 2.23—— 至今  | [奇安信攻防社区 - 深入理解 House of Botcake 堆利用手法 (butian.net)](https://forum.butian.net/share/1709)                                                                                                                                                   |
| house of rust      | 2.26—— 至今  | [c4ebt/House-of-Rust](https://github.com/c4ebt/House-of-Rust)                                                                                                                                                                               |
| house of crust     | 2.26——2.37 | [c4ebt/House-of-Rust](https://github.com/c4ebt/House-of-Rust)                                                                                                                                                                               |
| house of io        | 2.26—— 至今  | [Overview of GLIBC heap exploitation techniques (0x434b.dev)](https://0x434b.dev/overview-of-glibc-heap-exploitation-techniques/#house-of-io)                                                                                               |
| house of banana    | 2.23—— 至今  | [house of banana - 安全客 - 安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/222948)                                                                                                                                                    |
| house of kiwi      | 2.23——2.36 | [House OF Kiwi - 安全客 - 安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/235598)                                                                                                                                                      |
| house of emma      | 2.23—— 至今  | [house of emma](https://www.anquanke.com/post/id/260614)                                                                                                                                                                                    |
| house of pig       | 2.23—— 至今  | [house of pig 一个新的堆利用详解 - 安全客 - 安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/242640)                                                                                                                                             |
| house of obstack   | 2.23—— 至今  | [一条新的 glibc IO_FILE 利用链：_IO_obstack_jumps 利用分析 - 跳跳糖 (tttang.com)](https://tttang.com/archive/1845/)                                                                                                                                        |
| house of apple1    | 2.23—— 至今  | [House of Apple 一种新的 glibc 中 IO 攻击方法 (1) - roderick - record and learn! (roderickchan.cn)](https://roderickchan.github.io/zh-cn/house-of-apple-%e4%b8%80%e7%a7%8d%e6%96%b0%e7%9a%84glibc%e4%b8%adio%e6%94%bb%e5%87%bb%e6%96%b9%e6%b3%95-1/) |
| house of apple2    | 2.23—— 至今  | [House of Apple 一种新的 glibc 中 IO 攻击方法 (2) - roderick - record and learn! (roderickchan.cn)](https://roderickchan.github.io/zh-cn/house-of-apple-%e4%b8%80%e7%a7%8d%e6%96%b0%e7%9a%84glibc%e4%b8%adio%e6%94%bb%e5%87%bb%e6%96%b9%e6%b3%95-2/) |
| house of apple3    | 2.23—— 至今  | [House of Apple 一种新的 glibc 中 IO 攻击方法 (3) - roderick - record and learn! (roderickchan.cn)](https://roderickchan.github.io/zh-cn/house-of-apple-%e4%b8%80%e7%a7%8d%e6%96%b0%e7%9a%84glibc%e4%b8%adio%e6%94%bb%e5%87%bb%e6%96%b9%e6%b3%95-3/) |
| house of gods      | 2.23——2.27 | [house-of-gods/HOUSE_OF_GODS.TXT at master · Milo-D/house-of-gods (github.com)](https://github.com/Milo-D/house-of-gods/blob/master/rev2/HOUSE_OF_GODS.TXT)                                                                                 |
| house of lys       | 2.23—— 至今  | [[SECCON CTF 2022 Quals] babyfile \| repr](https://nasm.re/posts/babyfile/)或者[一条新的 glibc IO_FILE 利用链：_IO_obstack_jumps 利用分析 - 7resp4ss - 博客园](https://www.cnblogs.com/7resp4ss/p/17486261.html)                                             |
| house of snake     | 2.23—— 至今  | [house of snake：一条高版本 Glibc IO 调用链 - 7resp4ss - 博客园](https://www.cnblogs.com/7resp4ss/p/17300224.html)                                                                                                                                      |

此外，阅读下文之前需要了解：

- 下面所述的 `chunk A`，地址 `A` 指的是 `chunk header` 地址，而不是 `user data` 地址。
- 漏洞成因基本上都是堆溢出、`UAF` 等

## 2-House Of 系列[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#2-house-of%e7%b3%bb%e5%88%97)

## 2.1-House of Spirit[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#21-house-of-spirit)

### 漏洞成因[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e6%bc%8f%e6%b4%9e%e6%88%90%e5%9b%a0)

堆溢出写

### 适用范围[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e9%80%82%e7%94%a8%e8%8c%83%e5%9b%b4)

- `2.23`—— 至今

### 利用原理[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e5%8e%9f%e7%90%86)

利用堆溢出，修改 `chunk size`，伪造出 `fake chunk`，然后通过堆的释放和排布，控制 `fake chunk`。`house of spirit` 的操作思路有很多，比如可以按如下操作进行利用：

- 申请 `chunk A、chunk B、chunk C、chunk D`
- 对 `A` 写操作的时候溢出，修改 `B` 的 `size` 域，使其能包括 `chunk C`
- 释放 `B`，然后把 `B` 申请回来，再释放 `C`，则可以通过读写 `B` 来控制 `C` 的内容

### 相关技巧[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e7%9b%b8%e5%85%b3%e6%8a%80%e5%b7%a7)

起初 `house of spirit` 主要是针对 `fastbin`，后来引入了 `tcachebin` 后，也可以使用 `tcachebin` 版本的 `house of spirit`。利用方法与 `fastbin` 场景下类似，注意好不同版本下的检查条件即可。

### 利用效果[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e6%95%88%e6%9e%9c)

- 劫持 `fastbin/tcachebin` 的 `fd` 之后，可以任意地址分配、任意地址读写

## 2.2-House of Einherjar[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#22-house-of-einherjar)

### 漏洞成因[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e6%bc%8f%e6%b4%9e%e6%88%90%e5%9b%a0-1)

溢出写、`off by one`、`off by null`

### 适用范围[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e9%80%82%e7%94%a8%e8%8c%83%e5%9b%b4-1)

- `2.23`—— 至今
- 可分配大于处于 `unsortedbin` 的 `chunk`（通常 ≥ 0x80）

### 利用原理[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e5%8e%9f%e7%90%86-1)

利用 `off by null` 修改掉 `chunk` 的 `size` 域的 `P` 位，绕过 `unlink` 检查，在堆的后向合并过程中构造出 `chunk overlapping`。

- 申请 `chunk A、chunk B、chunk C、chunk D`，`chunk D` 用来做 `gap`，`chunk A、chunk C` 都要处于 `unsortedbin` 范围
- 释放 `A`，进入 `unsortedbin`
- 对 `B` 写操作的时候存在 `off by null`，修改了 `C` 的 `P` 位
- 释放 `C` 的时候，堆后向合并，直接把 `A、B、C` 三块内存合并为了一个 `chunk`，并放到了 `unsortedbin` 里面
- 读写合并后的大 `chunk` 可以操作 `chunk B` 的内容，`chunk B` 的头

### 相关技巧[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e7%9b%b8%e5%85%b3%e6%8a%80%e5%b7%a7-1)

虽然该利用技巧至今仍可以利用，但是需要对 `unlink` 绕过的条件随着版本的增加有所变化。

最开始的 `unlink` 的代码是：

```c
/* Take a chunk off a bin list */
#define unlink(AV, P, BK, FD) {                                            \
    FD = P->fd;								      \
    BK = P->bk;								      \
    if (__builtin_expect (FD->bk != P \| BK->fd != P, 0))		      \
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
    else {								      \
		// .....							      \
      }									      
}
```

只需要绕过`__builtin_expect (FD->bk != P || BK->fd != P, 0)` 即可，因此，不需要伪造地址处于高位的 `chunk` 的 `presize` 域。

高版本的 `unlink` 的条件是：

```c
/* Take a chunk off a bin list.  */
static void
unlink_chunk (mstate av, mchunkptr p)
{
  if (chunksize (p) != prev_size (next_chunk (p)))
    malloc_printerr ("corrupted size vs. prev_size");

  mchunkptr fd = p->fd;
  mchunkptr bk = p->bk;

  if (__builtin_expect (fd->bk != p \| bk->fd != p, 0))
    malloc_printerr ("corrupted double-linked list");
	// ......
}
```

新增了 `chunksize (p) != prev_size (next_chunk (p))`，对 `chunksize` 有了检查，伪造的时候需要绕过。

布局示例：
![IMG-20260509165328737](/assets/ctf/d7f7ae6005e77ab46cb9.webp)
### 利用效果[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e6%95%88%e6%9e%9c-1)

- 构造 `chunk overlap` 后，可以任意地址分配
- 结合其他方法进行任意地址读写

## 2.3-House of Force[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#23-house-of-force)

### 漏洞成因[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e6%bc%8f%e6%b4%9e%e6%88%90%e5%9b%a0-2)

堆溢出写 `top_chunk`

### 适用范围[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e9%80%82%e7%94%a8%e8%8c%83%e5%9b%b4-2)

- `2.23`——`2.29`
- 可分配任意大小的 `chunk`
- 需要泄露或已知地址

### 利用原理[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e5%8e%9f%e7%90%86-2)

对 `top_chunk` 的利用，过程如下：

- 申请 `chunk A`
- 写 `A` 的时候溢出，修改 `top_chunk` 的 `size` 为很大的数
- 分配很大的 `chunk` 到任意已知地址

### 相关技巧[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e7%9b%b8%e5%85%b3%e6%8a%80%e5%b7%a7-2)

注意，在 `glibc-2.29` 后加入了检测，`house of force` 基本失效：

![image-20230303194137930](https://image.roderickchan.cn/img/image-20230303194137930.png)

### 利用效果[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e6%95%88%e6%9e%9c-2)

- 任意地址分配
- 任意地址读写

## 2.4-House of Lore[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#24-house-of-lore)

### 漏洞成因[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e6%bc%8f%e6%b4%9e%e6%88%90%e5%9b%a0-3)

堆溢出、`use after free`、`edit after free`

### 适用范围[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e9%80%82%e7%94%a8%e8%8c%83%e5%9b%b4-3)

- `2.23`—— 2.31（不包含 2.31）
- 能在泄露或已知地址位置，写任意值；或能修改已知地址的堆管理结构中，堆地址的最低位 byte

### 利用原理[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e5%8e%9f%e7%90%86-3)

控制 `smallbin` 的 `bk` 指针，示例如下：
- 申请 `chunk A、chunk B、chunk C`，其中 `chunk B` 大小位于 `smallbin`
- 释放 `B`，申请更大的 `chunk D`，使得 `B` 进入 `smallbin`
- 写 `A`，溢出修改 `B` 的 `bk`，指向地址 `X`，这里有 `fake chunk`
- 布置 `X->fd == &B`
- 分配两次后即可取出位于 `X` 地址处的 `fake chunk`
![IMG-20260507214050064](/assets/ctf/69166007b02b3c7ea141.webp)



### 相关技巧[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e7%9b%b8%e5%85%b3%e6%8a%80%e5%b7%a7-3)

在引入了 `tcache stash unlink` 的时候，需要注意绕过：

```c
#if USE_TCACHE
	  /* While we're here, if we see other chunks of the same size,
	     stash them in the tcache.  */
	  size_t tc_idx = csize2tidx (nb);
	  if (tcache && tc_idx < mp_.tcache_bins)
	    {
	      mchunkptr tc_victim;

	      /* While bin not empty and tcache not full, copy chunks over.  */
	      while (tcache->counts[tc_idx] < mp_.tcache_count
		     && (tc_victim = last (bin)) != bin)
		{
		  if (tc_victim != 0)
		    {
		      bck = tc_victim->bk;
		      set_inuse_bit_at_offset (tc_victim, nb);
		      if (av != &main_arena)
			set_non_main_arena (tc_victim);
		      bin->bk = bck;
		      bck->fd = bin;

		      tcache_put (tc_victim, tc_idx);
	            }
		}
	    }
#endif
```

要么使其满足 `tc_victim = last (bin)) == bin`（伪造`bk`方向链表，构造条件比较苛刻）、要么使其满足：`tcache->counts[tc_idx] ≥ mp_.tcache_count`。否则可能会因为非法内存访问使得程序 `down` 掉。

实际上，这个技巧用得不是很多，因为在同等条件下，更偏向于利用 `fastbin/tcachebin`。

### 利用效果[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e6%95%88%e6%9e%9c-3)

- 任意地址分配
- 任意地址读写

## 2.5-House of Orange[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#25-house-of-orange)

### 漏洞成因[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e6%bc%8f%e6%b4%9e%e6%88%90%e5%9b%a0-4)

堆溢出写

### 适用范围[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e9%80%82%e7%94%a8%e8%8c%83%e5%9b%b4-4)

- `2.23`——`2.26`
- 没有 `free`
- 可以 `unsortedbin attack`

### 利用原理[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e5%8e%9f%e7%90%86-4)

**stage1：`unsortedbin at`**

- 修改 `top_chunk` 的 `size` 为 `0xXYZ`（需要满足页对齐的检测条件）
- 申请一个大于 `0xXYZ` 大小的 `chunk`，此时 `top_chunk` 会进行 `grow`，并将原来的 `old top_chunk` 释放进入 `unsortedbin`

**stage2：伪造`IO_file`：**

- 修改处于 `unsortedbin` 中的 `old top_chunk`，修改其 `size` 为 `0x61`，其 `bk` 为 `&_IO_list_all-0x10`
- 伪造 `IO_FILE` 结构一（2.24之前）：`_IO_OVERFLOW(fp,EOF)`
	- **`fp->O_write_ptr(IO_file+0x28) > fp->_IO_write_base(IO_file+0x20)`**
	- **`fp->mode(IO_file+0xc0) <= 0`**
	- **`fp->flags(IO_file+0x0)`** 设置为 rdi 指向地址的内容（一参地址内容）
	- **`fp->vtable(IO_file+0xd8)`**，设置为我们能控制内存块的地址
	
	- **`vtable->IO_OVERFLOW(vtable+0x18)`** 设置为目标代码段地址
- 伪造 `IO_FILE` 结构二（2..24及其之后）：`(((_IO_strfile *) fp)->_s._free_buffer) (fp->_IO_buf_base);`
	- **`fp->flags(IO_file+0x0)=0`**
	- **`fp->O_write_ptr(IO_file+0x28) > fp->_IO_write_base(IO_file+0x20)
	- **`fp-> _IO_buf_base(IO_file+0x38)`**，设置为rdi（一参）
	- **`fp->vtable(IO_file+0xd8) = &_IO_str_jumps-0x8`**
	
	- **`((_IO_strfile *) fp)->_s._free_buffer(IO_file+0xe8)`**,设置为目标代码段地址

![IMG-20260510182555110](/assets/ctf/6305dd1805cc2bc07aa6.webp)

例子：
```python
fake_IO_file = flat({
    0: '/bin/sh\x00', 
    0x8: p64(0x61),
    0x10: p64(libc_base+0x3c4b78)+p64(io_list_all-0x10),
    0x20: p64(0),
    0x28: p64(1),
    0xd8: p64(vtable_addr), #vtable -> 伪造的table的地址
    0x200+0x20: p64(sys_addr)
    }, filler=b'\x00')
```

**stage3：触发**

- 申请非 `0x60` 大小的 `chunk` 的时候，首先触发 `unsortedbin attack`，将`_IO_list_all` 修改为 `main_arena+88`，然后 `unsortedbin chunk` 会进入到 `smallbin`，大小为 `0x60`；接着遍历 `unsortedbin` 的时候触发了 `malloc_printerr`，然后调用链为： `malloc_printerr -> libc_message -> abort -> _IO_flush_all_lockp`，调用到伪造的 `vtable` 里面的函数指针
### 相关技巧[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e7%9b%b8%e5%85%b3%e6%8a%80%e5%b7%a7-4)

- 在 `glibc-2.24` 后加入了 `vtable` 的 `check`，不能任意地址伪造 `vatble` 了，但是可以利用 `IO_str_jumps` 结构进行利用。
- 在 `glibc-2.26` 后，`malloc_printerr` 不再刷新 `IO` 流了，所以该方法失效
- 由于`IO_file 0`的`_mode` 的正负性是随机的，影响判断条件，大概有 `1/2` 的概率会利用失败，多试几次就好

### 利用效果[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e6%95%88%e6%9e%9c-4)

- 任意函数执行
- 任意命令执行

## 2.6-House of Rabbit[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#26-house-of-rabbit)

### 漏洞成因[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e6%bc%8f%e6%b4%9e%e6%88%90%e5%9b%a0-5)

堆溢出写、`use after free`、`edit after free`

### 适用范围[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e9%80%82%e7%94%a8%e8%8c%83%e5%9b%b4-5)

- `2.23`——`2.26`
- 超过 `0x400` 大小的堆分配
- 可以写 `fastbin` 的 `fd` 或者 `size` 域

### 利用原理[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e5%8e%9f%e7%90%86-5)

该利用技巧的核心是 `malloc_consolidate` 函数，当检测到有 `fastbin` 的时候，会取出每一个 `fastbin chunk`，将其放置到 `unsortedbin` 中，并进行合并。以修改 `fd` 为例，利用过程如下：

- 申请 `chunk A`、`chunk B`，其中 `chunk A` 的大小位于 `fastbin` 范围
- 释放 `chunk A`，使其进入到 `fastbin`
- 利用 `use after free`，修改 `A->fd` 指向地址 `X`，需要伪造好 `fake chunk`，使其不执行 `unlink` 或者绕过 `unlink`
- 分配足够大的 `chunk`，或者释放 `0x10000` 以上的 `chunk`，只要能触发 `malloc_consolidate` 即可
- 此时 `fake chunk` 被放到了 `unsortedbin`，或者进入到对应的 `smallbin/largebin`
- 取出 `fake chunk` 进行读写即可

### 相关技巧[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e7%9b%b8%e5%85%b3%e6%8a%80%e5%b7%a7-5)

- `2.26` 加入了 `unlink` 对 `presize` 的检查
- `2.27` 加入了 `fastbin` 的检查

抓住重点：`house of rabbit` 是对 `malloc_consolidate` 的利用。因此，不一定要按照原作者的思路来，他的思路需要满足的条件太多了。

### 利用效果[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e6%95%88%e6%9e%9c-5)

- 任意地址分配
- 任意地址读写

## 2.7-House of Roman[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#27-house-of-roman)

### 漏洞成因[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e6%bc%8f%e6%b4%9e%e6%88%90%e5%9b%a0-6)

`use after free`、堆溢出

### 适用范围[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e9%80%82%e7%94%a8%e8%8c%83%e5%9b%b4-6)

- `2.23`——`2.29`
- 可以 `use after edit`
- 不需要泄露地址
- 需要爆破 `12 bit`，成功的概率 `1/4096`

### 利用原理[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e5%8e%9f%e7%90%86-6)

可以说这个技巧是 `fastbin attack + unsortedbin attack` 的组合技，利用思路如下：

- 申请 `chunk A`、`chunk B`、`chunk C` 和 `chunk D`，`chunk B` 的大小为 `0x70`
- 释放 `chunk B`，使其进入到 `fastbin[0x70]`
- 溢出写 `A`，修改 `chunk B` 的 `size`，使其大小在 `unsortedbin` 范围
- 再次释放 `B`，`B` 进入 `unsortedbin` 中
- 部分写 `B` 的 `fd`，使得 `fd` 指向 `malloc_hook-0x23`
- 利用 `A` 的溢出写修正 `B` 的 `size`，连续分配两次 `0x70`，即可分配到 `malloc_hook` 上方
- 触发 `unsortedbin attack`，将`__malloc_hook` 写为 `main_arena+88`
- 部分写`__malloc_hook` 的低三个字节，修改为 `one_gadget`
- 再次 `malloc` 即可拿到 `shell`

### 相关技巧[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e7%9b%b8%e5%85%b3%e6%8a%80%e5%b7%a7-6)

- 使用 `house of roman` 的时候，需要采用多线程爆破
- 可以使用其他方法代替，比如先攻击 `stdout`泄露地址，使得爆破的成本降低

### 利用效果[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e6%95%88%e6%9e%9c-6)

- 执行 `one_gadget`
- 绕过 `ASLR`

## 2.8-House of Storm[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#28-house-of-storm)

### 漏洞成因[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e6%bc%8f%e6%b4%9e%e6%88%90%e5%9b%a0-7)

堆溢出、`use after free`、`edit after free`

### 适用范围[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e9%80%82%e7%94%a8%e8%8c%83%e5%9b%b4-7)

- `2.23`——`2.29`
- 可以进行 `unsortedbin attack`
- 可以进行 `largebin attack`，修改 `bk` 和 `bk_nextsize`
- 可以分配 `0x50` 大小的 `chunk`

### 利用原理[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e5%8e%9f%e7%90%86-7)

`house of storm` 也是一款组合技，利用开启了 `PIE` 的 `x64` 程序的堆地址总是 `0x55xxxx...` 或者 `0x56xxxx...` 开头这一特性，使用一次 `largebin attack` 写两个堆地址，使用一次 `unsortedbin attack` 写一次 `libc` 地址，可以实现任意地址分配。虽然 `house of storm` 最后能达到任意地址分配，但是由于其所需的条件比较多，一般可以用其他更简便的堆利用技术代替。利用思路如下：
- 需要填满`tc[0x50]`
- `addr = target-0x10`，以下`addr`指目标`chunk_head`位置
- 进行一次 `unsortedbin attack`（size大一些），其 `bk` 修改为 `addr`
- 进行一次 `largebin attack`（size小一些），其 `bk` 修改为 `addr+0x8`，`bk_nextsize` 修改为 `addr-0x20+3`
- 申请 `0x50` 大小的 `chunk` 即可申请到 `addr` 处

如下构造后，申请大 chunk ，将 unsorted chunk 放入 large bin 就能触发 storm，将目标地址放入 fastbin：
![IMG-20260510201359975](/assets/ctf/b972c64d1fc01fb0d101.webp)


### 相关技巧[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e7%9b%b8%e5%85%b3%e6%8a%80%e5%b7%a7-7)

需要注意的有：

- 该方法成功的几率是 `50%`，因为 `0x55` 会触发 `assert` 断言，`0x56` 才能成功
- 部分架构堆地址开头范围更大，爆破概率更低
- 申请 `addr` 处的 `chunk` 的时候需要从 `unsortedbin` 里面取

### 利用效果[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e6%95%88%e6%9e%9c-7)

- 任意地址分配

## 2.9-House of Corrosion[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#29-house-of-corrosion)

### 漏洞成因[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e6%bc%8f%e6%b4%9e%e6%88%90%e5%9b%a0-8)

堆溢出、`use after free`

### 适用范围[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e9%80%82%e7%94%a8%e8%8c%83%e5%9b%b4-8)

- `2.23`—— 至今
- 任意大小分配
- 可以修改 `global_max_fast`
- 不需要泄露libc地址

### 利用原理[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e5%8e%9f%e7%90%86-8)

一个非常 `tricky` 的方法，可以绕过 `aslr`，不需要泄露地址都能达成 `rce`，可以很很多方法结合起来应用。先说利用原理：

- 使用 `unsortedbin attack/largebin attack` 等方法，成功修改 `global_max_fast` 的值为很大的值。如果使用 `unsortedbin attack`，不需要泄露地址，爆破 `1/16` 即可
	- largebin at ：`bk_nextsize = target - 0x20`，`target = heap_head`
	- unsortedbin at：`bk = target - 0x10`，`target = &(arena + 88)`

- 申请任意大小的 `chunk`，这些 `chunk` 都会被视为 `fastbin chunk`，然后利用这些 `chunk` 进行`fastbin_Y[]`的数组越界来进行读和写
	此时的计算公式为：
	`fastbin_Y_chunk = &main_arena.fastbinsY + (fake_size - 0x20) / 2`
	
	重组一下：
	`fake_size = (fastbin_Y_chunk - &main_arena.fastbinsY) x 2 + 0x20`

**注：处理 fd 指针的过程都有指针保护逻辑**
malloc 逻辑：
![IMG-20260511195404260](/assets/ctf/0dc2a130459638d1130d.webp)

free 逻辑：
![IMG-20260511194948825](/assets/ctf/08d99462a0a796cdadff.webp)
![IMG-20260511194955054](/assets/ctf/43dea67cbf9d93d4b668.webp)

*根据以上逻辑拼出如下利用方式*
**任意地址读一`long`任意值：**`chunk_0->fd = fastbin_Y_chunk`,`chunk_0->fd = target`

- 假设对应的地址 `X` 上存储着 `Y`，现在的目的是泄露出 `Y
`
- 根据偏移计算出来 `chunk size`，修改 `chunk A` 的 `size` 为计算出来的值，释放 `chunk A` 到地址 `X` 处
- 此时，`A->fd` 就被写入了 `Y`(被指针保护的)
- 通过打印即可泄露出 `Y` 的信息
```cpp
chunk_0->size = fake_size = (target - &main_arena.fastbinsY) x 2 + 0x20
free(chunk_0)
malloc(fake_size)

print(protect_ptr(&chunk_0, chunk_0->fd))
```
![IMG-20260511194948825](/assets/ctf/08d99462a0a796cdadff.webp)

**任意地址写一`long`任意值：**`fastbin_Y_chunk = chunk_0->fd`，`target = chunk_0; target = C`

- 假设对应的地址 `X` 上存储着 `Y`，现在的目的是修改地址 `X` 存储的 `Y` 为其他值

- 根据偏移计算出来 `fake size`，修改 `chunk A` 的 `size` 为计算出来的值，free `chunk A` 到地址 `X` 处
- 此时，`A->fd` 就被写入了 `Y`(被指针保护的)
- 修改 `A->fd` 为目标值
- 分配一次 `chunk A` 就可以把地址 `X` 存储的值为任意值
```cpp
chunk_0->size = fake_size = (target - &main_arena.fastbinsY) x 2 + 0x20
free(chunk_0)

chunk_0->fd = protect_ptr(&chunk_0, C)
malloc(fake_size)
```
![IMG-20260511210120895](/assets/ctf/0dc2a130459638d1130d.webp)

**向任意地址写一内存中的值：**

- 假设地址 `X` 上存储着 `Y`、地址 `M` 上存储着 `N`，现在的目的是把 `N` 写到地址 `X` 处

- 根据偏移计算 `chunk size 0`，先释放 `chunk A` 到地址 `X` 处，此时有地址 `X` 处存储 `chunk A` 地址，`chunk A->fd` 为 `Y`(被指针保护的)
- 根据偏移计算 `chunk size 1`，再次释放 `chunk A` 到地址 `M` 处，此时有地址 `M` 处存储 `chunk A` 地址，`chunk A->fd` 为 `N`(被指针保护的)
- 修正 `chunk A` 的大小为 `chunk size 0`，分配 `1` 次 `chunk` 即可使得 `N` 转移到地址 `X` 处，当然在转移的过程中可以适当的修改 `N`(被指针保护的)
```cpp
chunk_0->size = fake_size_0 = (target - &main_arena.fastbinsY) x 2 + 0x20
free(chunk_0)

chunk_0->size = fake_size_1 = (C_addr - &main_arena.fastbinsY) x 2 + 0x20
free(chunk_1)

chunk_0->size = fake_size_0 = (target - &main_arena.fastbinsY) x 2 + 0x20
malloc(fake_size_0)
```

显然，借助写原语 `2`，即可在不需要泄露地址的前提下将`__malloc_hook` 等写为 `one_gadget`，爆破的概率是 `1/4096`。

### 相关技巧[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e7%9b%b8%e5%85%b3%e6%8a%80%e5%b7%a7-8)

- 虽然至今都能使用 `house of corrosion`，但是在 `glibc-2.37` 版本中，`global_max_fast` 的数据类型被修改为了 `int8_u`，进而导致可控的空间范围大幅度缩小。
- `house of corrosion` 也可以拓展到 `tcachebin` 上
- 适当控制 `global_max_fast` 的大小，把握控制的空间范围
- 可以和 `IO_FILE` 结合起来泄露信息
- 可以通过劫持执行流到`dl_resolve + off`,在ld中找`int 0x80`或`syscall`进行srop
### 利用效果[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e6%95%88%e6%9e%9c-8)

- 任意地址读写
- 结合stdout的libc泄露（2.31及其之前）
- 无libc下，多线程爆破libc偏移

## 2.10-House of Husk
### 漏洞成因[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e6%bc%8f%e6%b4%9e%e6%88%90%e5%9b%a0-9)

堆溢出

### 适用范围
- `2.23`—— 至今
- 可以修改`__printf_arginfo_table` 和`__printf_function_table`
- 可触发格式化字符串解析

### 利用原理

严格来说，这个漏洞是与堆的关系并不是很大，主要是根据 `printf` 的机制进行利用。但是，该技术可以和很多堆利用手法结合起来。

调用处 `1`：

```c
//
  /* Use the slow path in case any printf handler is registered.  */
  if (__glibc_unlikely (__printf_function_table != NULL
			|| __printf_modifier_table != NULL
			|| __printf_va_arg_table != NULL))
    goto do_positional;

// vfprintf-internal.c#1763
nargs += __parse_one_specmb (f, nargs, &specs[nspecs], &max_ref_arg);

// printf-parsemb.c (__parse_one_specmb函数)
/* Get the format specification.  */
spec->info.spec = (wchar_t) *format++;
spec->size = -1;
if (__builtin_expect (__printf_function_table == NULL, 1) // 判断是否为空
  || spec->info.spec > UCHAR_MAX
  || __printf_arginfo_table[spec->info.spec] == NULL // 判断是否为空
  /* We don't try to get the types for all arguments if the format
 uses more than one.  The normal case is covered though.  If
 the call returns -1 we continue with the normal specifiers.  */
  || (int) (spec->ndata_args = (*__printf_arginfo_table[spec->info.spec]) // 调用__printf_arginfo_table中的函数指针
               (&spec->info, 1, &spec->data_arg_type,
                &spec->size)) < 0)
{
    // ......
}
```

利用方式为：`(*__printf_arginfo_table[spec->info.spec])(&spec->info, 1, &spec->data_arg_type, &spec->size) 
*`spec`结构体在`printf()`执行时会全部初始化，该处调用不能控制参数*

- `__printf_function_table` 和`__printf_arginfo_table` 分别写为非零和可控地址`B_addr` 
- 设占位符为 `α`，此时 `chunk B` 的内容应该为 `p64(0) x ord(α) + p64(target)`

```c
// vfprintf-internal.c#1962
if (spec <= UCHAR_MAX
          && __printf_function_table != NULL
          && __printf_function_table[(size_t) spec] != NULL)
{
	// ......
 
      /* Call the function.  */
      function_done = __printf_function_table[(size_t) spec](s, &specs[nspecs_done].info, ptr); // 调用__printf_function_table中的函数指针
 
    if (function_done != -2)
    {
      /* If an error occurred we don't have information
         about # of chars.  */
      if (function_done < 0)
        {
          /* Function has set errno.  */
          done = -1;
          goto all_done;
        }
 
      done_add (function_done);
      break;
    }
}
```

利用方式为：`__printf_function_table[(size_t) spec](s, &info, ptr);`(2.36以下)
`Xprintf(function_invoke)(buf, table[spec], args_value, ndata_args, info)` 再调用` callback(FILE_wrapper, info, args)`

- `__printf_function_table` 和`__printf_arginfo_table` 分别写为可控地址`A_addr`和`B_addr`
- 设占位符为 `α`，此时 `A_addr` 中的内容应该为 `p64(0) x ord(α) + p64(target_1)`；`B_addr` 中的内容应该为 `p64(0) x ord(α) + p64(target_2)`
- 能够连续执行两个目标代码段

**`__printf_arginfo_table[spec]` 被调用时**

| 对象                     | 是否已初始化 | 说明                                     |
| ---------------------- | ------ | -------------------------------------- |
| `info` 指针              | 是      | 指向当前 `spec->info`                      |
| `info->spec`           | 是      | 已经是最终格式符字符                             |
| `info->width` / `prec` | 是      | 已根据格式字符串解析；动态宽度/精度还涉及额外参数              |
| `info` 的 flags         | 是      | `alt`、`left`、`showsign` 等已经被解析或清零      |
| `n`                    | 是      | 通常第一次为 `1`                             |
| `argtypes` 指针          | 是      | 但其指向内容是输出槽，需要 callback 写               |
| `size` 指针              | 是      | `spec->size` 常先设为 `-1`，需要 callback 按需写 |

**`__printf_function_table[spec]` 被调用时**

| 对象          | 是否已初始化 | 说明                                     |
| ----------- | ------ | -------------------------------------- |
| `stream`    | 是      | <=2.36 为原始流；>=2.37 为 buffer-backed 包装流 |
| `info`      | 是      | 来自已解析的 `specs[i].info`                 |
| `args` 指针数组 | 是      | glibc 已根据 `arginfo` 的类型信息提取并组织参数       |
| `args[i]`   | 不确定    | arginfo 正确声明了参数数量和类型时初始化               |

### 相关技巧

- 该技巧一般和 `largebin attack` 结合起来
- 在低于 `2.36` 版本中，`__malloc_assert` 中有格式化字符串的解析
- 还有一个`__printf_va_arg_table` 也是可以利用的，但是条件比较苛刻

### 利用效果[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e6%95%88%e6%9e%9c-9)

- 执行 `one_gadget`
- 执行 `rop` 控制程序执行流
- 两次调用一参都为栈地址，可以通过将调用处改为 puts 函数泄露栈地址
## 2.11-House of Atum[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#211-house-of-atum)

### 漏洞成因[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e6%bc%8f%e6%b4%9e%e6%88%90%e5%9b%a0-10)

`use after free`

### 适用范围[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e9%80%82%e7%94%a8%e8%8c%83%e5%9b%b4-10)

- `2.26`——`2.30`
- 可以修改 `tcachebin` 的 `next` 和 `key`

### 利用原理[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e5%8e%9f%e7%90%86-10)

这是一个关于 `tcachebin` 的技巧，用于修改 `chunk presize/size`，利用过程如下：

- 申请 `chunk A`，大小在 `fastbin` 范围内
- 释放 `A`，连续释放 `8` 次，此时，`A` 的 `fd` 被清 `0`，`A` 也被放置到了 `fastbin` 里面
- 申请一个 `chunk`，将其 `fd` 修改为 `A - 0x10`，此时 `tcache` 中的 `counts` 为 `6`
- 再申请一个 `chunk`，从 `fastbin` 里面取，但是会把 `fastbin` 里面剩余的一个 `chunk` 链入到 `tcache bin`
- 再次分配就会分配到地址 `A-0x10` 处，就可以修改原来 `A` 的 `presize/size` 等

### 相关技巧

- `2.30` 之后逻辑变了，原来是判断 `entry[idx]!=NULL`，`2.31` 之后判断 `count[idx] > 0`
```c  
// glibc ≥ 2.30
void *
__libc_malloc (size_t bytes)
{
  //......
  MAYBE_INIT_TCACHE ();

  DIAG_PUSH_NEEDS_COMMENT;
  if (tc_idx < mp_.tcache_bins
      && tcache
      && tcache->counts[tc_idx] > 0)
    {
      return tcache_get (tc_idx);
    }
}

// glibc < 2.30
void *
__libc_malloc (size_t bytes)
{
  //......
  MAYBE_INIT_TCACHE ();

  DIAG_PUSH_NEEDS_COMMENT;
  if (tc_idx < mp_.tcache_bins
      && tcache
      && tcache->entries[tc_idx] != NULL)
    {
      return tcache_get (tc_idx);
    }
}
```

- 有时候需要绕过 `tcache->key` 的检测

### 利用效果

- 修改 `chunk size` 以及 `chunk presize`

## 2.12-House of Kauri

### 漏洞成因

堆溢出

### 适用范围
- `2.26`——`2.32`

### 利用原理

利用原理很简单，修改 `tcachebin` 的 `size`，然后使其被放到不同大小的 `tcachebin` 链表里面去。我感觉这个技巧是很基础的 `tcachebin` 技巧，甚至不应该被称之为 `house of`。

### 相关技巧

- 无

### 利用效果

- 多个 `tcachebin` 链表中存放同一个 `chunk`

## 2.13-House of Fun[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#213-house-of-fun)

### 漏洞成因[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e6%bc%8f%e6%b4%9e%e6%88%90%e5%9b%a0-12)

堆溢出、`use after free`

### 适用范围[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e9%80%82%e7%94%a8%e8%8c%83%e5%9b%b4-12)

- `2.23`——`2.30`
- 可以申请 `largebin` 范围的 `chunk`

### 利用原理[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e5%8e%9f%e7%90%86-12)

或许这个技巧应该叫做 `largebin attack`。

在这个 [sourceware.org Git - glibc.git/blobdiff - malloc/malloc.c](https://sourceware.org/git/?p=glibc.git;a=blobdiff;f=malloc/malloc.c;h=801ba1f499b566e677b763fc84f8ba86f4f7ccd0;hp=6e766d11bc85b6480fa5c9f2a76559f8acf9deb5;hb=5b06f538c5aee0389ed034f60d90a8884d6d54de;hpb=a0a0dc83173ce11ff45105fd32e5d14356cdfb9c)`commit` 被检测了：

![image-20230306115614058](https://image.roderickchan.cn/img/image-20230306115614058.png)

### 相关技巧[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e7%9b%b8%e5%85%b3%e6%8a%80%e5%b7%a7-12)

- 无

### 利用效果[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e6%95%88%e6%9e%9c-12)

- 任意地址写堆地址

## 2.14-House of Mind fastbin

### 漏洞成因

堆溢出

### 适用范围

- `2.23`—— 至今
- 可以分配任意大小的 `chunk`

### 利用原理

主要利用的是：

```c
#define heap_for_ptr(ptr) \
  ((heap_info *) ((unsigned long) (ptr) & ~(HEAP_MAX_SIZE - 1)))
  
#define arena_for_chunk(ptr) \
  (chunk_non_main_arena (ptr) ? heap_for_ptr (ptr)->ar_ptr : &main_arena)

  struct _heap_info {
    mstate ar_ptr;
    struct _heap_info *prev;
    size_t size;
    size_t mprotect_size;
    char pad[...];
} heap_info;

int HEAP_MAX_SIZE = 0x4000000;
int MAX_SIZE = (128*1024) - 0x100;     //设置单次大块分配大小，略低于 mmap threshold，目的是让分配仍然来自 heap，而不是 mmap。

// 本次攻击的目标位置，以及要使用的 fake arena
uint8_t* fake_arena = malloc(0x1000);  
uint8_t* target_loc = fake_arena + 0x30;
uint8_t* target_chunk = (uint8_t*) fake_arena - 0x10;

//fake arena->system_mem
//这个值需要大于当前 fastbin chunk 的大小
fake_arena[0x888] = 0xFF;
fake_arena[0x889] = 0xFF;
fake_arena[0x88a] = 0xFF;

uint64_t* fake_heap_info = (((uint64_t) target_chunk) + HEAP_MAX_SIZE) & ~(HEAP_MAX_SIZE - 1);
uint64_t* fastbin_chunk = malloc(0x50); // 实际 chunk size 为 0x60  
uint64_t* chunk_ptr = fastbin_chunk - 2; // 指向 chunk 头部，而不是用户内存

/*  
fake arena 必须位于 heap 上的某个特定偏移处。  
因此，我们分配大量 chunk，直到下一个 chunk 会落入 arena。  
这个值已经在上面计算出来。  
*/  
uint64_t* user_mem = malloc(MAX_SIZE);  
while((long long)user_mem < new_arena_value){  
user_mem = malloc(MAX_SIZE);  
}  
  

//创建一个 fastbin 大小的 chunk，作为攻击目标
uint64_t* fastbin_chunk = malloc(0x50); // 实际 chunk size 为 0x60  
uint64_t* chunk_ptr = fastbin_chunk - 2; // 指向 chunk 头部，而不是用户内存  
  
// 填满 tcache，以便后面使用 fastbin。  
uint64_t* tcache_chunks[7];  
for(int i = 0; i < 7; i++){  
tcache_chunks[i] = malloc(0x50);  
}  
for(int i = 0; i < 7; i++){  
free(tcache_chunks[i]);  
}  
  
/*  
heap_info->ar_ptr =  fake_arena
“ar_ptr”是“heap_info” 结构体偏移 0x0 处的第一个成员。  
  
实际被写入的位置取决于被释放 fastbinY[] 数组对应偏移的位置。
可以通过修改 global_max_fast 变量扩大写入范围，高版本该变量为 uint8_t 可写入范围变小
*/  
fake_heap_info[0] = (uint64_t) fake_arena; // 设置 fake ar_ptr，也就是 arena  
  
/*  
在 size 字段上设置 non-main arena bit。    
///// 漏洞点！覆盖 chunk size  
*/  
chunk_ptr[1] = 0x60 | 0x4; // 设置 non-main arena bit  
  
//// 漏洞结束  
  
/*  
fastbin chunk 地址被写入到哪个偏移，取决于所使用的 fastbin  
以及 malloc_state 本身。不同版本有差异
*/  
  
free(fastbin_chunk); // 触发
  
// 对于这个特定大小的 fastbin chunk，偏移是 0x28。  
assert(*((unsigned long *) (target_loc)) == (unsigned long)fastbin_chunk;  
}

```

如果是 `non-main-arean` 的 `chunk`，会根据其地址找到 `heapinfo`，然后找到 `malloc_state` 结构体。

因此，利用技巧是：

- 根据要释放的 `fastbin chunk A` 的堆地址，找到对应的 `heap_for_ptr` 地址
- 在 `heapinfo` 地址处伪造好相关变量，重点是 `mstate` 指针
- 修改 `chunk A` 的 `non-main` 标志位，释放到伪造的 `arena` 里面，控制好偏移即可

### 相关技巧

- 一般来说，可以分配任意大小的 `chunk`，还能堆溢出，很多技巧都能用
- 这个技巧是希望大家关注对于 `arena` 的攻击
- 甚至可以直接修改 `thread_arena` 这个变量

### 利用效果[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e6%95%88%e6%9e%9c-13)

- 任意地址写堆地址

## 2.15-House of Muney[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#215-house-of-muney)

### 漏洞成因

堆溢出

### 适用范围[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e9%80%82%e7%94%a8%e8%8c%83%e5%9b%b4-14)

- `2.23`—— 至今
- 能分配 `mmap` 的 `chunk`
- 能修改 `mmap` 的 `chunk` 的大小

### 利用原理

这个技巧被称之为 `steal heap from glibc`。主要的点有以下几个：

- `libc.so.6` 映射的地址空间，前面都是与符号表、哈希表、字符串表等重定位或者解析函数地址有关，前面一段的权限是 `r--`
- `mmap(NULL, ...)` 是会分配到 `libc.so.6` 的上方的

基于这两个知识点，利用过程如下：

- 申请 `chunk A`，假设为 `0x40000` 大小，则会走 `mmap` 申请，并且申请到 `libc.so.6` 的上方
- 修改 `chunk A` 的大小为 `0x45000`，设置 `MMAP` 标志位
- 释放 `chunk A`，则会把 `libc.so.6` 的 `0x5000` 的内存也释放掉
- 再次申请 `0x45000`，就可以控制 `libc.so.6` 原来的符号表、哈希表等等
- 触发一次 `dl_runtime_resolve` 等就能控制程序执行任意代码

### 相关技巧[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e7%9b%b8%e5%85%b3%e6%8a%80%e5%b7%a7-14)

- 需要伪造的符号表、哈希表等需要逐步调试
- 可以扩展为 `steal heap from everywhere`

### 利用效果[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e6%95%88%e6%9e%9c-14)

- 任意代码执行

## 2.16-House of Botcake[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#216-house-of-botcake)

### 漏洞成因[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e6%bc%8f%e6%b4%9e%e6%88%90%e5%9b%a0-15)

`double free`

### 适用范围[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e9%80%82%e7%94%a8%e8%8c%83%e5%9b%b4-15)

- `2.26`—— 至今
- 多次释放 `chunk` 的能力

### 利用原理[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e5%8e%9f%e7%90%86-15)

该技巧可以用于绕过 `tcache->key` 的检查，利用过程如下：

- 申请 `7` 个大小相同，大小大于 `0x80` 的 `chunk`，再申请三个，分别为 `chunk A` 和 `chunkB` 和 `chunk C`
- 释放前 `7` 个和 `chunk A`，前面 `7` 个都会进入到 `tcachebin` 里面，`chunk A` 进入到 `unsortedbin`
- 释放 `chunk B`，则 `chunk B` 会和 `chunk A` 合并
- 从 `tcachebin` 分配走一个
- 再次释放 `chunk B`，此时 `B` 同时存在与 `unsortedbin` 和 `tcachebin`

### 相关技巧[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e7%9b%b8%e5%85%b3%e6%8a%80%e5%b7%a7-15)

- 在高版本需要绕过指针保护的检查

### 利用效果[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e6%95%88%e6%9e%9c-15)

- 构造出堆重叠，为后续利用做准备

## 2.17-House of Rust[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#217-house-of-rust)

### 漏洞成因[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e6%bc%8f%e6%b4%9e%e6%88%90%e5%9b%a0-16)

堆溢出

### 适用范围[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e9%80%82%e7%94%a8%e8%8c%83%e5%9b%b4-16)

- `2.26`—— 至今
- 可以进行 `tcache stash unlinking` 攻击
- 可以进行 `largebin attack`
- 不需要泄露地址

### 利用原理[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e5%8e%9f%e7%90%86-16)

原作者的博客写得很复杂，我这里提炼出关键信息。该技巧就是 `tcachebin stash unlinking`+`largebin attack` 的组合技巧。

首先需要知道 `tcachebin stash unlinking`，下面称之为 `TSU` 技巧：

- `tcachebin[A]` 为空
- `smallbin[A]` 有 `8` 个
- 修改第 `8` 个 `smallbin chunk` 的 `bk` 为 `addr`
- 分配 `malloc(A)` 的时候，`addr+0x10` 会被写一个 `libc` 地址

还要知道 `tcachebin stash unlinking+`，下面称之为 `TSU+` 技巧：

- `tcachebin[A]` 为空
- `smallbin[A]` 有 `8` 个
- 修改第 `7` 个 `smallbin chunk` 的 `bk` 为 `addr`，还要保证 `addr+0x18` 是一个合法可写的地址
- 分配 `malloc(A)` 的时候，`addr` 会被链入到 `tcachebin`，也就是可以分配到 `addr` 处

以 `0x90` 大小的 `chunk` 为例，此时的 `tcache_key` 还是指向 `tcache_perthread_struct + 0x10` 的：

- 第一步，把 `tcachebin[0x90]` 填满，把 `smallbin[0x90]` 也填满
- 第二步，把最后一个 `smallbin 0x90` 的 `chunk` 的 `size` 改成 `0xb0`，将其释放到 `tcachebin[0xb0]`，这一步主要是为了改变其 `bk` 指向 `tcache_perthread_struct + 0x10`，可以部分修改低位的字节，以便下一步分配到目标区域
- 第三步，使用 `largebin attack` 往上一步的 `bk->bk` 写一个合法地址，然后耗尽 `tcachebin[0x90]`，再分配的时候就会触发 `TSU+`，之后就能分配到 `tcache_perthread_struct` 结构体
- 第四步，还是堆风水，但是用 `TSU` 技术，在 `tcache_perthread_struct` 上写一个 `libc` 地址（比前面一步要简单很多）
- 第五步，通过控制 `tcache_perthread_struct` 结构体，部分写上面的 `libc` 地址，分配到 `stdout` 结构体，泄露信息
- 第六步，通过控制 `tcache_perthread_struct` 结构体分配到任意地址

上面的过程最好的情况下需要爆破 `1/16`，最差 `1/256`。

但是，`2.34` 之后，`tcache_key` 是一个随机数，不是 `tcache_perthread_struct + 0x10` 了。

所以，此时可以加上 `largebin attack`，把以上的第二步变为：继续用 `largebin attack` 向其 `bk` 写一个堆地址，然后还要部分写 `bk` 使其落在 `tcache_perthread_struct` 区域。其他步骤一样。

或者，在 `smallbin` 里面放 `9` 个，这样第 `8` 个的 `bk` 肯定就是一个堆地址。此时就需要爆破 `1/16` 的堆，`1/16` 的 `glibc` 地址，成功的概率是 `1/256`。

### 相关技巧[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e7%9b%b8%e5%85%b3%e6%8a%80%e5%b7%a7-16)

- 总的来说，就是利用 `tcachebin stash unlinking` 打 `tcache_perthread_struct`
- 利用 `largebin attack` 构造合法地址

### 利用效果[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e6%95%88%e6%9e%9c-16)

- 任意地址分配
- 任意函数执行

## 2.18-House of Crust[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#218-house-of-crust)

### 漏洞成因[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e6%bc%8f%e6%b4%9e%e6%88%90%e5%9b%a0-17)

堆溢出

### 适用范围[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e9%80%82%e7%94%a8%e8%8c%83%e5%9b%b4-17)

- `2.26`——`2.37`
- 可以进行 `tcache stash unlinking` 攻击
- 可以进行 `largebin attack`
- 不需要泄露地址

### 利用原理[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e5%8e%9f%e7%90%86-17)

其他步骤和上面的 `house of rust` 一样，但是到第五步的时候，去修改 `global_max_fast`

后面的步骤和 `house of corrosion` 是一样的，通过写原语打 `stderr` 修改 `one_gadget` 拿到 `shell`。

### 相关技巧[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e7%9b%b8%e5%85%b3%e6%8a%80%e5%b7%a7-17)

- `house of crust = house of corrosion + house of rust`
- `2.37` 之后，`house of corrosion` 使用受限

## 2.19-House of Io[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#219-house-of-io)

### 漏洞成因[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e6%bc%8f%e6%b4%9e%e6%88%90%e5%9b%a0-18)

堆溢出

### 适用范围[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e9%80%82%e7%94%a8%e8%8c%83%e5%9b%b4-18)

- `2.26`—— 至今

### 利用原理[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e5%8e%9f%e7%90%86-18)

其实就是对 `tcache_perthread_struct` 结构体的攻击，想办法控制该结构体内容，通过再次`malloc()`进行任意地址分配。

### 相关技巧[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e7%9b%b8%e5%85%b3%e6%8a%80%e5%b7%a7-18)

- 围绕 `tcache_perthread_struct` 进行攻击

### 利用效果[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e6%95%88%e6%9e%9c-17)

- 任意地址分配

## 2.20-House of Banana[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#220-house-of-banana)

### 漏洞成因[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e6%bc%8f%e6%b4%9e%e6%88%90%e5%9b%a0-19)

堆溢出

### 适用范围[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e9%80%82%e7%94%a8%e8%8c%83%e5%9b%b4-19)

- `2.23`—— 至今
- 可以进行 `largebin attack`
- 能执行 `exit` 函数，或从`main`返回

### 利用原理
原作者专注于对`_dl_fini()`函数中对共享加载器的析构函数的攻击，这里总结所有`exit()`函数的攻击面：

**1：`exit() -> __run_exit_handlers()`**

2.23-

调用点一：覆盖并伪造`initial`指针，调用`hander`函数，可以控制一参或二参，并调用目标代码段，但需要泄露`tcbhead_t->pointer_guard`来伪造被保护的指针。

```cpp
//函数指针保护宏
#  define PTR_DEMANGLE(var)	asm ("ror $2*" LP_SIZE "+1, %0\n"	      \
				     "xor %%fs:%c2, %0"			      \
				     : "=r" (var)			      \
				     : "0" (var),			      \
				       "i" (offsetof (tcbhead_t,	      \
						      pointer_guard)))

void
exit (int status)
{
  __run_exit_handlers (status, &__exit_funcs, true, true);
}
libc_hidden_def (exit)

struct exit_function_list *__exit_funcs = &initial;

 while (cur->idx > 0)
	{
	  struct exit_function *const f = &cur->fns[--cur->idx];
	  const uint64_t new_exitfn_called = __new_exitfn_called;

	  switch (f->flavor)
	    {
	      void (*atfct) (void);
	      void (*onfct) (int status, void *arg);
	      void (*cxafct) (void *arg, int status);
	      void *arg;

	    case ef_free:
	    case ef_us:
	      break;
	    case ef_on:
	      onfct = f->func.on.fn;
	      arg = f->func.on.arg;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (onfct);
#endif
	      /* Unlock the list while we call a foreign function.  */
	      __libc_lock_unlock (__exit_funcs_lock);
	      onfct (status, arg);
	      __libc_lock_lock (__exit_funcs_lock);
	      break;
	    case ef_at:
	      atfct = f->func.at;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (atfct);
#endif
	      /* Unlock the list while we call a foreign function.  */
	      __libc_lock_unlock (__exit_funcs_lock);
	      atfct ();
	      __libc_lock_lock (__exit_funcs_lock);
	      break;
	    case ef_cxa:
	      /* To avoid dlclose/exit race calling cxafct twice (BZ 22180),
		 we must mark this function as ef_free.  */
	      f->flavor = ef_free;
	      cxafct = f->func.cxa.fn;
	      arg = f->func.cxa.arg;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (cxafct);
#endif
	      /* Unlock the list while we call a foreign function.  */
	      __libc_lock_unlock (__exit_funcs_lock);
	      cxafct (arg, status);
	      __libc_lock_lock (__exit_funcs_lock);
	      break;
	    }

	  if (__glibc_unlikely (new_exitfn_called != __new_exitfn_called))
	    /* The last exit function, or another thread, has registered
	       more exit functions.  Start the loop over.  */
            continue;
	}

      *listp = cur->next;
      if (*listp != NULL)
	/* Don't free the last element in the chain, this is the statically
	   allocate element.  */
	free (cur);
    }
```

调用点2`__elf_set___libc_atexit_element__IO_cleanup__`：

这里可以通过覆盖调用的函数指针，调用任意代码段。

2.36及其以下
```cpp
  if (run_list_atexit)
    RUN_HOOK (__libc_atexit, ());
  _exit (status);

  # define RUN_HOOK(NAME, ARGS)						      \
do {									      \
  void *const *ptr;						      \
  for (ptr = (void *const *) symbol_set_first_element (NAME);		      \
       ! symbol_set_end_p (NAME, ptr); ++ptr)				      \
    (*(__##NAME##_hook_function_t *) *ptr) ARGS;			      \
} while (0)
```
2.37及其以上改成如下调用，故失效：
```cpp
if (run_list_atexit)
    call_function_static_weak (_IO_cleanup);
```



**`_dl_fini`**

调用点一：加锁函数
2.23-2.33
可以通过劫持`rtld_global`，后伪造相应位置，控制一参对应地址内容，并劫持执行流。
```cpp
for (Lmid_t ns = GL(dl_nns) - 1; ns >= 0; --ns)
    {
      /* Protect against concurrent loads and unloads.  */
      __rtld_lock_lock_recursive (GL(dl_load_lock));

# define __rtld_lock_lock_recursive(NAME) \
  GL(dl_rtld_lock_recursive) (&(NAME).mutex)
```

调用点二：析构函数
```c
for (i = 0; i < nmaps; ++i)
{
    struct link_map *l = maps[i];

    if (l->l_init_called)
    {
        /* Make sure nothing happens if we are called twice.  */
        l->l_init_called = 0;

        /* Is there a destructor function?  */
        if (l->l_info[DT_FINI_ARRAY] != NULL
            || (ELF_INITFINI && l->l_info[DT_FINI] != NULL))
        {
            /* When debugging print a message first.  */
            if (__builtin_expect (GLRO(dl_debug_mask)
                                  & DL_DEBUG_IMPCALLS, 0))
                _dl_debug_printf ("\ncalling fini: %s [%lu]\n\n",
                                  DSO_FILENAME (l->l_name),
                                  ns);

            /* First see whether an array is given.  */
            if (l->l_info[DT_FINI_ARRAY] != NULL)
            {
                ElfW(Addr) *array =
                    (ElfW(Addr) *) (l->l_addr
                                    + l->l_info[DT_FINI_ARRAY]->d_un.d_ptr);
                unsigned int i = (l->l_info[DT_FINI_ARRAYSZ]->d_un.d_val
                                  / sizeof (ElfW(Addr)));
                while (i-- > 0)
                    ((fini_t) array[i]) (); // 这里call
            }

            /* Next try the old-style destructor.  */
            if (ELF_INITFINI && l->l_info[DT_FINI] != NULL)
                DL_CALL_DT_FINI
                (l, l->l_addr + l->l_info[DT_FINI]->d_un.d_ptr); // 这里call
        }

#define	DT_FINI_ARRAY	26		/* Array with addresses of fini fct */
#define	DT_FINI_ARRAYSZ	28		/* Size in bytes of DT_FINI_ARRAY */

typedef struct {
    Elf64_Sxword d_tag;    /* 标签（类型标识），决定了这个条目代表什么信息 */
    union {
        Elf64_Xword d_val; /* 一个整数值（比如大小） */
        Elf64_Addr  d_ptr; /* 一个虚拟内存地址（比如指向符号表的指针） */
    } d_un;
} Elf64_Dyn;
```

所以，利用的思路有：

- 直接伪造`_rtld_global` 的`_ns_loaded`，布局好其他内容，使其调用到 `fini_array`
- 伪造 `link_map` 的 `next` 指针，布局好其他内容，使其调用到 `fini_array`
- 修改 `link_map->l_addr`或`DT_FINI_ARRAY`、`DT_FINI_ARRAYSZ`表段，根据偏移使其调用到指定区域的函数

### 相关技巧[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e7%9b%b8%e5%85%b3%e6%8a%80%e5%b7%a7-19)

- 伪造 `fini_array` 数组的时候，是从后往前遍历的
- 有时候远程的 `rtld_global` 的偏移与本地不一样，需要爆破
- 如果不想逐个伪造，可以直接用 `gdb` 从内存里面 `dump` 出来，然后基于偏移修改内存即可

### 利用效果[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e6%95%88%e6%9e%9c-18)

- 任意代码执行

## 2.21-House of Kiwi[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#221-house-of-kiwi)

### 漏洞成因[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e6%bc%8f%e6%b4%9e%e6%88%90%e5%9b%a0-20)

堆溢出

### 适用范围[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e9%80%82%e7%94%a8%e8%8c%83%e5%9b%b4-20)

- `2.23`——`2.36`
- 在 `malloc` 流程中触发 `assert`

### 利用原理[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e5%8e%9f%e7%90%86-20)

主要是提供了一种在程序中调用 `IO` 流函数的思路：

```c
#if IS_IN (libc)
#ifndef NDEBUG
# define __assert_fail(assertion, file, line, function)			\
	 __malloc_assert(assertion, file, line, function)

extern const char *__progname;

static void
__malloc_assert (const char *assertion, const char *file, unsigned int line,
		 const char *function)
{
  (void) __fxprintf (NULL, "%s%s%s:%u: %s%sAssertion `%s' failed.\n",
		     __progname, __progname[0] ? ": " : "",
		     file, line,
		     function ? function : "", function ? ": " : "",
		     assertion);
  fflush (stderr);
  abort ();
}
#endif
#endif
```

可以看到，调用到了 `fxprintf` 和 `fflush`。

至于原 `house of kiwi` 所提到的控制 `rdx` 的思路，在很多版本中无法使用，因为 `IO_jumps_table` 都是不可写的，故此处不再详述。

### 相关技巧[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e7%9b%b8%e5%85%b3%e6%8a%80%e5%b7%a7-20)

- 在 `2.36` 之后，`__malloc_assert` 被修改为：

```c
_Noreturn static void
__malloc_assert (const char *assertion, const char *file, unsigned int line,
		 const char *function)
{
  __libc_message (do_abort, "\
Fatal glibc error: malloc assertion failure in %s: %s\n",
		  function, assertion);
  __builtin_unreachable ();
}
```

而在 `2.37` 该函数直接被删掉了。

- 如果 `stderr` 在 `libc` 上，需要修改调 `stderr` 处的指针，也有可能在程序的地址空间上
    
- 伪造的技巧如下，触发 `fxprintf(stderr，......)`：
    
    |   |   |
    |---|---|
    ||```fallback<br>flags & 0x8000的话，不用伪造_lock<br>flags & ~(0x2 \| 0x8) 必须成立，避免走到unbuffered的流程<br>mode 设置为0<br>vtable默认调用的是偏移0x38的函数，如果想劫持为_IO_xxx_overflow，需要设置为_IO_xxx_jumps-0x20<br>flags 可以设置为"  sh\|"，前面有两个空格，此时还需要设置_lock，不想设置_lock的时候，flags可以为"\x20\x80;sh\|"<br>```|
    

### 利用效果[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e6%95%88%e6%9e%9c-19)

- 触发 `IO` 处理流程，为后续利用做准备

## 2.22-House of Emma[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#222-house-of-emma)

### 漏洞成因[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e6%bc%8f%e6%b4%9e%e6%88%90%e5%9b%a0-21)

堆溢出

### 适用范围[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e9%80%82%e7%94%a8%e8%8c%83%e5%9b%b4-21)

- `2.23`—— 至今
- 可以进行两次 `largebin attack`
- 或者可以进行两次任意地址写堆地址
- 可以触发 `IO` 流操作

### 利用原理[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e5%8e%9f%e7%90%86-21)

在`_IO_cookie_jumps` 中存在一些`_IO_cookie_read` 等函数，如下：

```c
static ssize_t
_IO_cookie_read (FILE *fp, void *buf, ssize_t size)
{
  struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;
  cookie_read_function_t *read_cb = cfile->__io_functions.read;
#ifdef PTR_DEMANGLE
  PTR_DEMANGLE (read_cb);
#endif

  if (read_cb == NULL)
    return -1;

  return read_cb (cfile->__cookie, buf, size);
}
```

可以看到有函数指针的调用。但是对函数指针使用 `pointer_guard` 进行了加密：

```gdscript3
#  define PTR_MANGLE(var)	asm ("xorl %%gs:%c2, %0\n"		      \
				     "roll $9, %0"			      \
				     : "=r" (var)			      \
				     : "0" (var),			      \
				       "i" (offsetof (tcbhead_t,	      \
						      pointer_guard)))
#  define PTR_DEMANGLE(var)	asm ("rorl $9, %0\n"			      \
				     "xorl %%gs:%c2, %0"		      \
				     : "=r" (var)			      \
				     : "0" (var),			      \
				       "i" (offsetof (tcbhead_t,	      \
						      pointer_guard)))
# endif
```

循环右移后，再异或。

因此，利用思路如下：

- 截至某个 `IO_FILE` 的指针（`IO_list_all/stdxxx->chain` 等都可以）为堆地址
- 堆上伪造 `IO_FILE` 结构，其 `vtable` 替换为`_IO_cookie_jumps+XX`，`XX` 为一个偏移量
- 伪造好函数指针和调用参数，指针需要循环异或和加密
- 调用到`_IO_cookie_read` 等函数，进而执行任意函数

### 相关技巧[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e7%9b%b8%e5%85%b3%e6%8a%80%e5%b7%a7-21)

- 常用的 `gadget` 有：
    
    |   |   |
    |---|---|
    ||```fallback<br>;栈迁移<br>mov    rbp,QWORD PTR [rdi+0x48]<br>mov    rax,QWORD PTR [rbp+0x18]<br>lea    r13,[rbp+0x10]<br>mov    DWORD PTR [rbp+0x10],0x0<br>mov    rdi,r13<br>call   QWORD PTR [rax+0x28]<br><br><br>; rdi转rdx<br>mov rdx, qword ptr [rdi + 8]<br>mov qword ptr [rsp], rax<br>call qword ptr [rdx + 0x20]<br>```|
    
- `pointer_guard` 就在 `canary` 下面，偏移可能需要爆破
    

### 利用效果[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e6%95%88%e6%9e%9c-20)

- 任意函数执行

## 2.23-House of Pig[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#223-house-of-pig)

### 漏洞成因[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e6%bc%8f%e6%b4%9e%e6%88%90%e5%9b%a0-22)

堆溢出

### 适用范围[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e9%80%82%e7%94%a8%e8%8c%83%e5%9b%b4-22)

- `2.23`—— 至今
- 可以进行 `largebin attack`
- 可以触发 `IO` 流操作

### 利用原理[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e5%8e%9f%e7%90%86-22)

在`_IO_str_jumps` 中，存在着`_IO_str_overflow` 函数：

```c
int
_IO_str_overflow (FILE *fp, int c)
{
  int flush_only = c == EOF;
  size_t pos;
  if (fp->_flags & _IO_NO_WRITES)
      return flush_only ? 0 : EOF;
  if ((fp->_flags & _IO_TIED_PUT_GET) && !(fp->_flags & _IO_CURRENTLY_PUTTING))
    {
      fp->_flags \|= _IO_CURRENTLY_PUTTING;
      fp->_IO_write_ptr = fp->_IO_read_ptr;
      fp->_IO_read_ptr = fp->_IO_read_end;
    }
  pos = fp->_IO_write_ptr - fp->_IO_write_base;
  if (pos >= (size_t) (_IO_blen (fp) + flush_only))
    {
      if (fp->_flags & _IO_USER_BUF) /* not allowed to enlarge */
	return EOF;
      else
	{
	  char *new_buf;
	  char *old_buf = fp->_IO_buf_base; // 覆盖到这里
	  size_t old_blen = _IO_blen (fp);
	  size_t new_size = 2 * old_blen + 100;
	  if (new_size < old_blen)
	    return EOF;
	  new_buf = malloc (new_size); // 调用malloc
	  if (new_buf == NULL)
	    {
	      /*	  __ferror(fp) = 1; */
	      return EOF;
	    }
	  if (old_buf)
	    {
	      memcpy (new_buf, old_buf, old_blen);// 调用memecpy，覆盖
	      free (old_buf); // 调用free
	      /* Make sure _IO_setb won't try to delete _IO_buf_base. */
	      fp->_IO_buf_base = NULL;
	    }
	  memset (new_buf + old_blen, '\0', new_size - old_blen);
      //......
      }
  }
```

从函数中就能看到，利用流程如下：

- 伪造 `IO_FILE` 的`_IO_buf_base`
- 合理控制`_IO_buf_end-_IO_buf_base` 的值，进而控制分配的 `chunk` 的大小，分配到布局好的地址
- 在 `memcpy` 中覆盖地址，如可以覆盖`__malloc_hook/__free_hook` 等

该方法需要结合其他堆利用技术，需要保证 `malloc` 分配出来的 `chunk` 的地址是可控的。该方法主要提供了对 `IO` 系列函数中间接调用 `mallc/free/memcpy` 的组合利用。

### 相关技巧[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e7%9b%b8%e5%85%b3%e6%8a%80%e5%b7%a7-22)

- 可以 `largebin attack` 打掉 `mp_.tcachebins`，进而能把很大的 `chunk` 也放进入 `tcache` 进行管理
- 高版本没有 `hook` 的话，可以利用 `memcpy@got`，通过覆写 `got` 来进行 `rce`
- 可以多次 `house of pig` 组合调用

### 利用效果[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e6%95%88%e6%9e%9c-21)

- 任意函数执行
- `ROP` 控制程序执行流

## 2.24-House of Obstack[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#224-house-of-obstack)

### 漏洞成因[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e6%bc%8f%e6%b4%9e%e6%88%90%e5%9b%a0-23)

堆溢出

### 适用范围[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e9%80%82%e7%94%a8%e8%8c%83%e5%9b%b4-23)

- `2.23`—— 至今
- 可以执行一次 `largebin attack`
- 可以触发 `IO` 流操作

### 利用原理[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e5%8e%9f%e7%90%86-23)

一条新的利用链，伪造 `vtable` 为`_IO_obstack_jumps`，然后调用到`_IO_obstack_xsputn`，紧接着调用 `obstack_grow`，其代码为：

```c
#define obstack_grow(OBSTACK, where, length)                      \
  __extension__                                   \
    ({ struct obstack *__o = (OBSTACK);                       \
       int __len = (length);                              \
       if (_o->next_free + __len > __o->chunk_limit)                  \
     _obstack_newchunk (__o, __len);                      \
       memcpy (__o->next_free, where, __len);                     \
       __o->next_free += __len;                           \
       (void) 0; })
```

然后在`_obstack_newchunk` 调用了 `CALL_CHUNKFUN` 这个宏

```c
void
_obstack_newchunk (struct obstack *h, int length)
{
  struct _obstack_chunk *old_chunk = h->chunk;
  struct _obstack_chunk *new_chunk;
  long new_size;
  long obj_size = h->next_free - h->object_base;
  long i;
  long already;
  char *object_base;

  /* Compute size for new chunk.  */
  new_size = (obj_size + length) + (obj_size >> 3) + h->alignment_mask + 100;
  if (new_size < h->chunk_size)
    new_size = h->chunk_size;

  /* Allocate and initialize the new chunk.  */
  new_chunk = CALL_CHUNKFUN (h, new_size);
  [...]
}
```

这个宏会调用到函数指针：

```c
# define CALL_CHUNKFUN(h, size) \
  (((h)->use_extra_arg)                               \
   ? (*(h)->chunkfun)((h)->extra_arg, (size))                     \
   : (*(struct _obstack_chunk *(*)(long))(h)->chunkfun)((size)))
```

因此，其就是利用该函数指针进行控制程序的执行流。

### 相关技巧[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e7%9b%b8%e5%85%b3%e6%8a%80%e5%b7%a7-23)

伪造的 `IO_FILE` 布局如下：

- 利用 `largebin attack` 伪造`_IO_FILE`，记完成伪造的 `chunk` 为 `A`（或者别的手法）
- `chunk A` 内偏移为 `0xd8` 处设为`_IO_obstack_jumps+0x20`
- `chunk A` 内偏移为 `0xe0` 处设置 `chunk A` 的地址作为 `obstack` 结构体
- `chunk A` 内偏移为 `0x18` 处设为 `1`（`next_free`)
- `chunk A` 内偏移为 `0x20` 处设为 `0`（`chunk_limit`）
- `chunk A` 内偏移为 `0x48` 处设为 `&/bin/sh`
- `chunk A` 内偏移为 `0x38` 处设为 `system` 函数的地址
- `chunk A` 内偏移为 `0x28` 处设为 `1`（`_IO_write_ptr`)
- `chunk A` 内偏移为 `0x30` 处设为 `0` (`_IO_write_end`)
- `chunk A` 内偏移为 `0x50` 处设为 `1` (`use_extra_arg`)

`glibc-2.37` 开始这个方法的调用链为：`__printf_buffer_as_file_overflow -> __printf_buffer_flush -> __printf_buffer_flush_obstack->__obstack_newchunk`。

### 利用效果[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e6%95%88%e6%9e%9c-22)

- 任意函数执行

## 2.25-House of Apple1[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#225-house-of-apple1)

### 漏洞成因[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e6%bc%8f%e6%b4%9e%e6%88%90%e5%9b%a0-24)

堆溢出

### 适用范围[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e9%80%82%e7%94%a8%e8%8c%83%e5%9b%b4-24)

- `2.23`—— 至今
    
- 程序从 `main` 函数返回或能调用 `exit` 函数
    
- 能泄露出 `heap` 地址和 `libc` 地址
    
- 能使用一次 `largebin attack`（一次即可）
    

### 利用原理[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e5%8e%9f%e7%90%86-24)

利用`_IO_wstr_overflow` 将任意地址存储的值修改已知值：

```c
static wint_t
_IO_wstrn_overflow (FILE *fp, wint_t c)
{
  /* When we come to here this means the user supplied buffer is
     filled.  But since we must return the number of characters which
     would have been written in total we must provide a buffer for
     further use.  We can do this by writing on and on in the overflow
     buffer in the _IO_wstrnfile structure.  */
  _IO_wstrnfile *snf = (_IO_wstrnfile *) fp;

  if (fp->_wide_data->_IO_buf_base != snf->overflow_buf)
    {
      _IO_wsetb (fp, snf->overflow_buf,
		 snf->overflow_buf + (sizeof (snf->overflow_buf)
				      / sizeof (wchar_t)), 0);

      fp->_wide_data->_IO_write_base = snf->overflow_buf;
      fp->_wide_data->_IO_read_base = snf->overflow_buf;
      fp->_wide_data->_IO_read_ptr = snf->overflow_buf;
      fp->_wide_data->_IO_read_end = (snf->overflow_buf
				      + (sizeof (snf->overflow_buf)
					 / sizeof (wchar_t)));
    }

  fp->_wide_data->_IO_write_ptr = snf->overflow_buf;
  fp->_wide_data->_IO_write_end = snf->overflow_buf;

  /* Since we are not really interested in storing the characters
     which do not fit in the buffer we simply ignore it.  */
  return c;
}
```

比如修改 `tcache` 变量、`mp_`结构体、`pointer_guard` 变量等。

修改成功后，再使用其他技术控制程序执行流。

### 相关技巧[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e7%9b%b8%e5%85%b3%e6%8a%80%e5%b7%a7-24)

`house of apple1` 是对现有一些 `IO` 流攻击方法的补充，能在一次劫持 `IO` 流的过程中做到任意地址写已知值，进而构造出其他方法攻击成功的条件。

### 利用效果[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e6%95%88%e6%9e%9c-23)

- 任意地址写已知堆地址

## 2.26-House of Apple2[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#226-house-of-apple2)

### 漏洞成因[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e6%bc%8f%e6%b4%9e%e6%88%90%e5%9b%a0-25)

堆溢出

### 适用范围[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e9%80%82%e7%94%a8%e8%8c%83%e5%9b%b4-25)

- `2.23`—— 至今
- 已知 `heap` 地址和 `glibc` 地址
- 能控制程序执行 `IO` 操作，包括但不限于：从 `main` 函数返回、调用 `exit` 函数、通过`__malloc_assert` 触发
- 能控制`_IO_FILE` 的 `vtable` 和`_wide_data`，一般使用 `largebin attack` 去控制

### 利用原理[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e5%8e%9f%e7%90%86-25)

`_IO_WIDE_JUMPS` 没有检查`_wide_vtable` 的合法性：

```c
#define _IO_WOVERFLOW(FP, CH) WJUMP1 (__overflow, FP, CH)

#define WJUMP1(FUNC, THIS, X1) (_IO_WIDE_JUMPS_FUNC(THIS)->FUNC) (THIS, X1)

#define _IO_WIDE_JUMPS_FUNC(THIS) _IO_WIDE_JUMPS(THIS)

#define _IO_WIDE_JUMPS(THIS) \
  _IO_CAST_FIELD_ACCESS ((THIS), struct _IO_FILE, _wide_data)->_wide_vtable
```

所以利用`_IO_wfile_jumps` 等伪造`_wide_vtable` 即可。

### 相关技巧[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e7%9b%b8%e5%85%b3%e6%8a%80%e5%b7%a7-25)

利用`_IO_wfile_overflow` 函数控制程序执行流时对 `fp` 的设置如下：

- `_flags` 设置为 `~(2 | 0x8 | 0x800)`，如果不需要控制 `rdi`，设置为 `0` 即可；如果需要获得 `shell`，可设置为 `  sh;`，注意前面有两个空格。  
    对应 `struct _IO_FILE._flags`，相对 `fp` 的偏移是 **`0x00`**，字段大小 **`0x4`**。
- `vtable` 设置为 `_IO_wfile_jumps/_IO_wfile_jumps_mmap/_IO_wfile_jumps_maybe_mmap` 地址（加减偏移），使其能成功调用 `_IO_wfile_overflow` 即可。  
    这里的 `vtable` 是 `struct _IO_FILE_plus.vtable`，也就是在 `FILE` 结构体末尾额外跟着的那个指针；相对 `fp` 的偏移是 **`0xd8`**，字段大小 **`0x8`**。
- `_wide_data` 设置为可控堆地址 `A`，即满足 `*(fp + 0xa0) = A`。  
    对应 `struct _IO_FILE_complete._wide_data`，相对 `fp` 的偏移是 **`0xa0`**，字段大小 **`0x8`**。
- `_wide_data->_IO_write_base` 设置为 `0`，即满足 `*(A + 0x18) = 0`。  
    对应 `struct _IO_wide_data._IO_write_base`，相对 `A` 的偏移是 **`0x18`**，字段大小 **`0x8`**。
- `fp->_wide_data->_IO_write_ptr`设置为1，即满足`*(A+0x20) = 1`
	由于要求`fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base`，这里把`fp->_wide_data->_IO_write_ptr`设置为1，相对 `A` 的偏移是 **`0x20`**，字段大小 **`0x8`**。
- `_wide_data->_IO_buf_base` 设置为 `0`，即满足 `*(A + 0x30) = 0`。  
    对应 `struct _IO_wide_data._IO_buf_base`，相对 `A` 的偏移是 **`0x30`**，字段大小 **`0x8`**。
- `_wide_data->_wide_vtable` 设置为可控堆地址 `B`，即满足 `*(A + 0xe0) = B`。  
    对应 `struct _IO_wide_data._wide_vtable`，相对 `A` 的偏移是 **`0xe0`**，字段大小 **`0x8`**。
- `_wide_data->_wide_vtable->doallocate` 设置为地址 `C` 用于劫持 `RIP`，即满足 `*(B + 0x68) = C`。  
    这里的 `doallocate` 对应 `struct _IO_jump_t.__doallocate`，相对 `B` 的偏移是 **`0x68`**，字段大小 **`0x8`**。
- libc 2.38 及以上版本需要向 `lock` 处写入原 `lock` 的地址。  
    这个 `lock` 对应 `struct _IO_FILE._lock`，相对 `fp` 的偏移是 **`0x88`**，字段大小 **`0x8`**。
### 利用效果[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e6%95%88%e6%9e%9c-24)

- 任意函数执行

## 2.27-House of Apple3[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#227-house-of-apple3)

### 漏洞成因[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e6%bc%8f%e6%b4%9e%e6%88%90%e5%9b%a0-26)

堆溢出

### 适用范围[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e9%80%82%e7%94%a8%e8%8c%83%e5%9b%b4-26)

- `2.23`—— 至今
- 已知 `heap` 地址和 `glibc` 地址
- 能控制程序执行 `IO` 操作，包括但不限于：从 `main` 函数返回、调用 `exit` 函数、通过`__malloc_assert` 触发
- 能控制`_IO_FILE` 的 `vtable` 和`_wide_data`，一般使用 `largebin attack` 去控制

### 利用原理[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e5%8e%9f%e7%90%86-26)

`__libio_codecvt_in` 等函数，可以设置 `gs->__shlib_handle == NULL` 绕过 `PTR_DEMANGLE` 对指针的保护，然后通过`_IO_wfile_underflow` 调用到`__libio_codecvt_in` 来控制函数指针，执行任意代码。

```c
enum __codecvt_result
__libio_codecvt_in (struct _IO_codecvt *codecvt, __mbstate_t *statep,
		    const char *from_start, const char *from_end,
		    const char **from_stop,
		    wchar_t *to_start, wchar_t *to_end, wchar_t **to_stop)
{
  enum __codecvt_result result;
  // gs 源自第一个参数
  struct __gconv_step *gs = codecvt->__cd_in.step;
  int status;
  size_t dummy;
  const unsigned char *from_start_copy = (unsigned char *) from_start;

  codecvt->__cd_in.step_data.__outbuf = (unsigned char *) to_start;
  codecvt->__cd_in.step_data.__outbufend = (unsigned char *) to_end;
  codecvt->__cd_in.step_data.__statep = statep;

  __gconv_fct fct = gs->__fct;
#ifdef PTR_DEMANGLE
  // 如果gs->__shlib_handle不为空，则会用__pointer_guard去解密
  // 这里如果可控，设置为NULL即可绕过解密
  if (gs->__shlib_handle != NULL)
    PTR_DEMANGLE (fct);
#endif
  // 这里有函数指针调用
  // 这个宏就是调用fct(gs, ...)
  status = DL_CALL_FCT (fct,
			(gs, &codecvt->__cd_in.step_data, &from_start_copy,
			 (const unsigned char *) from_end, NULL,
			 &dummy, 0, 0));
       // ......
}
```

### 相关技巧[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e7%9b%b8%e5%85%b3%e6%8a%80%e5%b7%a7-26)

利用_IO_wfile_underflow 函数控制程序执行流时对 `fp` 的设置如下：

- `_flags` 设置为 `~(4 | 0x10)`
- `vtable` 设置为`_IO_wfile_jumps` 地址（加减偏移），使其能成功调用`_IO_wfile_underflow` 即可
- `fp->_IO_read_ptr < fp->_IO_read_end`，即满足 `*(fp + 8) < *(fp + 0x10)`
- `_wide_data` 保持默认，或者设置为堆地址，假设其地址为 `A`，即满足 `*(fp + 0xa0) = A`
- `_wide_data->_IO_read_ptr >= _wide_data->_IO_read_end`，即满足 `*A >= *(A + 8)`
- `_codecvt` 设置为可控堆地址 `B`，即满足 `*(fp + 0x98) = B`
- `codecvt->__cd_in.step` 设置为可控堆地址 `C`，即满足 `*B = C`
- `codecvt->__cd_in.step->__shlib_handle` 设置为 `0`，即满足 `*C = 0`
- `codecvt->__cd_in.step->__fct` 设置为地址 `D`, 地址 `D` 用于控制 `rip`，即满足 `*(C + 0x28) = D`。当调用到 `D` 的时候，此时的 `rdi` 为 `C`。如果`_wide_data` 也可控的话，`rsi` 也能控制。

### 利用效果[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e6%95%88%e6%9e%9c-25)

- 任意函数执行

## 2.28-House of Gods[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#228-house-of-gods)

### 漏洞成因[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e6%bc%8f%e6%b4%9e%e6%88%90%e5%9b%a0-27)

堆溢出

### 适用范围[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e9%80%82%e7%94%a8%e8%8c%83%e5%9b%b4-27)

- `2.23`——`2.27`
- 泄露堆地址和 `libc` 地址
- 任意大小分配

### 利用原理[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e5%8e%9f%e7%90%86-27)

这个技巧比较有意思，非常建议把作者的原博客读一下。我会简述一下该技巧的利用过程。

总的来说，该技巧最终的目的是伪造一个 `fake arena`，通过劫持 `main_arena.next` 字段完成。

其主要过程为：

- 通过 `binmap` 的赋值，将其当做 `chunk` 的 `size`，然后修改 `unsortedbin` 链的 `bk` 指向 `binmap`，作者选择的是 `0x90` 大小的 `chunk`，释放后恰好让 `binmap` 称为 `0x200`，然后 `binmap->bk` 是 `main_arena`(初始状态下 `main_arena.next = &main_arena`)，然后 `main_arena->bk= fastbin[0x40]`
- 分配 `0x1f0` 大小的 `chunk` 就刚好能分配到 `binmap`
- 之后修改掉 `main_arena` 的 `system_mem` 为很大的值和 `next` 指向 `fake arena`
- 然后用 `unsortedbin attack` 打掉 `narenas`，将其改为一个很大的数
- 然后分配两次 `malloc(0xffffffffffffffbf + 1)`，触发 `arena_get_retry`，进而触发两次 `reused_arena`，就能把 `fake arena` 给 `thread_arena` 变量
- 最后直接伪造 `fastbin` 任意地址分配

### 相关技巧[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e7%9b%b8%e5%85%b3%e6%8a%80%e5%b7%a7-27)

- 仅仅借助 `unsortedbin` 链就能控制 `main_arena` 的 `next` 和 `system_mem`
- 利用 `binmap` 的值构造出合法的 `size`

### 利用效果[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e6%95%88%e6%9e%9c-26)

- 劫持 `thread_arena` 为 `fake_arena`

## 2.29-House of Lys[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#229-house-of-lys)

### 漏洞成因[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e6%bc%8f%e6%b4%9e%e6%88%90%e5%9b%a0-28)

堆溢出

### 适用范围[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e9%80%82%e7%94%a8%e8%8c%83%e5%9b%b4-28)

- `2.23` —— 至今
- 泄露堆地址和 `libc` 地址
- 任意大小分配

### 利用原理[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e5%8e%9f%e7%90%86-28)

调用 `_IO_obstack_XXX` 函数的时候，没有检查函数指针的有效性。调用链为：

```c
exit
 __run_exit_handlers
   fcloseall
     _IO_cleanup
		_IO_flush_all_lockp
     		_IO_obstack_xsputn
         		obstack_grow
           			_obstack_newchunk
              			CALL_CHUNKFUN(一个宏定义)
                			(*(h)->chunkfun)((h)->extra_arg, (size))
```

### 相关技巧[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e7%9b%b8%e5%85%b3%e6%8a%80%e5%b7%a7-28)

- 伪造 `vtable` 为 `_IO_obstack_jumps`，然后触发 `_IO_obstack_xsputn` 函数执行上述调用链

### 利用效果[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#%e5%88%a9%e7%94%a8%e6%95%88%e6%9e%9c-27)

- 任意函数执行

## 2.30-House of Snake[](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/#230-house-of-snake)

和上一个 `house of lys` 的原理是类似的，但是用于 `glibc-2.37`
{% endraw %}
