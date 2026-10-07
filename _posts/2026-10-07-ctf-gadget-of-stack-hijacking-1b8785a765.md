---
layout: post
title: "Gadget of Stack Hijacking"
date: 2026-10-07 20:05:00 +0800
tags: ["CTF", "PWN"]
description: "Stack hijacking gadgets and control-flow techniques."
source_folder: "PWN"
lang: zh-CN
---
{% raw %}
`getkeyserv_handle+576`
2.35
```
<getkeyserv_handle+576>:	mov    rdx,QWORD PTR [rdi+0x8]
<getkeyserv_handle+580>:	mov    QWORD PTR [rsp],rax
<getkeyserv_handle+584>:	call   QWORD PTR [rdx+0x20]
```

`setcontext+61`
2.35
```
   <setcontext+61>:	mov    rsp,QWORD PTR [rdx+0xa0]
   <setcontext+68>:	mov    rbx,QWORD PTR [rdx+0x80]
   <setcontext+75>:	mov    rbp,QWORD PTR [rdx+0x78]
   <setcontext+79>:	mov    r12,QWORD PTR [rdx+0x48]
   <setcontext+83>:	mov    r13,QWORD PTR [rdx+0x50]
   <setcontext+87>:	mov    r14,QWORD PTR [rdx+0x58]
   <setcontext+91>:	mov    r15,QWORD PTR [rdx+0x60]
   <setcontext+95>:	test   DWORD PTR fs:0x48,0x2
   <setcontext+107>:	je     0x71f8c9453b06 <setcontext+294>
   <setcontext+113>:	mov    rsi,QWORD PTR [rdx+0x3a8]
   <setcontext+120>:	mov    rdi,rsi
   <setcontext+123>:	mov    rcx,QWORD PTR [rdx+0x3b0]
   <setcontext+130>:	cmp    rcx,QWORD PTR fs:0x78
   <setcontext+139>:	je     0x71f8c9453aa5 <setcontext+197>
   <setcontext+141>:	mov    rax,QWORD PTR [rsi-0x8]
   <setcontext+145>:	and    rax,0xfffffffffffffff8
   <setcontext+149>:	cmp    rax,rsi
   <setcontext+152>:	je     0x71f8c9453a80 <setcontext+160>
   <setcontext+154>:	sub    rsi,0x8
   <setcontext+158>:	jmp    0x71f8c9453a6d <setcontext+141>
   <setcontext+160>:	mov    rax,0x1
   <setcontext+167>:	incsspq rax
   <setcontext+172>:	rstorssp QWORD PTR [rsi-0x8]
   <setcontext+177>:	saveprevssp
   <setcontext+181>:	mov    rax,QWORD PTR [rdx+0x3b0]
   <setcontext+188>:	mov    QWORD PTR fs:0x78,rax
   <setcontext+197>:	rdsspq rcx
   <setcontext+202>:	sub    rcx,rdi
   <setcontext+205>:	je     0x71f8c9453acc <setcontext+236>
   <setcontext+207>:	neg    rcx
   <setcontext+210>:	shr    rcx,0x3
   <setcontext+214>:	mov    esi,0xff
   <setcontext+219>:	cmp    rcx,rsi
   <setcontext+222>:	cmovb  rsi,rcx
   <setcontext+226>:	incsspq rsi
   <setcontext+231>:	sub    rcx,rsi
   <setcontext+234>:	ja     0x71f8c9453abb <setcontext+219>
   <setcontext+236>:	mov    rsi,QWORD PTR [rdx+0x70]
   <setcontext+240>:	mov    rdi,QWORD PTR [rdx+0x68]
   <setcontext+244>:	mov    rcx,QWORD PTR [rdx+0x98]
   <setcontext+251>:	mov    r8,QWORD PTR [rdx+0x28]
   <setcontext+255>:	mov    r9,QWORD PTR [rdx+0x30]
   <setcontext+259>:	mov    r10,QWORD PTR [rdx+0xa8]
   <setcontext+266>:	mov    rdx,QWORD PTR [rdx+0x88]
   <setcontext+273>:	rdsspq rax
   <setcontext+278>:	cmp    r10,QWORD PTR [rax]
   <setcontext+281>:	mov    eax,0x0
   <setcontext+286>:	jne    0x71f8c9453b03 <setcontext+291>
   <setcontext+288>:	push   r10
   <setcontext+290>:	ret
```
{% endraw %}
