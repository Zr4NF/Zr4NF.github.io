---
layout: post
title: "本地libc search使用"
date: 2026-10-07 20:05:00 +0800
tags: ["CTF", "PWN"]
---
{% raw %}
```
from LibcSearcher import *

libc = LibcSearcher("puts", puts_addr)

libc.add_condition("read", read_addr)

puts_offset = libc.dump("puts")
system_offset = libc.dump("system")
binsh_offset = libc.dump("str_bin_sh")
```
{% endraw %}
