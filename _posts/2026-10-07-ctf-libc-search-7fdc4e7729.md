---
layout: post
title: "Using Local libc Search"
date: 2026-10-07 20:05:00 +0800
tags: ["CTF", "PWN"]
description: "记录通过本地 libc 数据库识别库版本的流程。"
source_folder: "PWN"
lang: zh-CN
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
