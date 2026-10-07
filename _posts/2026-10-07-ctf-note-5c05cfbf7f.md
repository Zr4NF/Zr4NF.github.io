---
layout: post
title: "2026 / ctf+ / Advanced Mathematics"
date: 2026-10-07 20:05:00 +0800
tags: ["CTF", "Write-up"]
description: "Notes and solution for Advanced Mathematics from ctf+ (2026)."
source_folder: "Write-ups/2026/ctf+"
lang: zh-CN
---
{% raw %}
# 源码

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

char sym[12] = "+-x%^&+-x%^&";
int seed, fail = 0;
int Num1[120];
int Num2[120];
int flag1 = 0, flag2 = 0, flag3 = 0;
int offset = 0;

void init()
{
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
}

void setNum()
{
    for (int i = 0; i < 120; i++)
    {
        Num1[i] = rand() % 0x10000 + 0x100;
        Num2[i] = rand() % 0x10000 + 0x100;
    }
}

int Trueval(int n1, char sym, int n2)
{
    switch (sym)
    {
    case '+':
        return n1 + n2;
    case '-':
        return n1 - n2;
    case 'x':
        return n1 * n2;
    case '%':
        return n1 % n2;
    case '^':
        return n1 ^ n2;
    case '&':
        return n1 & n2;
    }
    return 0;
}

int cala(int idx)
{
    if (idx < 40)
    {
        int res, true;
        int tmp = rand() % 6;
        if (!flag1)
        {
            flag1++;
            srand(rand());
            offset = rand() % 6;
        }
        printf("%d %c %d = \n", Num1[idx], sym[tmp + offset], Num2[idx]);
        scanf("%d", &res);
        true = Trueval(Num1[idx], sym[tmp], Num2[idx]);
        if (res == true)
            return 0;
        return 1;
    }
    else if (idx < 80)
    {
        int res, true;
        int tmp = rand() % 6;
        if (!flag2)
        {
            flag2++;
            srand(rand());
            offset = rand() % 6;
        }
        printf("%d %c %d = \n", Num1[idx], sym[tmp + offset], Num2[idx]);
        scanf("%d", &res);
        true = Trueval(Num1[idx], sym[tmp], Num2[idx]);
        if (res == true)
            return 0;
        return 1;
    }
    else
    {
        int res, true;
        int tmp = rand() % 6;
        if (!flag3)
        {
            flag3++;
            srand(rand());
            offset = rand() % 6;
        }
        printf("%d %c %d = \n", Num1[idx], sym[tmp + offset], Num2[idx]);
        scanf("%d", &res);
        true = Trueval(Num1[idx], sym[tmp], Num2[idx]);
        if (res == true)
            return 0;
        return 1;
    }
}

int main()
{
    init();
    char name[0x30];
    char buf[0x10];
    int fd = open("/dev/urandom", 0);
    read(fd, buf, 4);
    puts("Can you finish this test?");
    memcpy(&seed, buf, 4);
    srand(seed);
    setNum();
    for (int i = 0; i < 120; i++)
    {
        if (cala(i))
        {
            puts("You lose");
            exit(-1);
        }
        puts("Good");
        puts("Next task");
    }
    puts("You got it!");
    system("cat flag");
    return 0;
}
```

# 思路

程序会取随机数，当作偏移处理数学式的符号，每40个算式取一次偏移，偏移都有6种可能，所以只要猜每次偏移都是0，就有 1/216 的概率获得flag。

# exp
```python
def s32(x):
    return u32(p32(x & 0xffffffff), sign='signed')
# 将算出的数据取低位后打包，并用 u32() 解包加 sign 参数，模拟 int 类型数据的计算过程

def calc(a, op, b):
    if op == "+":
        return s32(a + b)
    if op == "-":
        return s32(a - b)
    if op == "x":
        return s32(a * b)
    if op == "%":
        return s32(a % b)
    if op == "^":
        return s32(a ^ b)
    if op == "&":
        return s32(a & b)
    raise ValueError(op)

def pwn():
    ru(b'Can you finish this test?\n')
    for i in range(120):
        
        data = rl()
        
        m = re.search(rb"(-?\d+)\s*([+\-x%^&])\s*(-?\d+)\s*=", data)
        if not m:
            ic()
            return
        
        a = int(m.group(1))
        tmp = m.group(2).decode()
        b = int(m.group(3))
        r = calc(a,tmp,b)
        sl(str(r).encode())
        
        result = io.recvline(timeout=1)
        if b"You lose" in result or not result:
            io.close()
            return False
        rl(timeout=1)
        
        
    data = rpt(0.2)
    if b'flag' in data:
        print(data)
        ia()
        

file = "/home/qwer/pwn/pwn"
host = "nc1.ctfplus.cn"
port = 37603
libc_path = "/lib/x86_64-linux-gnu/libc.so.6"
"""
"/home/qwer/pwn/pwn"
"./libc.so.6"
"/lib/x86_64-linux-gnu/libc.so.6"
"/lib/i386-linux-gnu/libc.so.6"
"""

for i in range(200):
    io, p, libc = init(file, host, port, libc_path)
    pwn()
```

# tips

对爆破概率较低的题，要注意优化io流，特别是每次io都要尽量节省时间，不然exp没跑完，就会crash。
{% endraw %}
