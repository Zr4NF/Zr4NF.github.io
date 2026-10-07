---
layout: post
title: "ezFinger"
date: 2026-10-07 20:05:00 +0800
tags: ["CTF", "Write-up"]
description: "Notes and solution for ezFinger from polar (2026)."
source_folder: "Write-ups/2026/polar/re"
lang: zh-CN
---
{% raw %}
# ezFinger WP

先看 `sub_8003498`。它直接读 `0x40023808/0x40023804`，也就是 STM32F4 的 `RCC->CFGR` 和 `RCC->PLLCFGR`。函数先判断系统时钟源是 `HSI/HSE/PLL`，如果是 HSI 返回 `16000000`，如果是 HSE 返回 `8000000`，如果是 PLL 就按 `PLLM/PLLN/PLLP` 的配置去计算最终的 `SYSCLK`。这正是 HAL 里 `HAL_RCC_GetSysClockFreq` 的典型逻辑，所以 `sub_8003498 = HAL_RCC_GetSysClockFreq`。

再看 `sub_8000EC0`。它先用一个 pin 映射表把输入编号转成具体的 `port + pin`，再通过 `sub_8000F64` 取 GPIO 基址，通过 `sub_800128E` 按参数把对应引脚输出高低电平。它的上层调用点也都符合 Arduino 风格的“按逻辑引脚号写电平”，所以 `sub_8000EC0 = digitalWrite`。

 flag ：`xmctf{HAL_RCC_GetSysClockFreq_digitalWrite}`

{% endraw %}
