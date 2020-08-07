---
layout: post
title: "WinRAR  x64 去广告记录"
date: 2020-08-07 15:57:59
categories: software
tags: x64dbg winrar
---
remove advertisements in winrar

## 0x01实验环境

操作系统：Windows 10 x64

实验对象：WinRAR 5.71（64位）

使用工具：MS Spy++；x64dbg

## 0x02窗口捕捉

对于分析windows上的窗口信息，spy++非常好用，可以直接捕捉桌面窗口，显示指定窗口的句柄、标题和类等信息

这里使用spy++对广告窗口进行捕获，以便于后面的进一步分析

首先打开一个winrar程序，使其弹出广告。

此时打开spy++，点击*搜索 -> 查找窗口*，拖动**查找程序工具**到广告窗口的标题栏上

![afALKH.png](https://s1.ax1x.com/2020/08/07/afALKH.png)

就可以显示出广告窗口的类名是RarReminder，可以利用类名在代码中搜索

## 0x03窗口弹出指令分析

应该是包含资源的原因，winrar程序在IDA中没有找到相应的信息，因此采用动态调试，64位程序使用x64dbg进行调试

启动后开始运行，会自动添加到exe模块的入口断点，并停在程序入口处

此时*右键->搜索->当前模块->字符串*，输入广告窗口的类名“RarReminder”

可以找到程序中两处对'RarReminder'字符串的引用，顺便在这些指令上下个断点

[![afnmgf.png](https://s1.ax1x.com/2020/08/07/afnmgf.png)](https://imgchr.com/i/afnmgf)

接下来继续运行(F9)到这两处，分别做进一步分析

首先到达的是107位置的指令，根据上下文可以分析得出，此处指令是对“RARReminder”窗口类进行注册

![](https://s1.ax1x.com/2020/08/07/afKApt.png)



继续运行，经过几个跨模块时debuger自动添加的断点后来到5c1处，根据上下文就可以确定是在此处通过*CreateWindowExW*函数，创建了RarReminder类的一个实例，即广告窗口。并且0x7ff6f13d05a2处引用的字符串网址，就是广告得url。

![afQ6Te.png](https://s1.ax1x.com/2020/08/07/afQ6Te.png)

通过继续逐步(F8)运行，执行完```call CreateWindowExW```后，确实立刻弹出了广告窗口。

到此就确定了弹出窗口的机制和具体位置。

## Patch

上一节中确定了弹出窗口的指令位于图中0x5ed处，因此只要把该地址对应的指令直接nop掉，就不会创建窗口了

在debuger中选中call指令，*右键->在内存窗口中转到->选定的地址*

就可以在左下角的内存窗口中显示该地址

只需要在此将属于```call CreateWindowExW```指令的六个字节全部改为nop(0x90)即可

在内存窗口中选定该六个字节，*右键->二进制编辑->编辑*

在编辑框中全部改为*90*

![aftve1.png](https://s1.ax1x.com/2020/08/07/aftve1.png)

此时理论上已经完成了任务，将修补之后的文件导出

右键->补丁->修补文件，保存为合适的文件即可

经测试，修补之后的文件可以正常运行，没有出现广告，使用体验 ↑↑

## 附录

Winrar注册文件

在winrar.exe同目录下保存

```
RAR registration data
8677
100 PC usage license
UID=01d5e0968e0dea51faf1
6412212250faf1ec6a9abb73bbcd462125cf0588ecffb70efb2166
8321b3487a8b6cff71396007e697024c155e27713a0f6ced4231f1
bdd814b379ce793dea8dc738ed6feab43e470752e4be6223bc1505
ef939613fad2a789a4e17319eb43d7f8b2609eeefcdf8f52f9cb6c
ed51073e1772bf16fe9f90f79747b3955bab8304837f92176dfe8d
ff216fe1e6498f74e62cef2191de19f88139e2f0c66407ef600bc5
57501b67807a0e696de9f05780245bb0e246318b0eee2068526980
```

为rarreg.key即可