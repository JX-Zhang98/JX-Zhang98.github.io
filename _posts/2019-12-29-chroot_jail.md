---
layout: post
title: "chroot jail break in CTF from 0 to -1"
date: 2019-12-29 19:57:22
categories: CTF
tags: chroot sandbox
---

xnuna2019-awd3 & thuctf2019-固若金汤

## chroot者，何也

### /usr/bin/chroot

> chroot(1) 
>
> chroot - run command or interactive shell with special root directory 
>
> chroot [OPTION] NEWROOT [COMMAND [ARG]…]

作为linux命令，chroot可以在指定目录新起一个shell，在新的shell中，指定的目录将会成为新的根目录(/)，限制文件访问的范围。如：

```bash
root@Dp:/ # ls
bin   etc    home            lastore  lib64       media  proc  sbin      sys  var
boot  flag   initrd.img      lib      libx32      mnt    root  srv       tmp  vmlinuz
dev   glibc  initrd.img.old  lib32    lost+found  opt    run   swapfile  usr  vmlinuz.old
root@Dp:/ # cat /flag
this_is_flag_in_root
root@Dp:/ # cd /tmp/jail 
root@Dp:/tmp/jail # ls
bash  bash-5.0-beta  bash-5.0-beta.tar.gz  busybox-x86_64  exploit  flag  sub  subdir
root@Dp:/tmp/jail # cat flag
this_is_flag_in_jail
root@Dp:/tmp/jail # chroot . ./bash
bash-5.0# pwd
/
bash-5.0# ./busybox-x86_64 ls
bash                  bash-5.0-beta.tar.gz  exploit               sub
bash-5.0-beta         busybox-x86_64        flag                  subdir
bash-5.0# ./busybox-x86_64 cat /flag
this_is_flag_in_jail
bash-5.0# cd ..
bash-5.0# pwd
/
bash-5.0# ./busybox-x86_64 ls
bash                  bash-5.0-beta.tar.gz  exploit               sub
bash-5.0-beta         busybox-x86_64        flag                  subdir
```

在使用```chroot . ./bash```命令新起的bash-5.0中，原系统中```/tmp/jail```目录成为了根目录，其父目录及同级目录都不可见。

![1p0lge.jpg](https://s2.ax1x.com/2020/01/18/1p0lge.jpg)

```bash
//以jail为根目录的shell中没有链接库，bash及其他工具均为静态编译，busybox中包含很多常用工具命令
wget https://busybox.net/downloads/binaries/1.21.1/busybox-x86_64
wget http://ftp.gnu.org/gnu/bash/bash-5.0-beta.tar.gz
./configure --enable-static-link --without-bash-malloc
make
```

### chroot('path') in libc

> chroot(2) 
>
> chroot - change root directory
>
> int chroot(const char *path);

与系统命令类似，chroot()函数改变进程的根目录，使进程对文件的访问限制在指定的根目录树中，实现一个沙箱。

```c
#include <unistd.h>
#include <stdio.h>
int main()
{
    char buf[100] = {0};
    chroot(".");
    //chdir("/");
    FILE * f = fopen("/flag", "r");
    fread(buf, 1, 99, f);
    puts(buf);
    fclose(f);
    return 0;
}
//need to run with root or sudo;print the flag in . instead of / 
```

## chroot 逃逸

chroot逃逸的核心是**使进程中存在一个文件，处于根目录树之外**。

这里需要了解两个目录的概念：

1. CWD (current work diretory)：进程当前的工作目录，```cd ..; open('./flag')```这里用到的就是CWD，有时候vscode中运行运行程序无法找到相对路径存储的文件也是CWD搞的鬼。
2. root (root diretory)：进程当前的根目录，决定了当前进程全部的可访问文件都在root的目录树中

其实可以直接和terminal中的目录结构对应起来，毕竟shell也是一个进程，本质上是一样的。

在进程中，通过(f)chdir和chroot函数可以更改进程的CWD和root目录

```c
int chdir(const char *path);     //依据目录名改cwd
int fchdir(int fd);              //依据文件描述符改cwd
int chroot(const char *path);    //依据目录名改rootDir
```

chdir()和cd命令一样，改变了CWD，即改变了直接使用相对地址```.```的访问结果

chroot()则与chroot命令一样，直接限定了进程的root目录(rootDir)，直接进入了chroot创建的沙箱文件系统，目录树外部的文件对进程透明。

### 1 - chroot to subDir 

利用调用```chroot()```时内核不会改变进程的CWD的特性。

1. 在jail中创建子进程，子进程中调用```chroot(subDir)```，将子进程的rootDir转移到subDir；
2. 此时进程的CWD并没有发生改变，所以子进程的CWD已经存在于rootDir的目录树之外，此时针对CWD调用chdir就可以不断地向父目录移动，经过有限次“../”到达真正的root目录；
3. 最终调用chroot(.)，就将沙箱的root恢复到系统真实的root目录。

![1p0q56.jpg](https://s2.ax1x.com/2020/01/18/1p0q56.jpg)

概括一下子进程中只需要```mkdir(d); chroot(d); chdir(../../../); chroot(.)```四步，子进程就完成了逃逸，可以访问真实目录下的文件。

**chroot()需要具有root权限，但题目使用chroot构建沙箱也需要root权限，所以一般可以满足*

Xnuca2019中的[awd3](<https://github.com/JX-Zhang98/MyStudy/tree/master/others/xnuca2019-chroot>)就是这种类型，题目在/tmp/jail中建造沙箱，然后允许上传文件，由沙箱使用execveat系统调用进行执行，可以多次上传但每次执行结束沙箱都会刷新。

~~这题目其实感觉出了些瑕疵，虽然构建了沙箱，但是题目本身的CWD没有变，仍然是文件所在位置，导致的结果就是完全不用逃逸，子进程直接访问../../../../../ ... ../../../../../../../flag就可以拿到~~

为了验证逃逸策略~~没事找事~~，在exploit里面先```chdir("/");```主动入狱，然后尝试逃逸。

[半成品代码](<https://github.com/JX-Zhang98/MyStudy/blob/master/others/xnuca2019-chroot/exploit.c>)：

```c
int main()
{
    catflag("../../../../../../../../flag"); // get real flag in root directly
    chdir("/");                              // enter jail
    catflag("../../../../flag");             // try to read ../ ... ../flag in root2
    int fd = open(".", O_RDWR);
    chrootsubdir();                          //chroot may change cwd to chrooted
    //still failed....
    fchdir(fd);
    chdir("../../../../../../../../");
    chroot(".");                             // jail should have broken
    catflag("./flag");                       // it should be real flag
    return 0;
}
```

理论上按照之前分析，以上代码可以顺利逃逸，实际上直接在本地模拟的jail中执行exploit确能逃逸，读到真实root中的flag，但喂给题目文件通过execveat系统调用没有实现逃逸，暂时没有找到原因。。。

![1p0X8O.jpg](https://s2.ax1x.com/2020/01/18/1p0X8O.jpg)

### 2 - existing outside fd

如果在chroot时还保留着之前之前打开的file descriptor，且fd在chrooted的根目录之外，则可以直接使用保留的fd实现对沙盒外部的访问

如[THUCTF2019-固若金汤](<https://github.com/JX-Zhang98/MyStudy/tree/master/others/THUCTF2019-impregnable>)中，创建沙盒后，可以使用popen执行一条命令

题目源码中```syscall(__NR_clone, CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUSER | CLONE_FILES | CLONE_NEWUTS | CLONE_NEWNET, 0, 0, 0, 0);```使用```clone```系统调用创建子进程(1)，与fork类似，但clone能够控制更多的细节，[Clang裁缝店](<https://xuanxuanblingbling.github.io/ctf/pwn/2019/10/15/sandbox/>)大佬分析了很多。这里使用了*CLONE_FILES* flag，使得子进程(1)与父进程的fd共享，包括在clone之后由父进程打开的fd。

这就导致在使用popen执行指定命令的时候，popen创建的子进程(2)会继承子进程(1)的fd，在执行popen的子进程(2)中存在的外部fd有：

```
3: /home/ctf/sandbox/
4: /home/ctf/sandbox/xxx/
5: /proc/xxx/uid_map
```

其中3和5都在根目录之外，可以利用进行逃逸。

由于使用seccomp禁用了很多系统调用，所以前一种方法基本上用不了，但是```openat(fd, path, flags)```函数能够利用已知句柄打开相对路径文件，所以利用继承而来的外部fd，配合openat就能够访问到真实的根目录下的文件

3 - ptrace附加其他进程，利用注入shellcode使用其他不在jail的进程实现逃逸。

loading...

**Reference：**

[betaMao](https://blog.betamao.me/2019/01/31/Linux%E6%B2%99%E7%AE%B1%E4%B9%8Bchroot%E4%B8%8Erbash/)

[chw00t](https://github.com/earthquake/chw00t/blob/master/Presentations/Balazs_Bucsay_Hacktivity2015_chw00t.pdf)

[Atum](http://atum.li/2017/04/25/linuxsandbox/)

[bpfh-chrootbreak](https://web.archive.org/web/20160127150916/http://www.bpfh.net/simes/computing/chroot-break.html)

[Clang裁缝店](<https://xuanxuanblingbling.github.io/ctf/pwn/2019/10/15/sandbox/>)

