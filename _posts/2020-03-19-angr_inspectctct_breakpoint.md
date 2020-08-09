---
layout: post
title: "Angr - inspect 断点"
date: 2020-03-19 13:35:17
categories: binary
tags: angr basicblock
---
angr 基本知识与inspect断点的使用

最近针对分析程序基本块内单指令的输入输出数据做了一些学习，主要使用angr的断点功能

## angr install

env : Ubuntu18.04 x86_64

version : python3 - angr 8.18.10.25

官方建议安装在virtualenv虚拟环境中，因为angr使用的z3库与官方z3库有区别，防止对真实环境中依赖库造成影响

```shell
# ref:https://github.com/a7vinx/angr-doc-zh_CN/blob/master/INSTALL.md
sudo apt-get install python3-dev libffi-dev build-essential  -y
sudo pip3 install virtualenvwrapper # mkvirturalenv command not found now
echo "export VIRTUALENVWRAPPER_PYTHON=/usr/bin/python3 \ export WORKON_HOME=$HOME/.virtualenvs" > ~/.zshrc
echo "source $(whereis virturalenvwrapper.sh)" > ~/.zshrc
source ~/.zshrc
mkvirtualenv --python=$(which python3) angr #&& pip install angr 
# 后面进入虚拟环境使用workon命令
workon angr
# 退出环境：deactivate 
# 删除环境: rmvirtualenv
pip3 install angr==8.18.10.25 # 不需要sudo， 否则会安装到真实环境中
# 不需要安装angr-dev，否则自动更新angr到最新版本
python3
>>> import angr
```

## angr - Block创建与接口

Block是angr中专门针对基本块进行分析的一个子类，通过地址获取指定的基本块对象

```python
import angr
bin = Project("./demo")
block = bin.factory.block(0x8048522)
```

其中project是angr中的一个顶层接口，用来加载二进制文件

> This is the main class of the angr module. It is meant to contain a set of binaries and the relationships between them, and perform analyses on them.

factory是提供重要分析对象的接口，本文中的全部操作也都是在factory接口下进行的。

block表示了一个基本块的重要信息，主要有以下访问接口

```python
>>> block.
┌────────────────────────────────────────────────────────────────────────────────┐
│ BLOCK_MAX_SIZE     addr               arch               bytes                 │
│ capstone           codenode           instruction_addrs  instructions          │
│ pp                 size               thumb              vex                   │
│ vex_nostmt                                                                     │
└────────────────────────────────────────────────────────────────────────────────┘

```
如将打印基本块的vex IR中间语言及capstone汇编


| vex IR                                                       | asm                         |
| ------------------------------------------------------------ | --------------------------- |
| >>> block.vex.pp()<br/>IRSB {<br/>   t0:Ity_I32 t1:Ity_I32···<br/>00 \| ------ IMark(0x8048522, 3, 0) ------<br/>01 \| t44 = GET:I32(ebp)<br/>02 \| t43 = Add32(t44,0xffffffec)<br/>03 \| t45 = LDle:I32(t43)<br/>04 \| ------ IMark(0x8048525, 2, 0) ------<br/>05 \| ------ IMark(0x8048527, 3, 0) ------<br/>06 \| t4 = Shl32(t45,0x02)<br/>07 \| ------ IMark(0x804852a, 2, 0) ------<br/>08 \| t8 = Add32(t4,t45)<br/>09 \| PUT(eip) = 0x0804852c<br/>10 \| ------ IMark(0x804852c, 3, 0) ------<br/>11 \| t58 = Add32(t44,0xffffffec)<br/>12 \| STle(t58) = t8<br/>13 \| PUT(eip) = 0x0804852f<br/>14 \| ------ IMark(0x804852f, 3, 0) ------<br/>15 \| t61 = Add32(t44,0xffffffe8)<br/>16 \| t63 = LDle:I32(t61)<br/>··· | >>> block.capstone.pp()<br/>0x8048522:	mov	edx, dword ptr [ebp - 0x14]<br/>0x8048525:	mov	eax, edx<br/>0x8048527:	shl	eax, 2<br/>0x804852a:	add	eax, edx<br/>0x804852c:	mov	dword ptr [ebp - 0x14], eax<br/>0x804852f:	mov	edx, dword ptr [ebp - 0x18]<br/>0x8048532:	mov	eax, dword ptr [ebp - 0x14]<br/>0x8048535:	add	eax, edx<br/>0x8048537:	mov	dword ptr [ebp - 0x10], eax<br/>0x804853a:	mov	eax, dword ptr [ebp - 0x10]<br/>0x804853d:	sub	eax, dword ptr [ebp - 0xc]<br/>0x8048540:	mov	dword ptr [ebp - 0x18], eax<br/>0x8048543:	sub	esp, 0xc<br/>0x8048546:	push	dword ptr [ebp - 0x10]<br/>0x8048549:	push	dword ptr [ebp - 0x14]<br/>0x804854c:	push	dword ptr [ebp - 0x18]<br/>0x804854f:	push	dword ptr [ebp - 0xc]<br/>0x8048552:	lea	eax, [ebx - 0x19f9]<br/>0x8048558:	push	eax<br/>0x8048559:	call	0x8048300 |

*IR是一种中间语言，将程序运算操作使用临时变量进行符号化运算*

## angr - SimState与数据查看&编辑

SimState保存着程序运行到某一阶段的状态信息，能够追踪且记录符号信息、符号对应的内存信息和符号对应的寄存器信息，以及打开的文件信息在当前运行状态等，同时可以借助simulation_manager模拟执行，查看甚至修改运行中数据。

### state的创建

state的创建方式有两种：

```python
>>> import angr
>>> bin = angr.Project("./demo")
>>> state = bin.factory.entry_state()
>>> state = bin.factory.blank_state(addr = 0x8048522)
```

``` entry_state() ```会进行初始化工作，并在程序入口点(start)处创建状态

``` blank_state(addr = ) ```在指定地址处创建一个“空”state，对象中数据未进行初始化，访问时会返回符号量

### state中状态数据的访问

主要是寄存器和内存数据的访问和指定

对于**寄存器**，可以使用```state.regs.eax```来访问(寄存器名称与架构相关)

```python
>>> state.regs.eip
<BV32 0x8048522>
>>> hex(state.solver.eval(state.regs.eip))
'0x8048522'
>>> state.regs.eax
WARNING | 2020-03-18 22:25:59,654 | angr.state_plugins.symbolic_memory | Register eax has
 an unspecified value; Generating an unconstrained value of 4 bytes.
<BV32 reg_eax_1_32{UNINITIALIZED}>
>>> state.regs.eax = 0xdeadbeef
>>> state.regs.eax
<BV32 0xdeadbeef>
>>> state.solver.BVV(0xdeadbeef, 32)
<BV32 0xdeadbeef>
>>> state.solver.BVV(0xdeadbeef, 64)
<BV64 0xdeadbeef>
```

可以直接使用整数对regs进行赋值，但访问regs返回的类型是BV(bit vector)类型，

使用```state.solver.eval()```转换成python的int类型，使用BVV函数可以可以将int数据转换成BV数据类型。

对于**内存**值，使用```state.mem```接口。

```python
>>> state.regs.ebp = 0x7fffff18
>>> state.regs.ebx = 0x7ffffd00
>>> state.mem[state.regs.ebp-0xc].dword = 3
>>> state.mem[state.regs.ebx-0x19f9].dword = 0x1234
>>> state.mem[state.regs.ebx-0x19f9].dword.resolved
<BV32 0x1234>
>>> state.mem[state.regs.ebx-0x19f9].dword.concrete
4660
```

有所区别的是除了使用```mem[address]```指定地址外，还需要使用指定访问目标的数据类型。应该是由于相邻地址内存数据修改长度的原因。

使用```.resolved```将数据输出为BV值，使用```.concrete```将数据输出为int值。

## angr - inspect断点使用及数据获取

### state的运行

上节中提到state可以借助simulation_manager跑起来。但是目前我还没有找到指令级别运行的引擎，也就是说，基于state运行的粒度是基本块级别，只能一跑就跑完整个基本块。

在运行前，需要对基本块中寄存器或内存值进行赋值，否则运行结束后访问参与计算的变量会返回符号表达式。

有两种运行方式：

- 使用**simulation_,manager()**接口

  ```python
  >>> state = bin.factory.entry_state()
  >>> print("init state's eip: ", state.regs.eip)
  init state's eip:  <BV32 0x8048340>
  >>> simgr = bin.factory.simulation_manager(state)
  >>> for i in range(5):
  ...     print("now branch number: ", len(simgr.active), end = "; ")
  ...     newstate = simgr.active[0]
  ...     print("eip: ", newstate.regs.eip)
  ...     simgr.step()
  ...     
  ... 
  now branch number:  1; eip:  <BV32 0x8048340>
  <SimulationManager with 1 active>
  now branch number:  1; eip:  <BV32 0x8048373>
  <SimulationManager with 1 active>
  now branch number:  1; eip:  <BV32 0x8048350>
  <SimulationManager with 1 active>
  now branch number:  1; eip:  <BV32 0x8048310>
  <SimulationManager with 1 active>
  now branch number:  1; eip:  <BV32 0x9018d90>
  <SimulationManager with 1 active>
  >>> print("now state's eip: ", state.regs.eip)
  now state's eip:  <BV32 0x8048340>
  ```

  使用state初始化一个SimulationManager实例，循环调用```simgr.step()```运行，每次产生的新状态存储在```simgr.active```中。

- 直接使用**state.step()**

  除了调用```simulation_manager```，```state.step()```本身也可以直接运行。

  ```python
  >>> state = bin.factory.entry_state()
  >>> while 1:
  ...     print(state.regs.eip)
  ...     succ = state.step()
  ...     if len(succ.successors) == 2 or succ.successors[0].addr == 0x80484f7:
  ...         print("len  == 2 or touch if")
  ...         break
  ...     state = succ.successors[0]
  ...     if state.addr == 0x80484aa:
  ...         print("touch 0x80484aa and set eax to 6")
  ...         state.regs.eax=6
  ...     elif state.addr == 0x8048478:
  ...         print("touch 0x8048478 and set eax to 3")
  ...         state.regs.eax=3
  ...         
  ...     
  ... 
  <BV32 0x8048340>
  <BV32 0x8048373>
  <BV32 0x8048350>
  <BV32 0x8048310>
  <BV32 0x9018d90>
  <BV32 0x8048570>
  WARNING | 2020-03-18 23:56:44,997 | angr.state_plugins.symbolic_memory | Register ed
  i has an unspecified value; Generating an unconstrained value of 4 bytes.
  <BV32 0x8048390>
  ...
  <BV32 0x9031430>
  touch 0x8048478 and set eax to 3
  <BV32 0x8048478>
  <BV32 0x8048320>
  <BV32 0x9031430>
  touch 0x80484aa and set eax to 6
  <BV32 0x80484aa>
  <BV32 0x8048300>
  <BV32 0x90512d0>
  len  == 2 or touch if
  ```

  这种方法中没有唯一的一个manager，而是需要接收每个state的运行结果，然后从successors中对state重新进行赋值。

值得注意的是，无论哪种方式，运行之后state本身不会变，他的后继状态要通过active[]或successors[]来获取

### state断点使用

目前angr中的模拟运行的粒度是基本块级别的，但是如果想要获取基本块内更细粒度的信息时，是不能直接通过state访问得到的。angr通过断点功能很好的弥补了这一点。

#### 添加断点

angr的断点不是把运行当中的state停下，而是通过设置触发函数，在state运行过程中遇到断点时，触发预设的action函数，从而完成对信息的访问。如

```python
def printstate(nowstate):
    ...

state = bin.factory.blank_state(addr = 0x8048522)
state.regs.ebp = 0x7fffff18
state.mem[state.regs.ebp-0x14].dword = 9
state.mem[state.regs.ebp-0x18].dword = 6
state.mem[state.regs.ebp-0xc].dword = 3
state.mem[state.regs.ebx-0x19f9].dword = 0x1234
state.inspect.b("mem_read", when = angr.BP_AFTER, action = angr.BP_IPYTHON)# printstate)
# state.inspect.b("reg_read", when = angr.BP_BEFORE, action = regread)
succ = state.step()
```

使用```state.inspect.b()```对一个state添加断点，参数分别是

- event type：触发断点的事件类型
- when：指定事件发生之前/之后触发action
- action：触发断点时调用的回调函数

全部事件类型及含义如下表

| Event type             | Event meaning                                                |
| ---------------------- | ------------------------------------------------------------ |
| mem_read               | Memory is being read.                                        |
| mem_write              | Memory is being written.                                     |
| address_concretization | A symbolic memory access is being resolved.                  |
| reg_read               | A register is being read.                                    |
| reg_write              | A register is being written.                                 |
| tmp_read               | A temp is being read.                                        |
| tmp_write              | A temp is being written.                                     |
| expr                   | An expression is being created (i.e., a result of an arithmetic operation or a constant in the IR). |
| statement              | An IR statement is being translated.                         |
| instruction            | A new (native) instruction is being translated.              |
| irsb                   | A new basic block is being translated.                       |
| constraints            | New constraints are being added to the state.                |
| exit                   | A successor is being generated from execution.               |
| fork                   | A symbolic execution state has forked into multiple states.  |
| symbolic_variable      | A new symbolic variable is being created.                    |
| call                   | A call instruction is hit.                                   |
| return                 | A ret instruction is hit.                                    |
| simprocedure           | A simprocedure (or syscall) is executed.                     |
| dirty                  | A dirty IR callback is executed.                             |
| syscall                | A syscall is executed (called in addition to the simprocedure event). |
| engine_process         | A SimEngine is about to process some code.                   |

由于最近的学习关注的是基本块内部指令的输入输出，所以只用了instruction, mem_read/write, reg_read/write, tmp_read/write

除了以上事件类型，还有很多属性可以协助添加更加精确的断点。

| Event type  | Attribute name      | Attribute availability | Attribute meaning                                            |
| ----------- | ------------------- | ---------------------- | ------------------------------------------------------------ |
| mem_read    | mem_read_address    | BP_BEFORE or BP_AFTER  | The address at which memory is being read.                   |
| mem_read    | mem_read_expr       | BP_AFTER               | The expression at that address.                              |
| mem_read    | mem_read_length     | BP_BEFORE or BP_AFTER  | The length of the memory read.                               |
| mem_read    | mem_read_condition  | BP_BEFORE or BP_AFTER  | The condition of the memory read.                            |
| mem_write   | mem_write_address   | BP_BEFORE or BP_AFTER  | The address at which memory is being written.                |
| mem_write   | mem_write_length    | BP_BEFORE or BP_AFTER  | The length of the memory write.                              |
| mem_write   | mem_write_expr      | BP_BEFORE or BP_AFTER  | The expression that is being written.                        |
| mem_write   | mem_write_condition | BP_BEFORE or BP_AFTER  | The condition of the memory write.                           |
| reg_read    | reg_read_offset     | BP_BEFORE or BP_AFTER  | The offset of the register being read.                       |
| reg_read    | reg_read_length     | BP_BEFORE or BP_AFTER  | The length of the register read.                             |
| reg_read    | reg_read_expr       | BP_AFTER               | The expression in the register.                              |
| reg_read    | reg_read_condition  | BP_BEFORE or BP_AFTER  | The condition of the register read.                          |
| reg_write   | reg_write_offset    | BP_BEFORE or BP_AFTER  | The offset of the register being written.                    |
| reg_write   | reg_write_length    | BP_BEFORE or BP_AFTER  | The length of the register write.                            |
| reg_write   | reg_write_expr      | BP_BEFORE or BP_AFTER  | The expression that is being written.                        |
| reg_write   | reg_write_condition | BP_BEFORE or BP_AFTER  | The condition of the register write.                         |
| tmp_read    | tmp_read_num        | BP_BEFORE or BP_AFTER  | The number of the temp being read.                           |
| tmp_read    | tmp_read_expr       | BP_AFTER               | The expression of the temp.                                  |
| tmp_write   | tmp_write_num       | BP_BEFORE or BP_AFTER  | The number of the temp written.                              |
| tmp_write   | tmp_write_expr      | BP_AFTER               | The expression written to the temp.                          |
| expr        | expr                | BP_BEFORE or BP_AFTER  | The IR expression.                                           |
| expr        | expr_result         | BP_AFTER               | The value (e.g. AST) which the expression was evaluated to.  |
| statement   | statement           | BP_BEFORE or BP_AFTER  | The index of the IR statement (in the IR basic block).       |
| instruction | instruction         | BP_BEFORE or BP_AFTER  | The address of the native instruction.                       |
| 表格太长    | 而且也没用过        | 列举无义               | 更多属性及信息，详见[官方文档](https://docs.angr.io/core-concepts/simulation) |

这些属性都可以作为添加断点时的参数，来增加对断点的约束，使断点更加精确

```python
# This will break before a memory write if 0x1000 is a possible value of its target expression
>>> s.inspect.b('mem_write', mem_write_address=0x1000)
​
# This will break before a memory write if 0x1000 is the *only* value of its target expression
>>> s.inspect.b('mem_write', mem_write_address=0x1000, mem_write_address_unique=True)
​
# This will break after instruction 0x8000, but only 0x1000 is a possible value of the last expression that was read from memory
>>> s.inspect.b('instruction', when=angr.BP_AFTER, instruction=0x8000, mem_read_expr=0x1000)
```

#### 回调函数

除此之外，可以在**回调函数**中通过```state.inspect```来访问以上属性，从而获得程序在基本块内部的信息。

```python
def memread(state):
    if state.inspect.instruction == None:
        return
    print("mem read at " + hex(state.inspect.instruction))
    print("Read ", end = "")
    print(state.inspect.mem_read_expr, end = "")
    print(" from ", end = "")
    print(state.inspect.mem_read_address)
    return
state.inspect.b("mem_read", when = angr.BP_AFTER, action = memread)# angr.BP_IPYTHON)
succ = state.step()
------------------------------------
mem read at 0x8048522
Read <BV32 0x9> from <BV32 0x7fffff04>
mem read at 0x804852f
Read <BV32 0x6> from <BV32 0x7fffff00>
mem read at 0x8048532
Read <BV32 0x2d> from <BV32 0x7fffff04>
mem read at 0x804853a
Read <BV32 0x33> from <BV32 0x7fffff08>
mem read at 0x804853d
Read <BV32 0x3> from <BV32 0x7fffff0c>
mem read at 0x8048546
Read <BV32 0x33> from <BV32 0x7fffff08>
mem read at 0x8048549
Read <BV32 0x2d> from <BV32 0x7fffff04>
mem read at 0x804854c
Read <BV32 0x30> from <BV32 0x7fffff00>
mem read at 0x804854f
Read <BV32 0x3> from <BV32 0x7fffff0c>
mem read at 0x8048559
Read <BV32 0x804855e> from <BV32 0x7ffffedc>
```

但经过实践，寄存器与内存读写事件的触发并不是基于汇编，而是基于对应的vex IR。

也就是说，如```add eax, edx```这一句，严格来讲存在对edx、eax的读操作，和对eax的写操作，理论上会触发寄存器读写断点；但实际上，在vex IR中，eax和edx都是通过隐形赋值给了IR中的临时变量，所以在IR角度看没有寄存器的读写操作。

所以只有在基本块对应的IR中存在```GET()```、```PUT()```、```STle()```、```LDle()```或其他架构等效函数的时候才会触发内存/寄存器读/写断点。

最终发现使用```tmp_read```和```tmp_write```断点可以直接通过```tmp_read_expr```和```tmp_read_num```等属性访问得到IR中的临时值```txx```和读写的值。符合对基本块内部指令级别的输入输出数据的获取，

*由于这部分可能和一个朋友的毕设相关，为避免不必要的麻烦，数据获取和处理的代码暂时不公开(其实也很简单)*



**ref：**

[0xHack-angr基本属性介绍](https://www.cnblogs.com/0xHack/p/11581529.html)

[安全脉搏angr学习笔记](https://www.secpulse.com/archives/83197.html)

[先知社区angr系列教程一](https://xz.aliyun.com/t/7117#toc-0)

[angr文档-Execution Engines](https://docs.angr.io/core-concepts/simulation)

[angr文档翻译](https://www.jianshu.com/p/69f4f5b22c94)





