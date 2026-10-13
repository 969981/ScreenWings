# P0 Windows VM 实机判别方案：用 4 个硬件断点追 EDI

**状态：尚未在隔离 Windows VM 中执行。** 此文档只提供经过静态地址校核的观察设置，不附带伪造寄存器读数。建议在系统快照后的隔离 Windows 虚拟机里操作；未知受保护 EXE 不应在主力计算机执行。

## 为什么只监控最后的故障地址不够

当前受限静态模型：

```text
0x5C3033    EAX = 0x18
0x5C30B8    [context+0x7A] = 0x18
0x5C3118    ESI = [context+0x7A] = 0x18
0x5C3123    [context+0x3B] = 0x18
0x53D2ED    EDI = [context+0x3B] = 0x18
0x53D2EF    EDI = [0x18] -> research-model unmapped
```

它是**模型结果，不是实机读数**。如果真实进程在这些地址得到不同数据，必须在**最早差异点**修正入口种子/内存语义，不能继续把虚拟机代码路径“推演”为真实 OEP。

## WinDbg 的初始准备

原样本的加载首选 image base 为 `0x400000`，但运行时可能受 ASLR 或外壳重映射影响。以下模块相对偏移是从已确认的 **VA - 0x400000** 计算的，不能直接假定绝对地址恒定。

```text
目标静态 VA    模块相对 RVA
0x5C3033      0x1C3033
0x5C3123      0x1C3123
0x53D2ED      0x13D2ED
0x53D2EF      0x13D2EF
```

附加到 VM 内的 **32 位 ScreenWings 进程**后，使用 WinDbg 命令窗口：

```text
.effmach x86
lm m ScreenWings
.logopen /t C:\Temp\screenwings-p0-edi.txt
```

先核对模块名称、实际 ImageBase 与内存中的目标字节。尤其是第一层必须已经还原到内存，否则断点可能对着尚未解包的空虚拟节。

手动将实际模块基址记为 `B`，并确认：

```text
u B+0x1C3033 L1      ; 应是 sub eax,dword ptr [esi]
u B+0x1C3123 L1      ; 应是 add dword ptr [edx],esi
u B+0x13D2ED L1      ; 应是 mov edi,dword ptr [edi]
u B+0x13D2EF L1      ; 应是 mov edi,dword ptr [edi]
```

上面的 `B` 是说明性占位符；运行时请替换为实际数值，或按符号表达式用 `ScreenWings+0x...`。确认内容不匹配时不要继续使用这些断点，可能有运行时重定位、虚拟化页替换或反分析干扰。

## 硬件执行断点

WinDbg 官方文档中的 **`ba e 1`** 是执行断点，可避免常见的 `bp` 软件 `INT3` 指令覆盖。x86 通常仅有四个硬件调试槽位，故初次只使用四个 P0 地址：

```text
ba e 1 ScreenWings+0x1C3033
ba e 1 ScreenWings+0x1C3123
ba e 1 ScreenWings+0x13D2ED
ba e 1 ScreenWings+0x13D2EF
bl
g
```

**这些命令仅适用于解析到目标模块、确认代码已映射后的状态。** 硬件断点不会像软件 `INT3` 那样改写代码字节，但调试器仍会改变目标环境，并可能触发 WinLicense 反调试；不命中不代表路径不存在。

每次中断时执行：

```text
r
u @eip L4
dd @ebp+0x09 L1
dd @ebp+0x3b L1
dd @ebp+0x7a L1
dd @ebp+0x7e L1
k
```

同时根据指令阶段观察 `@esi`、`@edi`、`@edx` 所指数据；对低值或不可映射指针不要强行解引用。记录实际 EIP、模块基址、ESI/EDI/EBP/ESP、栈和页属性；在 `0x53D2ED` 中断后单步核实 `EDI` 再进入 `0x53D2EF`。

停止记录：

```text
.logclose
```

先判断最早的模型/真实值分叉处：`0x5C3033` 的算术输入，还是 `0x5C3123` 的目标上下文，还是 `0x53D2ED` 的 EDI 指针。如果四处都不命中，需排查断点设置时机、模块实际加载基址、WinLicense 地址变换，而不是宣布该代码不可达。

## 证据接受标准

| 观察 | 解释边界 |
|---|---|
| 四处都命中、真实 EDI 与模型不同 | 修正模型上游数据与控制流；目前不存在正常 OEP 证明 |
| `0x53D2ED` 真实 EDI 最终为 `0x18` 并触发 AV | 仅证明测试会话出现错误路径；需排查反调试或样本运行配置 |
| 实际程序未执行任何上述地址 | 可能属于备用 VM handler、条件代码、早期解包、重映射；不能简单当作永久无用代码 |
| 触发代码页写入/权限变化 | 记录模块、源调用点和页映射，后续再判断是否是原始业务代码还原 |
| 仅观察到这些保护层运算 | **不够证明** `SetWindowDisplayAffinity` 或截屏机制 |

WinDbg `ba` 的语法/硬件限制见微软 [ba (Break on Access)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/ba--break-on-access-) 和 [Processor Breakpoints](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/processor-breakpoints---ba-breakpoints-)；`.logopen /t` 的记录方法见微软 [.logopen](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-logopen--open-log-file-)。

录制前确保无私人屏幕或账户数据；分享前检查日志内容。该计划**没有在当前 Linux 环境实际运行**。
