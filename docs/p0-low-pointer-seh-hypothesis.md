# ScreenWings P0：0x18 二次解引用与异常处理链候选核验

日期：2026-10-14。第一层恢复区域 SHA-256：
`2a1185bbcc93a049d413a71104ed41623bae61cf2412de5ea015564ea8b4d420`；`schiffer` 映射基址 VA `0x492000`，总长 `0x672000`。源 EXE SHA-256：`481ecd41bef2a33076729680747eb92e4e2964bed89c58825d80f602de19f214`。

**测试边界：** 本轮实际运行的是此前 852 步静态子集模拟器、附加寄存器快照记录以及新的恢复字节审计器。没有运行原生 Windows EXE，没有真实内核异常事件、SEH 链快照或者业务 OEP。

## 结果一：0x53D2EF 的目标字段地址并非猜测

从恢复镜像逐字节校验：

```asm
53D25F  mov edi,ebp
53D268  add edi,0x66
...
53D2A5  movzx edi,word ptr [edi]
...
53D2C3  add di,0xC74A
...
53D2DB  add edi,ebp
53D2ED  mov edi,dword ptr [edi]
53D2EF  mov edi,dword ptr [edi]
```

模型先前写入 `WORD[CTX+0x66]=0x38F1`，因此 `DI=(0x38F1+0xC74A)&0xFFFF=0x003B`。随后 `EDI=CTX+0x3B=0x4C19F7`。模型中 `DWORD[CTX+0x3B]=0x18`，导致第二次解引用地址为 `0x18`。

严格说来，这是**原生代码指令编码 + 条件性上下文字段值**联合构成的结论。原生程序的上下文字段值尚未实际采样。

## 结果二：一次模型内部完整性审计

原 852 步有 37 次写入：32 次上下文、5 次合成栈；条件跳转命中三次 `JBE`。本轮逐条统计模型中的操作：

| 操作类型 | 模型执行次数 |
|---|---:|
| MOV / MOVZX | 279 / 11 |
| ADD / SUB | 187 / 95 |
| XOR / OR / AND | 96 / 84 / 84 |
| CMP | 4 |
| JBE | 3 |
| SHL | 3 |
| INC、DEC、SHR | **均为 0** |

此前模拟器对 `INC/DEC` 以及位移的进位标志处理不够精确，但本轮三处 `JBE` 都跟随明确的 `CMP` 进行条件判断；在当前已验证前缀里，不能仅用这些未执行或不直接决定当前分支的标志处理缺陷来解释 `0x18`。仍不能保证整个 x86 子集模型的其他语义与真实 CPU 一致。

具体模型算术已验证：

```text
EAX 从编码指令流读取           0x7AEC651F
SUB EAX,[CTX+0x7E]           -0xE8480977 => 0x92A45BA8
SUB EAX,[CTX+0x09]           -0x92A45B90 => 0x00000018
ADD [CTX+0x7A],EAX          => 0x00000018
ADD [CTX+0x3B],ESI          => 0x00000018
MOVZX EDI,WORD [CTX+0x66]  => 0x38F1
ADD DI,0xC74A               => 0x003B
ADD EDI,EBP                 => CTX+0x3B
MOV EDI,[EDI]               => 0x00000018
MOV EDI,[EDI]               => [0x18]（研究模型未映射）
```

## 结果三：保护镜像确实具有 FS:[0] 异常链操作的**静态候选代码**

对完整恢复镜像进行严格字节检索：

| 原始字节编码 | 32 位 x86 意义 | 命中数量 |
|---|---|---:|
| `64 FF 35 00 00 00 00` | `push dword ptr fs:[0]` | 5 |
| `64 89 25 00 00 00 00` | `mov dword ptr fs:[0],esp` | 5 |
| `64 A3 00 00 00 00` | `mov fs:[0],eax` | 1 |
| `8B 3F 8B 3F` | 连续两次 `mov edi,[edi]` | 13 |

其中两处紧邻序列更有价值：

```asm
AAA446  push dword ptr fs:[0]
AAA44D  jmp  0xAAA452
AAA452  mov  dword ptr fs:[0],esp

AD0E54  push dword ptr fs:[0]
AD0E5B  jmp  0xAD0E60
AD0E60  mov  dword ptr fs:[0],esp
```

这两处表现出操作 x86 Windows 线程异常链头的代码模式，构成**此映像可能使用 SEH/异常驱动控制流**的具体静态证据。

**重要限制：** 尚未证明这两段在目标执行会话中被调用，也未识别负责接管 `0x53D2EF` 的实际异常处理器。即使确认程序中存在 SEH，也不等于证明低地址读取是刻意的反调试陷阱；模型错误或其他路径仍然可能。

## 下一轮应优先采集的 Windows 实机证据

在已保存快照的隔离 32 位 Windows VM 中，使用 WinDbg 32 位进程调试（对受到保护的软件，调试器本身可能改变执行路径）。建议**只观察，不补丁、不篡改寄存器或返回值**。

1. 启用访问冲突首次异常中断：`sxe av`，再 `.logopen /t C:\Temp\screenwings-p0-av.txt`。
2. 等待真正的异常。若它发生在目标模块 RVA `0x13D2EF`（首选 VA `0x53D2EF`；注意 ASLR），记录 `r`、`u @eip L4`、`k`、`!exchain`、`.exr -1`、`!teb`。
3. 若出现首次异常，要确认是否随后被线程的 SEH/其他处理器处理、控制流是否继续；只有**实机异常分派/恢复**能支持“故意异常做 VM 控制流”的进一步判断。
4. 如果进程根本没有进入 `0x53D2EF`，应优先比较 `0x5C3000`、`0x5C3033`、`0x5C3123` 的真实操作数和上一处理器入口寄存器；此时“模型偏差”优先于“故意异常”。

绝对地址应使用目标模块实际加载基址加 RVA：

| 静态 VA | 模块 RVA | 目的 |
|---|---|---|
| `0x5C3000` | `0x1C3000` | 第一项减法 |
| `0x5C3033` | `0x1C3033` | 第二项减法，生成 `0x18` |
| `0x5C3123` | `0x1C3123` | 写入上下文指针字段 |
| `0x53D2A5` | `0x13D2A5` | 从上下文 +0x66 读取偏移 |
| `0x53D2ED` | `0x13D2ED` | 第一层解引用 |
| `0x53D2EF` | `0x13D2EF` | 模型内第二层失效解引用 |

Windows 32 位 SEH 线程链的 `FS:[0]` 使用不能直接迁移到 64 位模式的异常模型；该目标是 32 位 PE，需要用适当的 32 位寄存器上下文分析。

## 重现实验

```bash
python3 tools/unpack_stage1.py samples/ScreenWings.exe --out analysis/stage1
python3 tools/audit_p0_pointer_seh.py analysis/stage1/schiffer_stage1.bin analysis/p0_model_memory_writes.csv --out analysis/p0_pointer_seh_audit.json
```

新工具校验镜像完整 SHA-256、12 处指定指令字节、37 条已有模型写入和 FS:[0] 序列的精确位置；不会调用、注入或执行目标 EXE。

**当前最严格的结论：** `CTX+0x3B` 目标字段的编码算法已恢复；SEH/异常控制流存在静态候选证据；**原始业务 OEP、真实异常控制流及 `SetWindowDisplayAffinity` 尚未证实。**
