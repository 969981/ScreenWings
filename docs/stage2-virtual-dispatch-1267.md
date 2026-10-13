# ScreenWings 2.16.1430：第二层 1,267 项重定位表与虚拟化分派器

日期：2026-10-13。此研究只基于已上传的样本及其第一层 aPLib 恢复镜像，**未启动 Windows EXE，未取得真实 HWND 或 user32 API 调用日志**。

## 原始数据身份

- ScreenWings.exe：4,159,512 字节，SHA-256 `481ecd41bef2a33076729680747eb92e4e2964bed89c58825d80f602de19f214`
- `schiffer_stage1.bin`：6,758,400 字节，映射 VA `0x492000`，SHA-256 `2a1185bbcc93a049d413a71104ed41623bae61cf2412de5ea015564ea8b4d420`
- 原始 PE ImageBase：`0x400000`

## 突破一：第二张控制流重定位表

第一张表位置 `0x60976C`，43 项、172 字节、19 组。其 E9 跳转的目标均从 `PUSHF` 开始。

新定位的第二张表则位于 **`0x6471D3`**，结束地址（不含）**`0x64859F`**。其 5,068 字节 SHA-256 为：

`2d87b174e89203dc01cb9db41c22d3b4a5738af9e4dd1918fe809dd7ed844692`

直接反汇编控制路径（需结合入口状态而非孤立反汇编）：

```asm
63C500  mov ebp,0x13CC            ; table bytes = 5068
63C520  shr ebx,2                 ; 5068/4 = 1267 DWORDs
63C53E  test ebx,ebx
63C540  je 63C5BB
63C55F  add dword ptr [ebx],ecx  ; add ImageBase
63C589  add eax,edx              ; EDX = 4, advance table cursor
63C5B6  jmp 63C53E
```

独立读取 1,267 个原始 DWORD：

- 1,267 个 RVA 加上映像基址后，全都指向**不同的** `E9 rel32` 指令；
- 跳转目标全部在恢复区范围之内，且 1,267 个目的地址互不重复；
- 按 VA 排序形成 **230 个**连续跳转桩区域；
- 与上一张 43 项表没有地址重合；
- 目的地首字节最常见的是 `0x89`（648 项）与 `0x81`（166 项），而**不是**前一张表统一的 `PUSHF`。

可检验的完整输出：[`stage2_reloc1267.csv`](../analysis/stage2_reloc1267.csv) 和 [`stage2_reloc1267_clusters.csv`](../analysis/stage2_reloc1267_clusters.csv)。

### 静态模型的控制流对照

使用仅实现部分 x86 指令、保护原始文件不变的受限状态模拟器，三组不同初始寄存器种子（0、1、42）均取得一致结果：

| 事件 | 模型指令步数 | EAX | EBX | ECX |
|---|---:|---|---|---|
| 第二张表循环入口 | 2,429 | `0x6471D3` | `0x4F3` | `0x400000` |
| 第二张表循环完成 | 54,378 | `0x64859F` | `0` | `0x400000` |

**重要：这里的步数是研究模型的模拟结果，并非真实 Windows 进程中的执行记录。** 对地址表存在性的证明无需依赖该模型，可以独立从第一层恢复镜像读取校验。

## 突破二：找到大表的实际查表与间接跳转消费者

位于 `0x541EA7–0x541ED7` 的原生代码：

```asm
541EA7 mov cx,word ptr [edi]
541EAA shl ecx,2
...
541EBD mov eax,dword ptr [ebx]
541EC7 add dword ptr [ebx],eax
...
541ED1 mov ebx,dword ptr [edx]
541ED3 add ebx,ecx
541ED5 mov edx,dword ptr [ebx]
541ED7 jmp edx
```

与模拟器推导的上下文 `EBP=0x4C19BC` 对应：

- `[EBP+0x22]`：指向编码指令流的**候选指针字段**；
- `[EBP+0x52]`：保护层分派表指针字段，重定位后为 `0x6471D3`；
- 第一次指令流候选 VA `0x4AAD06`；其首 WORD 为 `0x0323`（803）；
- `803*4 = 0xC8C`，表项 VA `0x647E5F`；
- 第 803 项是 `0x4F464D`，这条 E9 的目标是 **`0x4DB0E0`**；
- `[0x4AAD0A]=0x000BF0BD`，指令流指针加上该值成为 **`0x569DC3`**。

这里已经建立了**代码引用的原生消费者 → 原始数据字节 → 确定的跳转目标**的关联，摆脱了此前的单纯 E9 字节频率分析。

## 突破三：连续第二次分派

在 `0x4DB0E0` 开始的 handler 中又有：

```asm
4DB0F0 movzx edx,word ptr [edi]
4DB0F3 add edx,ebp
4DB0F5 mov dword ptr [edx],esp
4DB10C mov dx,word ptr [ebx]
4DB10F shl edx,2
...
4DB134 mov eax,dword ptr [ebx]
4DB136 add eax,edx
4DB138 mov edx,dword ptr [eax]
4DB13A jmp edx
```

当候选指令流推进到 `0x569DC3` 后：

| 读取值 | 数值 | 关联 |
|---|---|---|
| `WORD[VIP]` | `0x000D` | `[EBP+0x0D]` 保存栈指针 |
| `WORD[VIP+2]` | `0x023A` (570) | 第二次 selector |
| `DWORD[VIP+4]` | `0xFFF7A1AF` | 带回绕的指令流指针增量 |
| 大表第 570 项 | `0x496308` | E9 跳转桩 |
| 该 E9 的目标 | `0x5303F3` | 下一个 handler |
| 下一候选 VIP | `0x4E3F72` | 后续编码指令数据地址 |

这些实际字节和原生查表序列，与“虚拟化指令流 / threaded dispatcher”解释相符。它**仍然属于保护层内部机制**，不等于 1,267 个业务 Hook，且未获得原应用 OEP。

## 可复现命令

```bash
python3 tools/unpack_stage1.py samples/ScreenWings.exe --out analysis/stage1
python3 tools/extract_stage2_reloc1267.py analysis/stage1/schiffer_stage1.bin --out analysis/stage2_reloc1267
python3 tools/verify_stage2_dispatch.py analysis/stage1/schiffer_stage1.bin --out analysis/stage2_dispatch.json
```

两份新的 Python 工具均对完整恢复区 SHA-256 做强校验，并检查对应原生指令及 E9 目标，**不会加载或执行 EXE**。

## 下一步研究优先级

目前找到了保护层虚拟化分派器，而不是 Windows 窗口保护业务代码。继续遍历虚拟指令处理器有意义，但解密和原始应用控制流交接尚缺少确定入口。下一步应以**原始 PE 的可执行页变化、分派器出口、实际载入模块及 API 解析**作为重点；在隔离 Windows VM 上记录初始化前后私有执行页、模块、原始窗口句柄、`SetWindowDisplayAffinity` 调用/标志和 GUI 保护开关差异。

**未证实的结论：** 原始业务入口、`CreateWindowEx`、`SetWindowDisplayAffinity`、`WDA_MONITOR`、`WDA_EXCLUDEFROMCAPTURE`、截图 Hook 或全屏透明覆盖窗口。对这些结果不能凭保护层虚拟机机制推断。
