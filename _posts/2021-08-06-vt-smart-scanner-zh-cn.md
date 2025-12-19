---
title: Virus Total 智能扫描器现已开源
date: 2021-08-06 00:00:00 -0500
categories: [Project, Antivirus]
tags: [malware, scanner, vt]
---

## 简介

Virus Total Smart Scanner 是一个可以对任意给定目录执行文件扫描的工具。它具有基本的扫描功能和实现，例如文件类型识别、规则匹配、缓存管理以及简洁的用户界面。

扫描结果（文件是否恶意）基于 Virus Total 上几家受信任供应商的检测结果。它可以集成到上下文菜单中以执行右键扫描，或者通过文件哈希值打开 Virus Total 页面进行手动文件检查。

![截图](https://raw.githubusercontent.com/JerryLinLinLin/VirusTotalSmartScanner/master/screenshot.png)

## 特别说明

Virus Total Smart Scanner 是我在 2018 年的高中实验项目。它最初发布在 [卡饭安全论坛](https://bbs.kafan.cn/thread-2133049-1-1.html)。那已经是差不多三年前的事了，我决定将其开源。

该项目的结构不是很好，但功能还可以。它的目的是展示通过窃取 Virus Total 上著名供应商的检测结果（所谓的“云检测”）来制作反病毒扫描器是多么容易。许多懒惰和不负责任的供应商选择这种方法来使他们的检测率看起来“很棒”，但这可能会产生大量不可靠的检测和误报，从而损害整个反病毒社区。

## 功能亮点

- 高检测率，低误报率：仅获取谨慎厂商的识别结果，减少误报，避免看到一堆奇怪且难以理解的名称。
- 准确分类，让您了解威胁类型。
- 右键菜单集成，您可以一键扫描需要扫描的文件夹，省时省力。
- 自动识别 PE 文件，节省扫描时间。
- 可选：自动上传未知文件。
- 您可以选择开启/关闭 PUA 检测。
- 可自定义多引擎报告阈值。

## 受信任供应商列表

`Kaspersky`
`ESET-NOD32`
`Malwarebytes`
`Microsoft`

## 检测名称列表

| Detection              |
|------------------------|
| Grayware.Unwanted      |
| Grayware.RiskTool      |
| Grayware.CoinMiner     |
| Phishing.Generic       |
| Exploit.Generic        |
| Worm.Generic           |
| Ransom.Generic         |
| Rootkit.Generic        |
| Backdoor.Bot           |
| Backdoor.Generic       |
| Trojan.Banker          |
| Trojan.Spy             |
| Trojan.Downloader      |
| Trojan.PasswordStealer |
| Trojan.Dropper         |
| Trojan.Script          |
| Trojan.Injector        |
| Trojan.Generic         |
| Malware.Confidence%    |

## 使用方法

下载并解压 zip 文件。运行 `VTScanner.exe`。

## 故障排除

- 如果在扫描过程中遇到“获取报告失败”或“上传失败”等提示，请检查您的网络连接；如有必要，请准备自己的代理服务器。
- 如果长时间卡在扫描过程中，可能是因为 API 请求次数已达到限制（VTAPI 限制为 4 次/分钟），请稍候。
- 软件内置了 API，但仍建议您填写自己的 API（在 VT 官网注册 -> 设置 -> APIkey 免费获取 API）。
- 日志存储在程序目录\log 文件夹中，主界面上有一个按钮可以直接打开它。
- 上传未知文件后，需要等待 VT 云端完成，此过程较慢，请稍候。

## 贡献

我不打算再开发这个项目了。欢迎您 fork 并自行开发。

## 许可证

有关许可权利和限制 (MIT)，请参阅 [LICENSE](https://github.com/JerryLinLinLin/VirusTotalSmartScanner/blob/master/LICENSE) 文件。

## [查看项目](https://github.com/JerryLinLinLin/VirusTotalSmartScanner)
