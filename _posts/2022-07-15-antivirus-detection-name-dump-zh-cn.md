---
title: 杀毒软件检测名称转储
date: 2022-07-15 17:30:00 -0500
categories: [Project, Antivirus]
tags: [malware, antivirus, reverse]
---

## 关于

本项目包含部分杀毒软件产品的恶意软件检测名称 CSV 文件，以及一个用于转储检测条目的 PowerShell 脚本。

## 开始使用

每个子文件夹包含带有供应商名称和日期的转储 CSV 文件。文件名以 BASE 结尾的文件包含来自供应商扫描引擎的名称，其他文件可能因检测来源（例如行为保护）而异。

### 先决条件

要运行 PowerShell 脚本：

1. 下载 [Windows Sysinternals](https://docs.microsoft.com/sysinternals/downloads/sysinternals-suite) 并将其添加到 `PATH` 环境变量中，或者从 [Microsoft Store](https://www.microsoft.com/p/sysinternals-suite/9p7knl5rwt25) 安装。

2. 使用 [PPLKiller](https://github.com/Mattiwatti/PPLKiller) 禁用 PPL (Protected Processes Light)，或者使用 Microsoft Windows 7（该系统不包含 PPL）。

3. 如果可能，请禁用杀毒软件的自我保护模块。

注意：要在 Windows 7 中运行此脚本，您可能需要 [更新 PowerShell](https://www.microsoft.com/download/details.aspx?id=54616)（v4.0 或更高版本）和 [.NET Framework](https://dotnet.microsoft.com/download/dotnet-framework)（v4.5 或更高版本）。

## 用法

`powershell -executionpolicy bypass -File .\AV_DUMP.ps1 <Name>`

## 支持的供应商列表

| 名称         | PPL | 需禁用自我保护 | 检测来源 | 准确度 |
| ------------ | --- | ------------------ | ---------------- | -------- |
| 火绒 (Huorong)      | 否  | 否                 | BASE             | 高     |
| 卡巴斯基 (Kaspersky)    | 是 | 是                | BASE, PDM        | 中   |
| Malwarebytes | 是 | 否                 | BASE, DDS        | 高     |

## [查看项目](https://github.com/JerryLinLinLin/AV_Detection_Dump)
