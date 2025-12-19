---
title: 火绒高级威胁防护规则
date: 2022-07-15 18:00:00 -0500
categories: [Project, Antivirus]
tags: [hips, huorong, antivirus]
---

## 简介

火绒高级威胁防护规则基于 [MITRE ATT\&CK™](https://attack.mitre.org/) 和恶意软件行为特征编写。它可以检测、阻止和拦截各种恶意软件、[高级持续性威胁 (APT)](https://zh.m.wikipedia.org/zh-hans/%E9%AB%98%E7%BA%A7%E9%95%BF%E6%9C%9F%E5%A8%81%E8%83%81) 攻击向量和攻击路径，例如无文件攻击、漏洞利用攻击、加密勒索软件等。它还具有高度的可扩展性、可维护性，并且对社区开发者友好。

## 安装/导入规则

下载 [最新规则版本](https://github.com/JerryLinLinLin/Huorong-ATP-Rules/releases/latest)，解压文件得到 `Rule.json` 和 `Auto.json`。打开火绒主界面 -> 防护中心 -> 高级防护 -> 自定义规则，点击开关启用，点击该项 -> 进入高级防护设置，在自定义规则设置界面 -> 导入 -> 选择 `Rule.json`，在自动处理设置界面 -> 导入 -> 选择 `Auto.json`。

更新到新版本时，请手动删除旧规则并重新导入。

## 新手指南

如图 [所示](https://github.com/JerryLinLinLin/Huorong-ATP-Rules/blob/master/images/import_rules.jpg) 导入规则。

为了防止误报，某些规则默认未启用，请阅读规则文档，然后选择启用它们。

## 规则内容

- MS Office 漏洞攻击防护
- 勒索软件防护
- 无文件攻击防护
- 流行恶意软件家族威胁预防
- [... 详见规则文档](https://github.com/JerryLinLinLin/Huorong-ATP-Rules/blob/master/rules/README_en_us.md)

## 规则目录

所有规则都位于 `rules/` 目录下，子文件夹代表不同的规则组，以 `威胁类别.行为描述/病毒家族` 命名，例如 `Exploit.MSOffice`。

每个子目录包含规则文件 `rule.json`、`auto.json`，分别是当前规则组的规则文件和相应的自动处理文件。每条规则以当前规则组 `组名 + 字母` 命名，例如 `Exploit.MSOffice`。

每条规则的具体用途可以在每个规则组文件夹下的 `README_en_us.md` 中找到，或者在 `Rules` 的根目录中找到。

目录结构如下

    .
    ├── Classification.Description1
    ├── Classification.Description2
    │   ├── rule.json
    │   ├── auto.json
    │   └── README.md
    └── README.md

## 自动化脚本

位于 `scripts/` 目录下，用于自动检查规则文件格式、导出/合并所有规则组、生成规则说明文档等，仅限于此规则目录结构。

- `validate_rules.py` - 验证规则文件，基于此 [schema](https://github.com/JerryLinLinLin/Huorong-HIPS-Rule-Schema)

<!---->

    usage: validate_rules.py [-h] --path PATH

    optional arguments:
      -h, --help   show this help message and exit
      --path PATH  folder path to check

- `merge_rules.py` - 将规则合并为一个文件以便于导入。

<!---->

    usage: merge_rules.py [-h] --path PATH --output OUTPUT

    optional arguments:
      -h, --help       show this help message and exit
      --path PATH      rule folder path to merge
      --output OUTPUT  output folder path

- `md_parser.py` - 生成规则文件。

<!---->

    usage: md_parser.py [-h] --path PATH

    optional arguments:
      -h, --help   show this help message and exit
      --path PATH  rule folder path to generate markdown

## 更新日志

详情请参阅 [发布日志](https://github.com/JerryLinLinLin/Huorong-ATP-Rules/releases/latest)

TO-DO: 添加 changelog.md

## 反馈/贡献

在提交 Issue 或 PR 之前，请确保您已阅读 [贡献指南](https://github.com/JerryLinLinLin/Huorong-ATP-Rules/blob/master/CONTRIBUTING.md)。


## [查看项目](https://github.com/JerryLinLinLin/Huorong-ATP-Rules)
