---
title: Huorong Advanced Threat Protection Rules
date: 2022-07-15 18:00:00 -0500
categories: [Project, Antivirus]
tags: [hips, huorong, antivirus]
---

## Introduction

Huorong Advanced Threat Protection Rules are written based on [MITRE ATT\&CK™](https://attack.mitre.org/) and malware behavioral characteristics. It can detect, block and intercept all kinds of malware, [Advanced Persistent Threat (APT)](https://zh.m.wikipedia.org/zh-hans/%E9%AB%98%E7%BA%A7%E9%95%BF%E6%9C%9F%E5%A8%81%E8%83%81) attack vectors and attack paths, such as fileless attacks, exploit attacks, crypto-ransomware, etc. It is also highly scalable, maintainable and community developer friendly.

## Install/Import rules

Download the [latest rule version](https://github.com/JerryLinLinLin/Huorong-ATP-Rules/releases/latest), unzip the file to get `Rule.json`, `Auto.json`. Open the main interface of Huorong -> Protection Center -> Advanced Protection -> Custom Rules, click the switch to enable, click the item -> Enter the advanced protection settings, in the custom rule settings interface -> Import -> Select `Rule.json` and in the Automatic processing settings interface -> Import -> Select `Auto.json`.

Please manually delete the old rules and re-import them when you update to a new version.

## Beginner's Guide

Import the rules as shown [in this figure](https://github.com/JerryLinLinLin/Huorong-ATP-Rules/blob/master/images/import_rules.jpg).

To prevent false positives, some rules are not enabled by default, please read the rule document and then choose to enable them.

## Rules Content

- MS Office Vulnerability Attack Protection
- Ransomware Protection
- Fileless Attack Protection
- Popular Malware Family Threat Prevention
- [... See the rule documentation for details](https://github.com/JerryLinLinLin/Huorong-ATP-Rules/blob/master/rules/README_en_us.md)

## Rules Directory

All rules are located in the `rules/` directory, with subfolders representing different rule groups, named after the `threat category. Behavior descriptions/virus families` are named, e.g. `Exploit.MSOffice`.

Each subdirectory contains the rule files `rule.json`, `auto.json`, which are the rule file for the current rule group and the corresponding auto processing file. Each rule is named after the current rule group `group name + letter`, e.g. `Exploit.MSOffice`.

The specific purpose of each rule can be found in `README_en_us.md` under each rule group folder, or in the root directory of `Rules`.

The directory structure is as follows

    .
    ├── Classification.Description1
    ├── Classification.Description2
    │   ├── rule.json
    │   ├── auto.json
    │   └── README.md
    └── README.md

## Automation Scripts

Located in the `scripts/` directory, it is used to automatically check the rule file format, export/merge all rule groups, generate rule description documents, etc. and is limited to this rule directory structure.

- `validate_rules.py` - Validation rules file, based on this [schema](https://github.com/JerryLinLinLin/Huorong-HIPS-Rule-Schema)

<!---->

    usage: validate_rules.py [-h] --path PATH

    optional arguments:
      -h, --help   show this help message and exit
      --path PATH  folder path to check

- `merge_rules.py` - Combine rules into one file for easy import.

<!---->

    usage: merge_rules.py [-h] --path PATH --output OUTPUT

    optional arguments:
      -h, --help       show this help message and exit
      --path PATH      rule folder path to merge
      --output OUTPUT  output folder path

- `md_parser.` py - Generate rule files.

<!---->

    usage: md_parser.py [-h] --path PATH

    optional arguments:
      -h, --help   show this help message and exit
      --path PATH  rule folder path to generate markdown

## Changelog

See the [release log](https://github.com/JerryLinLinLin/Huorong-ATP-Rules/releases/latest) for details

TO-DO: Add changelog.md

## Feedback/Contribution

Make sure you read the [contributing guidelines](https://github.com/JerryLinLinLin/Huorong-ATP-Rules/blob/master/CONTRIBUTING.md) before opening Issues or PR.


## [View Project](https://github.com/JerryLinLinLin/Huorong-ATP-Rules)
