---
title: 自动提交误报/漏报文件
date: 2020-07-28 00:00:00 -0500
categories: [Project, Software]
tags: [malware, fp, sample, threat]
---


## 简介

恶意软件研究人员经常遇到一些杀毒软件厂商未能检测到恶意软件样本，或者错误地将正常文件标记为恶意文件的情况。为了建立一个自动报告误报/漏报文件的流程，我编写了一个 Python 工具，用于压缩样本并通过电子邮件提交给杀毒软件厂商。

## 功能特点

 - 自动将所有文件压缩成一个加密的 zip 文件。
 - 可自定义 Zip 密码和邮件内容。
 - 添加/删除杀毒软件厂商列表中的项目。
 - 自动保存登录信息。
 - 一键发送。
 - 多语言支持（英语或简体中文）。

## 截图


 ![Desktop View](https://raw.githubusercontent.com/JerryLinLinLin/SampleMailSubmitter/master/screenshot/main_eng.png){: width="500" height="600" style="max-width: 70%" .normal}

## [查看项目](https://github.com/JerryLinLinLin/SampleMailSubmitter)

## 杀毒软件厂商及邮箱列表

| 杀毒软件厂商  | 漏报 (False-Negative)       |误报 (False-Positive) |
|:-----------------------------|:-----------------|:--------|
| Kaspersky  | newvirus@kaspersky.com     |- |
| ESET       | samples@eset.com       | samples@eset.com |
| Mcafee | virus_research@mcafee.com | virus_research@mcafee.com   |
| Bitdefender  | virus_submission@bitdefender.com     |virus_submission@bitdefender.com |
| Avira  | virus@avira.com     |novirus@avira.com |
| Emsisoft  | submit@emsisoft.com     |fp@emsisoft.com |
| Sophos  | samples@sophos.com     |samples@sophos.com |
