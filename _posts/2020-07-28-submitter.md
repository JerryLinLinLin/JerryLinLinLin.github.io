---
title: Auto Submit False-Positive/Negative Files
date: 2020-06-23 00:00:00 -0500
categories: [Project, Software]
tags: [malware, fp, sample, threat]
---


## Intro

Malware researchers often encounter some AV vendors fail to detect a malware sample, or falsely flags a normal file as being malicious. To build an automatic process of reporting the FP/FN files, I wrote a python tool for compressing samples and submitting to AV vendors via email.

## Features

 - Automatically compress all files into a single encrypted zip.
 - Customizable Zip password and Email content.
 - Add/Remove items from Antivirus vendor list
 - Automatically save login info 
 - Send with one click
 - Multi-language support (English or Chinese Simplified)

 ## Screenshot

 ![Desktop View](https://github.com/JerryLinLinLin/SampleMailSubmitter/blob/master/screenshot/main_eng.png){: width="250" height="300"}
_Full screen width and center alignment_

## [View Project](https://github.com/JerryLinLinLin/SampleMailSubmitter)

## List of AV Vendors and Emails

| AV Vendor  | False-Negative       |False-Positive |
|:-----------------------------|:-----------------|--------:|
| Kaspersky  | newvirus@kaspersky.com     |- |
| ESET       | samples@eset.com       | samples@eset.com |
| Mcafee | virus_research@mcafee.com | virus_research@mcafee.com   |
| Bitdefender  | virus_submission@bitdefender.com     |virus_submission@bitdefender.com |
| Avira  | virus@avira.com     |novirus@avira.com |
| Emsisoft  | submit@emsisoft.com     |fp@emsisoft.com |
| Sophos  | samples@sophos.com     |samples@sophos.com |
