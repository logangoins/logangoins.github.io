---
layout: post
title: Reflection
subtitle: Vulnlab writeup
thumbnail-img: https://assets.vulnlab.com/reflection_slide.png
share-img: https://assets.vulnlab.com/reflection_slide.png
tags: [Pentesting, Active Directory, Vulnlab]
---

# Introduction

Reflection is a medium difficulty Active Directory chain on the Vulnlab's platform, consisting of 3 machines: DC01, MS01, and WS01. This chain consists of a variety of realistic internal network penetration testing attack vectors and was incredibly enjoyable. The types of attack vectors required for successful exploitation include anonymous SMB bind abuse, MSSQL abuse, NTLM relay attacks, Windows Credential Vault harvesting, Resource-Based Constrained Delegation (RBCD), and finally credential reuse. While none of these attack vectors are particularly complex, the realism experienced when chaining them together in a believable and logical way was insanely rewarding.

# Enumeration

## DC01

From an nmap scan of DC01 we can confirm that it is in fact a domain controller. Most of the output is very standard, except for the fact that a MSSQL server is running on port `1433` and SMB signing is not enforced, potentially meaning an NTLM relay attack of some sort could be possible. 

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-01 23:12:39Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: reflection.vl0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000
|_ssl-date: 2024-06-01T23:13:27+00:00; +2s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-06-01T22:36:14
|_Not valid after:  2054-06-01T22:36:14
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: reflection.vl0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=dc01.reflection.vl
| Not valid before: 2024-05-31T22:33:21
|_Not valid after:  2024-11-30T22:33:21
|_ssl-date: 2024-06-01T23:13:26+00:00; +1s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  adws?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1s, deviation: 0s, median: 0s
| smb2-time: 
|   date: 2024-06-01T23:13:25
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
```

The nmap scan of MS01 is also pretty standard, mainly telling us MSSQL is running on port `1433` just like the DC, and RDP on `3389` and WinRM on `5985` are both available for potentially remote control of the device if we gather user credentials. 

## MS01
```
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
445/tcp  open  microsoft-ds?
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   10.10.192.246:1433: 
|     Target_Name: REFLECTION
|     NetBIOS_Domain_Name: REFLECTION
|     NetBIOS_Computer_Name: MS01
|     DNS_Domain_Name: reflection.vl
|     DNS_Computer_Name: ms01.reflection.vl
|     DNS_Tree_Name: reflection.vl
|_    Product_Version: 10.0.20348
|_ssl-date: 2024-06-01T22:54:44+00:00; +2s from scanner time.
| ms-sql-info: 
|   10.10.192.246:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-06-01T22:33:46
|_Not valid after:  2054-06-01T22:33:46
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=ms01.reflection.vl
| Not valid before: 2024-05-31T22:33:21
|_Not valid after:  2024-11-30T22:33:21
|_ssl-date: 2024-06-01T22:54:44+00:00; +2s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: REFLECTION
|   NetBIOS_Domain_Name: REFLECTION
|   NetBIOS_Computer_Name: MS01
|   DNS_Domain_Name: reflection.vl
|   DNS_Computer_Name: ms01.reflection.vl
|   DNS_Tree_Name: reflection.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2024-06-01T22:54:04+00:00
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-06-01T22:54:07
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 1s, deviation: 0s, median: 1s
```

Pretty much the same thing with WS01. The nmap scan looks pretty standard with RDP enabled being the only thing that stands out for the same reason as MS01. 

## WS01
```
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=ws01.reflection.vl
| Not valid before: 2024-05-31T22:35:52
|_Not valid after:  2024-11-30T22:35:52
| rdp-ntlm-info: 
|   Target_Name: REFLECTION
|   NetBIOS_Domain_Name: REFLECTION
|   NetBIOS_Computer_Name: WS01
|   DNS_Domain_Name: reflection.vl
|   DNS_Computer_Name: ws01.reflection.vl
|   DNS_Tree_Name: reflection.vl
|   Product_Version: 10.0.19041
|_  System_Time: 2024-06-01T23:37:04+00:00
|_ssl-date: 2024-06-01T23:37:44+00:00; +1s from scanner time.
5040/tcp open  unknown
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-06-01T23:37:05
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
```

## SMB Enumeration

After a generic nmap scan of each device, I began enumerating each devices SMB service, testing for anonymous access and null bindings. Weirdly enough, Netexec didn't have permissions to display the SMB shares anonymously, but smbclient was able to. 

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/d0286b3e-8cf2-40cf-8971-b0b4a9a3f10e)

<br />

In the staging share I then found database credentials, likely for the MSSQL service on MS01.

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/ab57bec2-7ce9-43ca-90b8-6918101695ed)

<br />

Next I tested the credentials and authenticated to MS01's MSSQL service.

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/eb3ed030-b94f-4481-94f9-617b242f1d51)

<br />

## MSSQL And The Power Of SMB Signing

Now that we've fully authenticated to the MSSQL service, I've had the name of the chain: "Reflection" and the fitting fact that signing is disabled on the DC in the back of my head the whole time. I've known that some sort of relay attack was going to be required since the beginning, but I wasn't super sure when.

When enumerating the MSSQL database, I found some testing dev accounts, but when trying them on the domain they were invalid, leading me to realize that I could `xp_dirtree` to send my attacker host NTLM authentication and relay it to the DC to potentially read SMB share information. 

First I set up a relay server with `ntlmrelayx`:

```
ntlmrelayx.py -t dc01.reflection.vl -smb2support -i 
```

Then I sent the authentication request

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/92000f6d-8549-4481-a1d3-07b5b9f4240f)

<br />

Looking back at the relay server, we've received authentication and successfully relayed those credentials to the DC

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/36e9f5a3-a912-49fb-bed9-e1c41e96687b)

<br />

Now we can use netcat to interact with the SMB service on the DC. There appears to be a production share, with another DB configuration file inside.

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/d4f45ee8-0814-4488-a336-a58880eb3677)

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/353764e1-556d-4a17-b9bd-3e91d087200b)

<br />

We once again find credentials for the MSSQL service, this time on the DC

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/8e4aeae8-75d1-45a0-a80b-2a4cd03d0782)

<br />

After we ensure we can successfully authenticate, looking around yields us some users, and as this is a production database its assumed these users are active domain users

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/aca96aba-8422-40de-853d-88b8dcba02c2)

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/9be55ac2-90a5-44dd-8023-71290fcfbd72)

<br />

## Credentialed Domain Enumeration

After confirming through a tool such as Netexec that these users are truly domain users, we can then use their access to launch a bloodhound scan.

```
bloodhound-python -u abbie.smith@reflection.vl -p 'CMe1x+nlRaaWEw' -ns 10.10.192.245 -c All --zip 
```

One of the major things that I note is that our current user `abbie.smith` has generic write over MS01

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/c6760547-409d-4377-9210-f0524cbe324d)

<br />

## MS01 Initial Access

The very first thing which comes to mind is modifying the msDS-AllowedToActOnBehalfOfOtherIdentity to takeover the device, otherwise known as Resource-Based Constrained Delegation (RBCD), but unfortunately RBCD requires an SPN to carry out the full attack, usually a computer account, which I don't have access to. 

I decided to make a bold assumption and guess that the Local Administrator Password Solution (LAPS) is enabled on this domain, and was able to read the local administrator password through the GenericAll permission with Netexec through the `abbie.smith` account.

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/a7e3fffb-4bac-4121-a6b5-62e7b6a374ec)

<br />

When checking our local administrator credentials against MS01 with wmiexec we successfully authenticate

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/f758c89b-732d-4467-be48-a3084ac093bc)

<br />

## MS01 Post Exploitation

I knew that I had to use some aspect of MS01 to pivot to the other machines in the chain, so my immediate thought was credential harvesting using tools like Mimikatz. Dumping LSASS and SAM provided me with no further credentials. Although I did end up noticing a scheduled task being executed as the Georgia.Price user. This means their credentials would be stored in the Windows Credential Vault, which can also be dumped with Mimikatz. 

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/baad0259-3ae6-43c4-a909-d7f447b1f6e1)

<br />

Using these credentials with bloodhound conveniently shows that Georgia.Price has GenericAll over the second device in the chain, WS01.

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/e7be3ffe-88f6-4c1f-8db0-ff0cc650e55e)

<br />

## WS01 Initial Access

The very first thing I attempted was reading the LAPS password on WS01 using Georgia.Price's credentials, unfortunately, LAPS was not configured on WS01. No matter, because we can utilize the computer account of MS01 that we compromised (A SPN) to exploit Resource-Based Constrained Delegation (RBCD) on WS01. 

First write the msDs-AllowedToActOnBehalfOfOtherIdentity LDAP attribute using rbcd.py
```
rbcd.py -delegate-from 'MS01$' -delegate-to 'WS01$' -dc-ip '10.10.147.85' -action 'write' 'reflection.vl'/'Georgia.Price':'DBl+5MPkpJg5id'
```
![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/d6554569-c0c9-40b5-af0b-6299389bac89)

<br />

Next we have to request a service ticket while impersonating Administrator with `getST.py`

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/20d42db1-fe82-4fcc-bbcb-a717b1c1f84f)

<br />

Now once we use this ticket to authenticate with Netexec we find that we hold Administrator permissions over WS01

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/328f6792-a16e-477d-be1d-133ff0684a88)

<br />

## WS01 Post Exploitation

When quickly dumping LSA secrets from WS01, we find a new users credentials stored: `Rhys.Garner`

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/ba87ea23-35e6-4ea1-9a37-8831a51ec834)

<br />

## Getting Domain Admin

This user didn't have any special domain privileges or anything leading to full domain compromise unfortunately, so I kept looking into credential harvesting on WS01 for a long time yielding nothing. After a while I started looking at general domain information again to try and see anything I might have missed before. That's when I noticed the domain admin user, `dom_rgarner` again. For a while I wasn't sure exactly what this naming convention meant, then I started looking at it in the context of the just compromised `Rhys.Garner` user. 

I realized the `dom` prefix was short for domain, indicating the span of user privilege, and `rgarner` being a `[firstletter][lastname]` format for the `Rhys.Garner` user. Just out of desperation I tested the underprivileged account privileges on Rhys's Administrator account and they worked! Rhys had reused their credentials.

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/968dec1d-a160-4bfe-9e8a-563a5bd0ae35)

<br />