# Diving into HeadHunter, an Adversary Emulation Framework Written in C

<p align="center">
  <img src="https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/38a0993b-569d-4a87-9742-675d2759407f">
</p>

### A Bit of Background
HeadHunter is a project very dear to me. It started as a simple reverse shell multi-handler and reverse shell payload generator written in C while I was in high school. Through tons of work and passion, it quickly evolved as my own knowledge evolved, and my freshmen year of college, it was quickly transformed into an encrypted command and control framework. 

Although I’ve worked on this project for over a year, it’s far from finished. I’m constantly planning features for the project, including team play, stronger cryptographic algorithms for communications, and expansion of the C2 agent feature set.

### Project Description

HeadHunter is an adversary emulation framework and command & control (C2) server with asynchronous, beacon based encrypted communications.
HeadHunter also includes compatible custom agents and a server bundled agent generator with cross compilation capabilities.
HeadHunter has functionality to generate binary and shellcode agents for Windows 32- and 64-bit, and GNU/Linux based operating systems.
Once deployed, a Hunter agent will call back to the HeadHunter command and control infrastructure, requesting agent tasking from the operator until provided.
If no commands are provided, the agent will sleep and continuously beacon until the agent is provided with instructions.


### Installation 
Installation on HeadHunter should be relatively simple, as I’ve specifically developed HeadHunter to not utilize many dependencies, and most of the dependencies that I do list are optional or can be substituted, and simply expand the functionality of the project. Keep in mind that installing the various dependencies only takes a few moments and are highly recommended.

***Note that HeadHunter was specifically developed with the Kali Linux platform in mind, so using a Kali install will result in the least troublesome install process. ***
 
Before the installation process, install the various dependencies for the project, with this command:
```
sudo apt install mingw-w64 gcc make objdump
```

Then for the actual installation process:

1. Clone the repository
``` 
git clone https://github.com/Lionskey/HeadHunter.git
```

2. Change directory to source tree
``` 
cd HeadHunter/
```

3. Install HeadHunter binary and payload source
```
make && sudo make install
```

<br />

After the HeadHunter server binary is moved to path, and the agent source is moved into the HeadHunter program folder, you should be able to see the HeadHunter help options:

```
shellph1sh@kali:~/HeadHunter$ headhunter --help

Commands
--------------------------------------------------------
-h, --help                                             displays this help menu
-l, --listen <address> <port>                          starts a listening HeadHunter server on a specified address and port
-g, --generate <Payload Generation Options>            generates a Hunter agent to initiate a callback


Payload Generation Options
--------------------------------------------------------
-p, --port <port>                                      Hunter agent callback port
-o, --output <outputfile>                              file to output agent to
-w, --platform <platform>                              Hunter agent target platform (win64, win32, linux)
-f, --format <format>                                  Hunter agent output format (bin, shellcode)
-l, --localhost <address>                              Hunter agent callback address
```

<br />

Let’s see HeadHunter in action! First start up our HeadHunter listener on the loopback address: 127.0.0.1 and on port 443.

We can use the command:
```
headhunter -l 127.0.0.1 443
```


![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/5693faff-8a84-4611-8e78-36454840338e)

<br />

Now let’s generate an agent with the default encryption key from inside of the HeadHunter server console using the command:
```
headhunter -g -l 127.0.0.1 -p 443 -w linux -f bin -o Hunter
```

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/10fcba59-c191-4daf-b45f-f4fb639932b4)

<br />

Note that the HeadHunter operator can execute any shell command through the HeadHunter server console, providing flexibility for the operator.

<br />

Ok, now execute the compiled agent in another window, and if all goes well, we should receive a callback notifier in our C2 server console output.

```
shellph1sh@kali:~/HeadHunter$ ./Hunter&     
[1] 11284
                                                                                
shellph1sh@kali:~/HeadHunter$ 
```

<br />

And yes! HeadHunter notes that we’ve received a beacon connection from our compiled agent!

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/0cd4463b-9e10-49c7-b710-2cdc99fbbbee)


<br />

We can now enter the “show sessions” command, or “show” for short, to see active agent sessions, as well as how long it has been since they’ve checked in to the HeadHunter server.

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/de5460bb-36b5-43ed-a384-5659bb0251d5)

<br />

Utilize the “use” command to interact with an agent, passing the ID from the “show” command as a parameter. Note that we can now queue the agent with tasks to execute and receive output back. For example, we can execute system commands with the “shell” command, using the command we want to execute as a parameter:

![image](https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/561a5cf8-b731-4d8d-aadf-b69240aebe64)

<br />

That's all for the installation and simple demonstration.

Also note: HeadHunter can task the agent to change the default sleep timer setting depending on the objectives of the operation, with the ability to choose between a loud interactive session or a “low and slow” OPSEC safe operation. And the operator of the HeadHunter C2 server can background an agent session and interact with any session connected to the server infrastructure at the discretion of the operator.

### Conclusion
While I’m extremely happy with the state of the HeadHunter project, it lacks agent features and commands. Hopefully soon I’ll be able to integrate a multitude of Hunter agent commands and functionality, and possibly a stager for a more lightweight payload delivery process.

Thank you so much for following along, and contributions are greatly appreciated!


