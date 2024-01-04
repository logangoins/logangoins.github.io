# Diving into HeadHunter, an Adversary Emulation Framework written in C


<p align="center">
  <img src="https://github.com/shellph1sh/shellph1sh.github.io/assets/55106700/38a0993b-569d-4a87-9742-675d2759407f">
</p>

### A Bit of Background
HeadHunter is a project very dear to me. It started as a simple reverse shell multi-handler and reverse shell payload generator written in C while I was in high school. Through tons of work and passion, it quickly evolved as my own knowledge evolved, and my freshmen year of college, it was quickly transformed into an encrypted command and control framework. 

Although I’ve worked on this project for over a year, it’s far from finished. I’m constantly planning features for the project, including team play, stronger cryptographic algorithms for communications, and expansion of the C2 agent feature set.

### Project Description
```
HeadHunter is an adversary emulation framework and command & control (C2) server with asynchronous, beacon based encrypted communications. HeadHunter also includes compatible custom agents and a server bundled agent generator with cross compilation capabilities. HeadHunter has functionality to generate binary and shellcode agents for Windows 32- and 64-bit, and GNU/Linux based operating systems.
Once deployed, a Hunter agent will call back to the HeadHunter command and control infrastructure, requesting agent tasking from the operator until provided. If no commands are provided, the agent will sleep and continuously beacon until the agent is provided with instructions.
```

