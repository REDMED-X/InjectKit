# InjectKit
This repository contains modified versions of the Cobalt Strike Process Injection Kit. 

Since its introduction in version 4.5 (2021), the Cobalt Strike Process Injection Kit allows users to define their own process injection techniques. This is done through the `PROCESS_INJECT_SPAWN` and `PROCESS_INJECT_EXPLICIT` hook functions. These hooks enable users to define the execution flow of memory allocation, code writing, and execution for a significant number of the CS built-in post-exploitation commands.

Additional information and a complete list of the supported post-exploitation commands can be found here: [Controlling Process Injection](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2-extend_control-process-injection.htm). 


The goal of this project is to demonstrate how to implement various process injection techniques for this purpose. Therefore, the kits can be further enhanced with OPSEC best practices. 

>Additional variations/techniques will be added at a later time.  

## Kit content
The following process injection techniques are currently in the InjectKit: 

|Name|Description|
|----|----------|
|**[Tartarus Gate](KIT/TartarusGate)**|Indirect syscalls via the [Tartarus' Gate](https://github.com/trickster0/TartarusGate) method.|


## Usage
Each individual process injection kit has its own README file with additional information and compile instructions. 


