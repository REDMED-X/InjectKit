# InjectKit
Since its introduction in version 4.5 (2021), the Cobalt Strike Process Injection Kit allows users to define their own process injection techniques. This is done through the `PROCESS_INJECT_SPAWN` (fork&run) and `PROCESS_INJECT_EXPLICIT` (remote injection) hook functions. These hooks enable users to define the execution flow of memory allocation, code writing, and execution for a significant number of the Cobalt Strike built-in post-exploitation commands like `keylogger`, `screenshot`, and `mimikatz`.

Additional information and a complete list of the supported post-exploitation commands can be found here: [Controlling Process Injection](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2-extend_control-process-injection.htm). 

This project's goal is to showcase the application of the Process Injection Kit, which is utilized across a broad spectrum of Cobalt Strike's built-in commands. Moreover, the custom kits in this repository offer the potential for further refinement by integrating OPSEC best practices.

>Additional variations/techniques will be added at a later time.  

## Kit content
The following process injection techniques are currently in the InjectKit: 

|Name|Description|
|----|----------|
|**[Tartarus Gate](KIT/TartarusGate)**|Indirect syscalls via the [Tartarus' Gate](https://github.com/trickster0/TartarusGate) method.|


## Usage
Each individual process injection kit has its own README file with additional information and compile instructions. 


