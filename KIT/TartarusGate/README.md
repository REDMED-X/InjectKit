# Tartarus' Gate
Process Injection Kit leveraging indirect syscalls via the [Tartarus' Gate](https://github.com/trickster0/TartarusGate) method.  

>This implementation only supports X64 process injection. 

## Compile and usage
- 1\. Run the `Makefile` to compile both the SPAWN and EXPLICIT \*.x64.o object files: `make`
- 2\. To use the kit, either load the `injectkit.cna` script in Cobalt Strike using the script manager OR replace/add the compiled \*.x64.o files to the `arsenal-kit\dist\process_inject` directory and load the default `arsenal_kit.cna` script that has the Process Injection Kit enabled. 
- 3\. It is now possible to run the supported post-exploitation commands using the modified process injection technique. 

## Acknowledgements
The implemenation of the [Tartarus' Gate](https://github.com/trickster0/TartarusGate) method is based on the [Tartarus-TpAllocInject](https://github.com/nettitude/Tartarus-TpAllocInject) project from [LRQA Nettitude](https://github.com/nettitude). 