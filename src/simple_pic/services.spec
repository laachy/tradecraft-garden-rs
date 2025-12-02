#
# This file is includable in other projects to bring PIC bootstrap services there
# Use: run "path/to/services.spec"
 
x86:
    # load our x86 PIC services module and merge it into our parent
    load "bin/services.x86.o"
        merge
 
    # OPT into x86 program fixes to allow data references without code hacks
    fixptrs "_caller"
 
    # fix the .bss section to give us some globals again
    fixbss "_getBSS"
 
    # OPT into PIC dynamic function resolution
    # * _resolve is for modules that we know are loaded
    # * punt anything else over to _resolve_ext so we can load the module (if needed)
    dfr "_resolve" "ror13" "KERNEL32, NTDLL"
    dfr "_resolve_ext" "strings"
 
x64:
    load "bin/c/services.x64.o"
        merge
 
    fixbss "getBSS"
 
    dfr "resolve" "ror13" "KERNEL32, NTDLL"
    dfr "resolve_ext" "strings"