#
# configure the stackcutting hooks (this is to be merged in with our hooks PICO, right?)
#
x86:
    # load our XOR hooks and merge with the hooks PICO
    load "bin/stackcut.x86.o"
        merge
 
    # export our confighooks function, which is necessary for setup later
    exportfunc "_configstackcutting" "___tag_configstackcutting"
 
    # add our hooks
    addhook "KERNEL32$LoadLibraryA"   "__LoadLibraryA@4"
    addhook "KERNEL32$Sleep"          "__Sleep@4"
    addhook "KERNEL32$VirtualAlloc"   "__VirtualAlloc@16"
    addhook "KERNEL32$VirtualProtect" "__VirtualProtect@16"
    addhook "USER32$MessageBoxA"      "__MessageBoxA@16"
     
    # remove registered hooks for functions not imported by $DLL
    filterhooks $DLL
 
    # hook GetProcAddress to propgate our hooks to capability our DLL might load
    addhook "KERNEL32$GetProcAddress" "__GetProcAddress@8"
 
x64:
    load "bin/rs/stackcut.x64.o"
        merge

    disassemble "sccc"
 
    exportfunc "configstackcutting" "__tag_configstackcutting"
 
    addhook "KERNEL32$LoadLibraryA"   "_LoadLibraryA"
    addhook "KERNEL32$Sleep"          "_Sleep"
    addhook "KERNEL32$VirtualAlloc"   "_VirtualAlloc"
    addhook "KERNEL32$VirtualProtect" "_VirtualProtect"
    addhook "USER32$MessageBoxA"      "_MessageBoxA"
    filterhooks $DLL
    addhook "KERNEL32$GetProcAddress" "_GetProcAddress"