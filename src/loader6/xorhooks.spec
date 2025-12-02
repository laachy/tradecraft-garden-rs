#
# This script handles merging our hooks code with the hooks PICO, registering hooks.
#
 
x86:
    # load our XOR hooks and merge with the hooks PICO
    load "bin/xorhooks.x86.o"
        merge
 
    # export our confighooks function, which is necessary for setup later
    exportfunc "_confighooks" "___tag_confighooks"
 
    # generate a 128B key for our hook module
    generate $HKEY 128
 
    # patch that key into our PICO
    patch "_xorkey" $HKEY
 
    # add __MessageBoxA@16 as a hook for USER32$MessageBoxA
    addhook "USER32$MessageBoxA"      "__MessageBoxA@16"
 
    # remove registered hooks for functions not imported by $DLL
    filterhooks $DLL
 
x64:
    load "bin/rs/xorhooks.x64.o"
        merge
 
    exportfunc "confighooks" "__tag_confighooks"
 
    generate $HKEY 128
    patch "xorkey" $HKEY
 
    addhook "USER32$MessageBoxA"      "_MessageBoxA"
    filterhooks $DLL