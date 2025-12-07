#
# XorHooks Hooking Module
#
 
#
# Linker directives to setup our XOR hooks tradecraft. Surprise: not much to do in this simple example
#
setup.x86:
    # load our XOR hooks and merge with the main PIC? PICO?
    load "bin/xorhooks_setup.x86.o"
        merge
 
    # layer this module's setup function onto the setup hooks function. Note: if we only ever intended
    # one function here... we're better off with merge. But, for many:1 layering, redirect is the tool.
    redirect "_setupHooks" "_setupHooksXor"
 
setup.x64:
    load "bin/rs/xorhooks_setup.x64.o"
        merge
 
    redirect "setupHooks" "setupHooksXor"
 
#
# register our hooks within the hooks PICO
#
hooks.x86:
    # load our XOR hooks and merge with the hooks PICO
    load "bin/xorhooks.x86.o"
        merge
 
    # export our confighooks function. This allows _setupHooksXor to pass needed information to us from 
    # the loader's context.
    exportfunc "_confighooksXor" "___tag_confighooksXor"
 
    # generate a 128B key for our hook module
    generate $HKEY 128
 
    # patch that key into our PICO
    patch "_xorkey" $HKEY
 
    # tell __resolve_hook to return the attach chain function for USER32$MessageBoxA. We
    # *could* specify a function here directly too, but this form allows us to benefit
    # from layering attach'd functions over a Win32 API
    addhook "USER32$MessageBoxA"
 
    # attach _MessageBoxA function to USER32$MessageBoxA calls
    attach "USER32$MessageBoxA" "__xMessageBoxA@16"
 
hooks.x64:
    load "bin/rs/xorhooks.x64.o"
        merge
 
    exportfunc "confighooksXor" "__tag_confighooksXor"
 
    generate $HKEY 128
    patch "xorkey" $HKEY
 
    addhook "USER32$MessageBoxA"
    attach "USER32$MessageBoxA" "_xMessageBoxA"

    disassemble "xor.txt"
