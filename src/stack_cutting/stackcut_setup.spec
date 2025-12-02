x86:
    # load+merge our stackcutting initialization logic
    load "bin/stackcut_setup.x86.o"
        merge
 
    # load+merge our stackcutting hooks... because this is where our globals are too
    load "bin/stackcut.x86.o"
        merge
 
    # load our proxy PIC as a resource.
    load "bin/proxy.x86.o"
        # This is PIC but we're not bothering with dfr, fixptrs, and +gofirst. It's not needed here. This PIC is 
        # a simple one-off call gate function.
        make pic
        export
        preplen
        link "my_proxy"
 
    # protect _SetupProxy from getting hooked... because we don't want to try to use stack cutting before stack 
    # cutting is setup... know what I mean?
    protect "_SetupProxy"
 
    # WHY yes... we can HOOK our loader PIC with the same hook code used in our IAT hooking. This is one of the 
    # reasons I wanted to merge our stack cutting hooks into this loader/setup module too. They do double duty now :)
 
    attach "KERNEL32$LoadLibraryA"   "__LoadLibraryA@4"
    attach "KERNEL32$Sleep"          "__Sleep@4"
    attach "KERNEL32$VirtualAlloc"   "__VirtualAlloc@16"
    attach "KERNEL32$VirtualProtect" "__VirtualProtect@16"
    attach "USER32$MessageBoxA"      "__MessageBoxA@16"
 
    # I've listed all of our hooks here, but in practice VirtualAlloc and LoadLibraryA are what's kept and used here. 
    # But, hey... transparent stack tradecraft in a PIC DLL loader that's applying stack tradecraft to a DLL is
    # pretty damned cool, right?
    #
    # To what's kept after link-time optimization, uncomment this line. It's also a good opportunity to look at how
    # and where _LoadLibraryA and _VirtualAlloc are called. You'll see they're just weaved into the program
    #disassemble "setup.x86.txt"
 
x64:
    load "bin/rs/stackcut_setup.x64.o"
        merge
 
    load "bin/rs/stackcut.x64.o"
        merge

    load "bin/rs/proxy.x64.o"
        make pic
        export
        preplen
        link "my_proxy"
 
    protect "SetupProxy"
 
    attach "KERNEL32$LoadLibraryA"   "_LoadLibraryA"
    attach "KERNEL32$Sleep"          "_Sleep"
    attach "KERNEL32$VirtualAlloc"   "_VirtualAlloc"
    attach "KERNEL32$VirtualProtect" "_VirtualProtect"
    attach "USER32$MessageBoxA"      "_MessageBoxA"
 
    