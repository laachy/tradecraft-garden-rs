#
# some helper labels, since we specify the attach functions twice.
#
attach.x86:
    # attach Win32 API interests to our hook functions
    attach "KERNEL32$LoadLibraryA"   "__cLoadLibraryA@4"
    attach "KERNEL32$Sleep"          "__cSleep@4"
    attach "KERNEL32$VirtualAlloc"   "__cVirtualAlloc@16"
    attach "KERNEL32$VirtualProtect" "__cVirtualProtect@16"
    attach "USER32$MessageBoxA"      "__cMessageBoxA@16"
 
    # since this is a terminal hooking (e.g., we expect DIRECT access to the Win32 API), I'm using protect to prevent
    # anything else from hooking/incepting our hook functions themselves
    protect "__cLoadLibraryA@4, __cSleep@4, __cVirtualAlloc@16, __cVirtualProtect@16, __cMessageBoxA@16"
 
attach.x64:
    attach "KERNEL32$LoadLibraryA"   "_cLoadLibraryA"
    attach "KERNEL32$Sleep"          "_cSleep"
    attach "KERNEL32$VirtualAlloc"   "_cVirtualAlloc"
    attach "KERNEL32$VirtualProtect" "_cVirtualProtect"
    attach "USER32$MessageBoxA"      "_cMessageBoxA"
 
    protect "_cLoadLibraryA, _cSleep, _cVirtualAlloc, _cVirtualProtect, _cMessageBoxA"
 
#
# Setup our stack cutting tradecraft.
#
setup.x86:
    # GYMNASTICS WARNING: stackcutting has to execute before anything else to get the safe return/frame address. So,
    # before we merge anything, we're going to get rid of the old go() function. Our stackcut_setup.x86 will have a new
    # go() function.
    remap "_go" "_go_away"
 
    # load+merge our stackcutting initialization logic
    load "bin/stackcut_setup.x86.o"
        merge
 
    # the getStart() function in loader.c STILL refers to _go_away (it's a linkage by relative address, not symbol); so
    # we use redirect to change that reference to our newly merged in go. Voila, we've taken ovr the entrypoint function
    redirect "_go_away" "_go"
 
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
 
    # register this with our thing.
    redirect "_setupHooks" "_setupHooksStackCutting"
 
    # we use optout to protect _SetupProxy from its own hooks, but to leave it open to inception by another module
    optout "_SetupProxy" "__cVirtualAlloc@16, __cVirtualProtect@16"
 
    # WHY yes... we can HOOK our loader PIC with the same hook code used in our IAT hooking. This is one of the 
    # reasons I wanted to merge our stack cutting hooks into this loader/setup module too. They do double duty now :)
    .attach
 
    # While .attach let's our hooks do double-duty (e.g., getting used to incept our own PIC)--in practice VirtualAlloc 
    # and LoadLibraryA are what's kept and used here. But, hey... transparent stack tradecraft in a PIC DLL loader that's 
    # applying stack tradecraft to a DLL is pretty damned cool, right?
    #
    # To see what's kept after link-time optimization, uncomment this line. It's also a good opportunity to look at how
    # and where _LoadLibraryA and _VirtualAlloc are called. You'll see they're just weaved into the program
    #disassemble "setup.x86.txt"
 
setup.x64:
    remap "go" "go_away"
 
    load "bin/rs/stackcut_setup.x64.o"
        merge
 
    redirect "go_away" "go"
 
    load "bin/rs/stackcut.x64.o"
        merge
 
    load "bin/c/proxy.x64.o"
        make pic
        export
        preplen
        link "my_proxy"
 
    redirect "setupHooks" "setupHooksStackCutting"
 
    optout "SetupProxy" "_cVirtualAlloc, _cVirtualProtect"
 
    .attach
    
    coffparse "aaa"
    disassemble "setup.x64.txt"
 
#
# configure the stackcutting hooks (this is to be merged in with our hooks PICO, right?)
#
hooks.x86:
    # load our stack cutting hooks logic and merge with the hooks PICO
    load "bin/stackcut.x86.o"
        merge
 
    # export our confighooks function, which is necessary for setupHooksStackCutting to
    # find our configstackcutting function mixed into the hooks PICO
    exportfunc "_configstackcutting" "___tag_configstackcutting"
 
    # add our hooks, which will return attach chain entries
    addhook "KERNEL32$LoadLibraryA"
    addhook "KERNEL32$Sleep"
    addhook "KERNEL32$VirtualAlloc"
    addhook "KERNEL32$VirtualProtect"
    addhook "USER32$MessageBoxA"
 
    # attach to our Win32 APIs
    .attach
 
hooks.x64:
    load "bin/rs/stackcut.x64.o"
        merge
 
    exportfunc "configstackcutting" "__tag_configstackcutting"
 
    addhook "KERNEL32$LoadLibraryA"
    addhook "KERNEL32$Sleep"
    addhook "KERNEL32$VirtualAlloc"
    addhook "KERNEL32$VirtualProtect"
    addhook "USER32$MessageBoxA"
 
    .attach
