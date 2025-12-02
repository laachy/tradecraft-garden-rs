#
# Stage 2 of our loading process. We handle the actual DLL here.
#
 
x86:
    # push stage2.x6.o contents onto the stack
    load "bin/stage2.x86.o"
        # interpret these contents as a COFF
        make object
 
        # map the pointers passed to PicoLoad() via IMPORTFUNCS parameter
        # to functions within this COFF
        import "LoadLibraryA, GetProcAddress, VirtualAlloc, VirtualFree"
 
        # merge the Tradecraft Garden Library into our PICO
        mergelib "../libtcg/libtcg.x86.zip"
 
        # push our DLL contents onto  the stack
        push $DLL
            # prepend the length of our DLL to its contents. We will use
            # this length to accurately zero out DLL content when we're
            # done with it.
            preplen
 
            # link all of this to the my_data symbol in our COFF. The
            # convention to access this data is the same as from PIC
            link "my_data"
 
        # export our COFF as a ready-to-load PICO and return to stage 1
        export
 
x64:
    load "bin/rs/stage2.x64.o"
        make object
        import "LoadLibraryA, GetProcAddress, VirtualAlloc, VirtualFree"
 
        mergelib "../../libtcg/libtcg.x64.zip"
 
        push $DLL
            preplen
            link "my_data"
 
        export