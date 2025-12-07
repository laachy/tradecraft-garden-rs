name     "Simple Loader (Pointer Patching)"
describe "Simple Loader that bootstraps with user-provided GetModuleHandle and GetProcAddress pointers"
author   "Raphael Mudge"
 
x86:
    # load our x86 .o file AND turn it into position-independent code
    load "bin/loader.x86.o"
        # +gofirst moves go() to position 0 of our PIC
        make pic +gofirst +optimize
 
        # OPT into x86 program fixes to allow data references without code hacks
        fixptrs "_caller"
 
        # patch symbols that we located into the .text section
        # $GMH is GetModuleHandle, $GPA is GetProcAddress
        patch "_pGetModuleHandle" $GMH
        patch "_pGetProcAddress"  $GPA
 
        # OPT into PIC dynamic function resolution.
        #
        # Note that we're using the strings method and not ror13. This is because we have
        # our GetModuleHandle and GetProcAddress pointers to work with.
        dfr "_resolve" "strings"
 
        # merge the Tradecraft Garden Library into our PIC
        mergelib "../libtcg/libtcg.x86.zip"
 
        # load our DLL argument AND link it into our PIC as my_data section
        push $DLL
            link "my_data"
 
        # we're done, export the final blob
        export
 
x64:
    load "bin/rs/loader.x64.o"
        make pic +gofirst +optimize
 
        patch "pGetModuleHandle" $GMH
        patch "pGetProcAddress"  $GPA
 
        dfr "resolve" "strings"
        mergelib "../../libtcg/libtcg.x64.zip"
 
        push $DLL
            link "my_data"

        disassemble "ggg"
 
        export
