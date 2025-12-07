#
# Simple Reflective DLL build spec
#
 
x86:
    # load our x86 .o file AND turn it into position-independent code
    load "bin/loader.x86.o"
        # +gofirst moves go() to position 0 of our PIC
        make pic +gofirst
 
        # OPT into x86 program fixes to allow data references without code hacks
        fixptrs "_caller"
 
        # OPT into PIC dynamic function resolution
        dfr "_resolve" "ror13"
 
        # merge the Tradecraft Garden Library into our PIC
        mergelib "../libtcg/libtcg.x86.zip"
 
        # load our Reflective DLL argument AND link it into our PIC as my_data section
        push $DLL
            link "my_data"
     
        # we're done, export the final blob
        export
 
x64:
    load "bin/rs/loader.x64.o"
        make pic +gofirst
 
        dfr "resolve" "ror13"
        mergelib "../../libtcg/libtcg.x64.zip"
 
        push $DLL
            link "my_data"
     
        export
