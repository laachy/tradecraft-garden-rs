#
# Simple Reflective DLL build spec
#
x86:
    # generate an 8KB XOR key, why not
    generate $KEY 8192
 
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
            xor $KEY
            preplen
            link "my_data"
 
        # load our XOR key and link it in as my_key
        push $KEY
            preplen
            link "my_key"
 
        # load our free() PICO
        load "bin/free.x86.o"
            make object
            export
            xor $KEY
            preplen
            link "my_bof"
 
    # we're done, export the final blob
    export
 
x64:
    generate $KEY 8192
 
    load "bin/rs/loader.x64.o"
        make pic +gofirst
 
        dfr "resolve" "ror13"
        mergelib "../../libtcg/libtcg.x64.zip"
 
        push $DLL
            xor $KEY
            preplen
            link "my_data"
 
        push $KEY
            preplen
            link "my_key"
 
        load "bin/rs/free.x64.o"
            make object
            export
            xor $KEY
            preplen
            link "my_bof"
     
    export