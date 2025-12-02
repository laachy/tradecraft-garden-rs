#
# Demonstrate loading a DLL and hooking functions.
#
name     "Simple Loader (Hooking)"
describe "Simple DLL loader that masks DLL content when MessageBoxA called"
author   "Raphael Mudge"
 
x86:
    # load our x86 .o file AND turn it into position-independent code
    load "bin/loader.x86.o"
        # +gofirst moves go() to position 0 of our PIC
        make pic +gofirst +optimize
 
        # opt into a PIC services module for dfr, fixbss, fixptrs
        run "../simple_pic/services.spec"
 
        # merge the Tradecraft Garden Library into our PIC
        mergelib "../libtcg/libtcg.x86.zip"
 
        # load our Reflective DLL argument AND link it into our PIC as my_data section
        push $DLL
            link "my_data"
 
        # setup our XOR hooks
        run "xorhooks_setup.spec"
 
        # load our hook PICO
        load "bin/hook.x86.o"
            make object +optimize
 
            # merge LibTCG for ror13hash function, +optimize gets rid of everything else
            mergelib "../libtcg/libtcg.x86.zip"
 
            # bring our freeAndRun() functionality into this PICO
            run "freeandrun.spec"
 
            # let's get specific... bring in our XOR hooks
            run "xorhooks.spec"
 
            # export and link it
            export
            link "my_hooks"
     
        # we're done, export the final blob
        export
 
x64:
    load "bin/rs/loader.x64.o"
        make pic +gofirst
 
        run "../simple_pic/services.spec"
        mergelib "../../libtcg/libtcg.x64.zip"
 
        push $DLL
            link "my_data"
 
        run "xorhooks_setup.spec"
 
        load "bin/rs/hook.x64.o"
            make object
 
            mergelib "../../libtcg/libtcg.x64.zip"
 
            run "freeandrun.spec"
            run "xorhooks.spec"
 
            export
            link "my_hooks"
 
        export