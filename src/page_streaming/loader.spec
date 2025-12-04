# some meta-info about our capability
name     "PageStream rDLL"
describe "Use VEHs and guard pages to limit DLL visibility in eXecutable memory"
author   "Raphael Mudge"
 
x86:
    # load our x86 .o file AND turn it into position-independent code
    load "bin/loader.x86.o"
        # +gofirst moves go() to position 0 of our PIC
        make pic +gofirst +optimize
 
        # bring in PIC Service Module from another project
        run "../simple_pic/services.spec"
 
        # merge the Tradecraft Garden Library into our PIC
        mergelib "../libtcg/libtcg.x86.zip"
 
        # generate a 16b XOR key for our obfuscated pages
        generate $KEY 16
 
        # load our guardexec() PICO
        load "bin/guardexec.x86.o"
            make object +optimize
 
            # bring our freeAndRun() functionality into this PICO
            run "freeandrun.spec"
 
            # merge the Tradecraft Garden Library into our PICO, +optimize means we're
            # only keeping the functions we use, so it's all right
            mergelib "../libtcg/libtcg.x86.zip"
 
            # patch that key into our PICO
            patch "_xorkey" $KEY
 
            export
            link "my_guardexec"
     
        # load our Reflective DLL argument AND link it into our PICO as my_data section.
        push $DLL
            link "my_data"
 
        # we're done, export the final blob
        export
 
x64:
    load "bin/rs/loader.x64.o"
        make pic +gofirst
 
        run "../simple_pic/services.spec"
        mergelib "../../libtcg/libtcg.x64.zip"
 
        generate $KEY 16
 
        load "bin/rs/guardexec.x64.o"
            make object
            run "freeandrun.spec"
            mergelib "../../libtcg/libtcg.x64.zip"
            patch "xorkey" $KEY
            export
            link "my_guardexec"
 
        push $DLL
            link "my_data"
 
        export