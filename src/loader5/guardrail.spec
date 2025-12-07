#
# We're setting up a few PIC programs, so let's consolidate those setup commands here
#
initpic.x86:
    # +gofirst moves go() to position 0 of our PIC, +optimize removes unused code/functions
    make pic +gofirst +optimize
 
    # bring in our PIC services module from another project.
    run "../simple_pic/services.spec"
 
    # merge the Tradecraft Garden Library into our PIC
    mergelib "../libtcg/libtcg.x86.zip"
 
initpic.x64:
    make pic +gofirst +optimize
    run "../simple_pic/services.spec"
    mergelib "../../libtcg/libtcg.x64.zip"
 
#
# Setup our guardrails
#
x86:
    # load the guardrail COFF onto the Crystal Palace program stack
    load "bin/guardrail.x86.o"
        # call the helper label initpic to setup our PIC loader
        .initpic
 
        # merge in the guardrails implementation module (key derivation, capability decryption)
        load "bin/gr_impl.x86.o"
            merge
 
        # bring in our freeandrun PIC
        load "bin/free.x86.o"
            # let's initialize this too
            .initpic
 
            # Let's run the %STAGE2 specification file, presume we get back a PIC blob, and link
            # that to the function go_stage2() within our freeandrun PIC
            run %STAGE2
                linkfunc "_go_stage2"
 
            # turn the freeandrun PIC + appended package (the result of our next stage) into bytes
            export
 
            # prepend the Adler32 sum to this data
            prepsum
 
            # rc4 encrypt our data using CLI/API-passed ENVKEY
            rc4 $ENVKEY
 
            # prepend the length to our (encrypted) data
            preplen
 
            # link to the payload section
            link "stage2"
 
        export
 
x64:
    load "bin/rs/guardrail.x64.o"
        .initpic
 
        load "bin/rs/gr_impl.x64.o"
            merge
 
        load "bin/rs/free.x64.o"
            .initpic
 
            run %STAGE2
                linkfunc "go_stage2"
 
            export
 
            prepsum
            rc4 $ENVKEY
            preplen
 
            link "stage2"
 
        export
