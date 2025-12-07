#
# Is this a loader? Nope! Straight to PIC! This demonstrates how to act on an arbitrary PICO
# and turn it into PIC. 
#
 
x86:
    push $OBJECT
        make pic +optimize +gofirst
 
        # apply our PIC service module to this object. This will set dfr/fixbss/fixptrs
        # and merge in code to implement them
        run "services.spec"
 
        # merge the Tradecraft Garden Library into our PIC
        mergelib "../libtcg/libtcg.x86.zip"
 
        export
 
x64:
    push $OBJECT
        make pic +optimize +gofirst
 
        run "services.spec"
        mergelib "../../libtcg/libtcg.x64.zip"
 
        export
