#
# Linker directives to setup our XOR hooks tradecraft. Surprise: not much to do in this simple example
#
 
x86:
    # load our XOR hooks and merge with the main PIC? PICO?
    load "bin/xorhooks_setup.x86.o"
        merge
 
x64:
    load "bin/rs/xorhooks_setup.x64.o"
        merge