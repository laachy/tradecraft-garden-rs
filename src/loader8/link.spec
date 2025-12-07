#
# Handle the DLL/COFF-specific linking parts of our build process
#
 
# x86.dll is the first label Crystal Palace will use, when acting on an x86 DLL argument.
# If there's no x86.dll target, Crystal Palace will fall back to the x86 target.
x86.dll:
    # given that we're working with a DLL, we're going to remap the symbol go_dll() to go()
    # to make it our entry point. The link-time optimizer will get rid of the unused go_object().
    remap "_go_dll" "_go"
 
    # let's push our DLL content onto the stack and link it with my_data
    push $DLL
        link "my_data"
 
x64.dll:
    remap "go_dll" "go"
 
    push $DLL
        link "my_data"
 
# x86.o is the first label Crystal Palace will use, when acting on an x86 COFF argument.
# If there's no x86.o target, Crystal Palace will fall back to the x86 target.
x86.o:
    # Sametype of thing as our x86.dll counterpart. We remap go_object() to go() to make it
    # our entry point. The link-time optimizer will get rid of the unused go_dll()
    remap "_go_object" "_go"
 
    # push our COFF content onto the stack, turn it into a PICO and link it to my_data
    push $OBJECT
        make object +optimize
        export
        link "my_data"
 
x64.o:
    remap "go_object" "go"
 
    push $OBJECT
        make object +optimize
        export
        link "my_data"
