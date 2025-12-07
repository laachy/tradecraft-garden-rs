#
# A little doodad to call free() a DLL loader and pass execution to a DLL
# 
 
x86:
    # load our free COFF and merge it
    load "bin/free.x86.o"
        merge
 
    # export freeAndRun for use with PicoGetExport
    exportfunc "_freeAndRun" "___tag_freeandrun"
 
x64:
    load "bin/rs/free.x64.o"
        merge
 
    exportfunc "freeAndRun" "__tag_freeandrun"
