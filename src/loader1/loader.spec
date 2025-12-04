x64:
    load "bin/rs/loader.x64.o"
        make pic +gofirst
 
        dfr "resolve" "ror13"
        mergelib "../../libtcg/libtcg.x64.zip"
 
        push $DLL
            link "my_data"

        disassemble "out.txt"
        
        export
