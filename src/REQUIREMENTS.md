WINAPI imports:
    DFR only touches instructions that have a relocation whose symbol name parses as a WinAPI import

    Algorithm:
        Iterate over every section
            Iterate over every relocation in that section
                Look at symbol name and determine validity
                    Process (add DFR stub)

    Symbol naming:
        MODULE$Function pairs
            Unless GetProcAddress or LoadLibraryA where no MODULE$ prefix is required (KERNEL32 appended internally)
        Prefixed with __imp_ OR __imp__


    Byte pattern:
        1) 
            call qword ptr (IMPORT)
        OR
        2)
            mov rax, (IMPORT)

    Output:
        replace those instructions with resolve stubs, add call rax for first case else leave alone


Methodology:
    Static symbol that holds the pointer, must be named to required crystal palace conventions

    Getting function pointers
    Calling functions