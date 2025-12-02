/*
 * Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 * conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other materials provided
 * with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to
 * endorse or promote products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS Ã¢Â€ÂœAS ISÃ¢Â€Â AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
 
#include <windows.h>
#include "tcg.h"
 
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
 
/*
 * This is the Crystal Palace convention for getting ahold of data linked with this loader.
 */
char __DLLDATA__[0] __attribute__((section("my_data")));
char __GRDDATA__[0] __attribute__((section("my_guardexec")));
 
char * findAppendedDLL() {
    return (char *)&__DLLDATA__;
}
 
char * findAppendedGE() {
    return (char *)&__GRDDATA__;
}
 
/*
 * Our PICO loader, have fun, go nuts!
 */
char * SetupCOFF(IMPORTFUNCS * funcs, char * srcData) {
    char * dstCode = NULL;
    char * dstData = NULL;
 
    /* allocate memory */
    dstCode = KERNEL32$VirtualAlloc( NULL, PicoCodeSize(srcData), MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE );
    dstData = KERNEL32$VirtualAlloc( NULL, PicoDataSize(srcData), MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_READWRITE );
 
    /* load our pico into our destination address, thanks! */
    PicoLoad(funcs, srcData, dstCode, dstData);
 
    return dstCode;
}
 
// go() function for guard exec
typedef void (*GUARDEXEC_FUNC_2)(DLLDATA * data, char * dstdll);
 
// exported function for freeAndRun
typedef void (*FREEANDRUN_FUNC_3)(char * loader, char * dllEntry, char * dllBase);
 
/*
 * Get the start address of our PIC DLL loader.
 */
void go();
 
char * getStart() {
    return (char *)go;
}
 
/* this is the linker intrinsic() to get the tag for our exported free and run function */
int __tag_freeandrun();
 
/*
 * Our reflective loader itself, have fun, go nuts!
 */
void go() {
    DLLDATA      data;
    IMPORTFUNCS  funcs;
 
    /* find our DLL appended to this PIC */
    char * srcdll = findAppendedDLL();
 
    /* resolve the functions we'll need */
    funcs.GetProcAddress = GetProcAddress;
    funcs.LoadLibraryA   = LoadLibraryA;
 
    /* parse our DLL! */
    ParseDLL(srcdll, &data);
 
    /* allocate memory for our DLL and the other stuff within our layout.  */
    char * dstdll = KERNEL32$VirtualAlloc( NULL, SizeOfDLL(&data), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );
 
    /* load the damned DLL */
    LoadDLL(&data, srcdll, dstdll);
 
    /* process the imports */
    ProcessImports(&funcs, &data, dstdll);
 
    /* setup and run our GuardExec nmodule */
    char * srcge = findAppendedGE();
    char * dstge = SetupCOFF(&funcs, srcge);
 
    ((GUARDEXEC_FUNC_2)PicoEntryPoint(srcge, dstge))(&data, dstdll);
 
    /* run DLL via our freeAndRun (free.c) exported function merged into our guardexec PICO */
    ((FREEANDRUN_FUNC_3)PicoGetExport(srcge, dstge, __tag_freeandrun())) (getStart(), (char *)EntryPoint(&data, dstdll), dstdll);
}