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
 
typedef void (*PICO_CONFIG_HOOKS)(char * dllBase, DWORD dllsz);
 
/* this is a linker intrinsic to get the tag of our confighooks export function. */
int __tag_confighooksXor();
 
/*
 * setupHooks is called by the loader to allow our tradecraft to work with the DLL hooking BOF.
 * This is our chance to grab an exported function and pass our configuration on.
 */
void setupHooks(char * srchooks, char * dsthooks, DLLDATA * data, char * dstdll);
 
void setupHooksXor(char * srchooks, char * dsthooks, DLLDATA * data, char * dstdll) {
    /* call the configuration function exported by our PICO */
    ((PICO_CONFIG_HOOKS)PicoGetExport(srchooks, dsthooks, __tag_confighooksXor())) (dstdll, SizeOfDLL(data));
 
    /* continue the chain */
    setupHooks(srchooks, dsthooks, data, dstdll);
}