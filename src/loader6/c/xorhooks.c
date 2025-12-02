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
 
WINUSERAPI int WINAPI USER32$MessageBoxA(HWND hWnd,LPCSTR lpText,LPCSTR lpCaption,UINT uType);
 
/*
 * our xorkey, we're going to set this via our loader.spec
 */
char xorkey[128] = { 1 };
 
/*
 * A simple routine to obfuscate and de-obfuscate our data
 */
void applyxor(char * data, DWORD len) {
    for (DWORD x = 0; x < len; x++) {
        data[x] ^= xorkey[x % 128];
    }
}
 
/* globals to keep track of our DLL in memory. For simplicity's sake, this example
 * assumes the whole thing is RWX, but we could really do whatever we need between
 * the loader and this hooking module */
char * g_dllBase;
DWORD  g_dllSize;
 
/*
 * our MessageBoxA hook. See addhook "USER32$MessageBoxA" in loader.spec
 */
int WINAPI _MessageBoxA(HWND hWnd,LPCSTR lpText,LPCSTR lpCaption,UINT uType) {
    int result;
 
    applyxor(g_dllBase, g_dllSize);
 
    // may as well use our own strings, because the originals are garbled right now
    result = USER32$MessageBoxA(hWnd, "Hello from hook.c!", "HOOKED!", uType);
 
    applyxor(g_dllBase, g_dllSize);
 
    return result;
}
 
void confighooks(char * dllBase, DWORD dllsz) {
    /* track this information, because we will need it later */
    g_dllBase = dllBase;
    g_dllSize = dllsz;
}