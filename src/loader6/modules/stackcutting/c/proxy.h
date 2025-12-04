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
 
/*
 * Set the return address and frame address of the (real) stack frame we want to point back to. I use
 * this to create a stack that looks like our non-module backed code was never called. If you don't have
 * anything like that, then set both to 0 to break some means of stack unwinding.
 */
typedef struct {
    ULONG_PTR   frameaddr;
    ULONG_PTR   retaddr;
} FRAME;
 
/*
 * This is an internal struct, just keeping some info off of the stack, so I don't have to keep
 * adjusting proxy.c based on the number of local vars.
 *
 * You, as an API caller, have no responsibility to any of this.
 */
typedef struct {
    FRAME     * p_frame;
    FRAME       frame;
} __INTERNAL;
 
/*
 * Our proxycall struct, this is where we pass in arguments for our PIC proxy function
 * to act on. Each of the arguments is annotated below.
 */
typedef struct {
    ULONG_PTR  function;    /* a pointer to the function we want the proxy to call */
    DWORD      argc;    /* the number of arguments being passed, args[argc] and argc must agree */
    __INTERNAL temp;    /* don't touch this, not even to zero it, used by the proxy function */
    FRAME      spoofme; /* the return address and frame address we want to "spoof" */
    ULONG_PTR  args[4]; /* the arguments to our function */
} PROXYCALL;
 
/*
 * And, as simple as this, it's our proxy call function
 */
typedef ULONG_PTR (*PROXY)(PROXYCALL * desc);