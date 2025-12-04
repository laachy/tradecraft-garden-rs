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
#include "proxy.h"
 
typedef ULONG_PTR WINAPI (*CALL0)();
typedef ULONG_PTR WINAPI (*CALL1)(ULONG_PTR);
typedef ULONG_PTR WINAPI (*CALL2)(ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR WINAPI (*CALL3)(ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR WINAPI (*CALL4)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
 
ULONG_PTR proxy(PROXYCALL * call) {
    ULONG_PTR result;
 
    /* grab and backup our previous frame ptr and ret addr */
    call->temp.p_frame    = (FRAME *)__builtin_frame_address(0);
    call->temp.frame      = *(call->temp.p_frame);
 
    /* spoof our frame address and return address */
    *(call->temp.p_frame) = call->spoofme;
 
#ifdef WIN_X64
    /* And, what is... going on... HERE...
     *
     * This is the guesswork of Raphael, his limited knowledge, and alone time with
     * a debugger. I had high hopes. I could just FIX the damned frame pointer and
     * stack pointer and suddenly... suddenly... my stack would look AWESOME.
     *
     * But, that's not what happened. :(
     *
     * The CPU isn't the judge here. It follows the instructions and does what it
     * does. We're up against StackWalk, which is a mix of reading .pdata (not
     * applicable here) and making guesses.
     *
     * When its assumptions break, it starts to try to treat everything as a return
     * address before it gives up. It's much more complicated than that (from my quick
     * read of ReactOS code).
     *
     * So, first things first, let's set our desired return address to the very top
     * of the frame (bottom most address). This is DEPENDENT on the number of local
     * vars. So, you'll need to read the pre-amble to this function (if you change it)
     * to determine where that's at.
     *
     * x86_64-w64-mingw32-objdump -d proxy.x64.o
     *
     * 0000000000000000 <proxy>:
     * 0:   55                      push   %rbp
     * 1:   48 89 e5                mov    %rsp,%rbp
     * 4:   53                      push   %rbx
     * 5:   48 83 ec 38             sub    $0x38,%rsp
     *
     * We push rbx (8b) and create 0x38 (56b) of stack space. So, 64 / 8--we want to
     * stick our return address at -8 from our frame address (rbp).
     */
    *((ULONG_PTR *)__builtin_frame_address(0) - 8) = call->spoofme.retaddr;
 
    /* Oh, but our hell isn't done yet. You see, some functions use that lovely space
     * at the top of our frame (shadow space) to store some non-volatile / callee saved
     * registers. Not all. But, some do. And when that happens, my carefully crafted
     * plans fall apart and the above value gets STOMPED breaking our illusion.
     *
     * What's an example of a function that does this? Sleep/SleepEx.
     *
     * What's an example of a function you're guaranteed to try to hook to see if this
     * works? Sleep/SleepEx.
     *
     * So, here's the fix for that... find the register that's propagating back to our
     * shadow space in the frame and set it to our return address. Things will work out
     * fine after doing this. */
    register ULONG_PTR fixrbx asm("rbx") __attribute__((unused)) = call->spoofme.retaddr;
#else
    /* for ONCE, x86 isn't the problem */
#endif
 
    /* let's make our proxied call (separate of this stack munging nonsense) */
    if (call->argc == 0) {
        result = ((CALL0)call->function)();
    }
    else if (call->argc == 1) {
        result = ((CALL1)call->function)(call->args[0]);
    }
    else if (call->argc == 2) {
        result = ((CALL2)call->function)(call->args[0], call->args[1]);
    }
    else if (call->argc == 3) {
        result = ((CALL3)call->function)(call->args[0], call->args[1], call->args[2]);
    }
    else if (call->argc == 4) {
        result = ((CALL4)call->function)(call->args[0], call->args[1], call->args[2], call->args[3]);
    }
 
    /* restore our previous frame ptr and ret addr */
    *(call->temp.p_frame) = call->temp.frame;
 
    return result;
}