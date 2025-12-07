#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

use core::mem;
use crystal_sdk::brk;
use stackcutting::{get_frame, PROXYCALL};
use winapi::shared::basetsd::ULONG_PTR;

type CALL0 = unsafe extern "system" fn() -> ULONG_PTR;
type CALL1 = unsafe extern "system" fn(ULONG_PTR) -> ULONG_PTR;
type CALL2 = unsafe extern "system" fn(ULONG_PTR, ULONG_PTR) -> ULONG_PTR;
type CALL3 = unsafe extern "system" fn(ULONG_PTR, ULONG_PTR, ULONG_PTR) -> ULONG_PTR;
type CALL4 = unsafe extern "system" fn(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR) -> ULONG_PTR;

#[unsafe(no_mangle)]
extern "C" fn proxy(call: &mut PROXYCALL) -> ULONG_PTR {
    unsafe {
        let result;

        brk();

        /* grab and backup our previous frame ptr and ret addr */
        call.temp.p_frame = get_frame() as _;
        call.temp.frame = *call.temp.p_frame;

        brk();

        /* spoof our frame address and return address */
        *call.temp.p_frame = call.spoof_me;

        /* We push rbx (8b) and create 0x38 (56b) of stack space. So, 64 / 8--we want to
         * stick our return address at -8 from our frame address (rbp).
         */
        *(get_frame().sub(8) as *mut _) = call.spoof_me.ret_addr;
        core::arch::asm!("mov rbx, {0}", in(reg) call.spoof_me.ret_addr, options(nostack, preserves_flags));

        brk();

        /* let's make our proxied call (separate of this stack munging nonsense) */
        if call.argc == 0 {
            result = mem::transmute::<_, CALL0>(call.function)();
        } else if call.argc == 1 {
            result = mem::transmute::<_, CALL1>(call.function)(call.args[0]);
        } else if call.argc == 2 {
            result = mem::transmute::<_, CALL2>(call.function)(call.args[0], call.args[1]);
        } else if call.argc == 3 {
            result =
                mem::transmute::<_, CALL3>(call.function)(call.args[0], call.args[1], call.args[2]);
        } else if call.argc == 4 {
            result = mem::transmute::<_, CALL4>(call.function)(
                call.args[0],
                call.args[1],
                call.args[2],
                call.args[3],
            );
        } else {
            result = 0;
        }

        brk();

        /* restore our previous frame ptr and ret addr */
        *call.temp.p_frame = call.temp.frame;

        result
    }
}
