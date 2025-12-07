#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

use core::{arch::asm, mem::zeroed, ptr::addr_of};

use crystal_bindings::tcg::{PicoGetExport, DLLDATA};
use crystal_sdk::import;
use stackcutting::{PROXY, PROXYCALL};
use winapi::shared::{basetsd::{SIZE_T, ULONG_PTR}, minwindef::{DWORD, HMODULE, LPVOID, PDWORD, UINT}, ntdef::{LPCSTR, VOID}, windef::HWND};

import!(KERNEL32!VirtualAlloc(lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD) -> LPVOID);
import!(KERNEL32!VirtualProtect(lpAddress: LPVOID, dwSize: SIZE_T, flNewProtect: DWORD, lpflOldProtect: PDWORD) -> LPVOID);
import!(KERNEL32!Sleep(dwMilliseconds: DWORD) -> VOID);
import!(USER32!MessageBoxA(hWnd: HWND, lpText: LPCSTR, lpCaption: LPCSTR, uType: UINT) -> i32);
import!(LoadLibraryA(arg1: LPCSTR) -> HMODULE);

unsafe extern "C" {
    /* this is a linker intrinsic to get the tag of our confighooks export function. */
    fn __tag_configstackcutting() -> i32;

    fn setupHooks(src_hooks: *const u8, dst_hooks: *const u8, data: *const DLLDATA, dst_dll: *const u8);
}

type PicoConfigStackcutting = fn(proxy: PROXY, ret_addr: *const u8, frame_addr: *const u8);

/*
 * GLOBALS
 */
#[unsafe(link_section = ".cplink")]
static mut CALL_PROXY: Option<PROXY> = None;

#[unsafe(link_section = ".cplink")]
static mut CALL: PROXYCALL = unsafe { zeroed() };

#[unsafe(no_mangle)]
#[inline(never)]
fn proxy(argc: u32) -> ULONG_PTR {
    unsafe {
        CALL.argc = argc;

        let r = CALL_PROXY.unwrap_unchecked()(addr_of!(CALL));

        asm!("", options(nomem, nostack, preserves_flags));

        r
    }
}

/*
 * HOOKS
 */
#[unsafe(no_mangle)]
extern "system" fn _cLoadLibraryA(lp_lib_file_name: LPCSTR) -> HMODULE {
    unsafe {
        CALL.function = LoadLibraryA_ptr() as _;
        CALL.args[0] = lp_lib_file_name as _;

        let result = proxy(4);

        // Prevent tail-call optimization
        asm!("", options(nomem, nostack, preserves_flags));

        result as _
    }
}

#[unsafe(no_mangle)]
extern "system" fn _cMessageBoxA(h_wnd: HWND, lp_text: LPCSTR, lp_caption: LPCSTR, u_type: UINT) -> i32 {
    unsafe {
        CALL.function = MessageBoxA_ptr() as _;
        CALL.args[0] = h_wnd as _;
        CALL.args[1] = lp_text as _;
        CALL.args[2] = lp_caption as _;
        CALL.args[3] = u_type as _;

        let result = proxy(4);

        // Prevent tail-call optimization
        asm!("", options(nomem, nostack, preserves_flags));

        result as _
    }
}

#[unsafe(no_mangle)]
extern "system" fn _cSleep(dw_milliseconds: DWORD) {
    unsafe {
        CALL.function = Sleep_ptr() as _;
        CALL.args[0] = dw_milliseconds as _;

        proxy(1);

        // Prevent tail-call optimization
        asm!("", options(nomem, nostack, preserves_flags));
    }
}

#[unsafe(no_mangle)]
extern "system" fn _cVirtualAlloc(lp_address: LPVOID, dw_size: SIZE_T, fl_allocation_type: DWORD, fl_protect: DWORD,) -> LPVOID {
    unsafe {
        CALL.function = VirtualAlloc_ptr() as _;
        CALL.args[0] = lp_address as _;
        CALL.args[1] = dw_size as _;
        CALL.args[2] = fl_allocation_type as _;
        CALL.args[3] = fl_protect as _;

        let result = proxy(4);

        // Prevent tail-call optimization
        asm!("", options(nomem, nostack, preserves_flags));

        result as _
    }
}

#[unsafe(no_mangle)]
extern "system" fn _cVirtualProtect(lp_address: LPVOID, dw_size: SIZE_T, fl_new_protect: DWORD, lpfl_old_protect: PDWORD) -> LPVOID {
    unsafe {
        CALL.function = VirtualProtect_ptr() as _;
        CALL.args[0] = lp_address as _;
        CALL.args[1] = dw_size as _;
        CALL.args[2] = fl_new_protect as _;
        CALL.args[3] = lpfl_old_protect as _;

        let result = proxy(4);

        // Prevent tail-call optimization
        asm!("", options(nomem, nostack, preserves_flags));

        result as _
    }
}

/*
 * Implement the setupHooks function called by loader.c--which is our chance to call our exported config function.
 * We do this here because this is where our global vars with the stack cutting info live
 */
#[unsafe(no_mangle)]
extern "C" fn setupHooksStackCutting(src_hooks: *const u8, dst_hooks: *const u8, data: &DLLDATA, dst_dll: *mut u8) {
    unsafe {
        core::mem::transmute::<_, PicoConfigStackcutting>(
            PicoGetExport(src_hooks as _, dst_hooks as _, __tag_configstackcutting())
                .unwrap_unchecked(),
        )(
            CALL_PROXY.unwrap_unchecked(),
            CALL.spoof_me.ret_addr as _,
            CALL.spoof_me.frame_addr as _,
        );

        setupHooks(src_hooks, dst_hooks, data, dst_dll);
    }
}

#[unsafe(no_mangle)]
extern "C" fn configstackcutting(proxy: PROXY, ret_addr: *const u8, frame_addr: *const u8) {
    unsafe {
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
        if frame_addr.is_null() {
            CALL.spoof_me.ret_addr = ret_addr as _;
            CALL.spoof_me.frame_addr = frame_addr as _;
        } else {
            CALL.spoof_me.ret_addr = ret_addr as _;
            CALL.spoof_me.frame_addr = frame_addr as _;
        }

        /* set our call proxy too */
        CALL_PROXY = Some(proxy);
    }
}
