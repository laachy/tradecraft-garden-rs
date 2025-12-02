#![no_std]

use core::ffi::c_void;

use winapi::shared::{basetsd::ULONG_PTR, minwindef::DWORD};

#[repr(C)]
#[derive(Copy)]
#[derive(Clone)]
pub struct FRAME {
    pub frame_addr: ULONG_PTR,
    pub ret_addr: ULONG_PTR,
}

#[repr(C)]
pub struct __INTERNAL {
    pub p_frame: *mut FRAME,
    pub frame: FRAME,
}

#[repr(C)]
pub struct PROXYCALL {
    pub function: ULONG_PTR,
    pub argc: DWORD,
    pub temp: __INTERNAL,
    pub spoof_me: FRAME,
    pub args: [ULONG_PTR;4]
}

pub type PROXY = unsafe extern "C" fn(desc: *const PROXYCALL) -> ULONG_PTR;

#[inline(always)]
pub unsafe fn get_frame() -> *const c_void {
    let fp;
    unsafe { core::arch::asm!("mov {0}, rbp", out(reg) fp) };
    fp
}

#[inline(always)]
pub unsafe fn get_return() -> *const c_void {
    let rp;
    unsafe { core::arch::asm!("mov {0}, [rbp + 8]", out(reg) rp) };
    rp
}
