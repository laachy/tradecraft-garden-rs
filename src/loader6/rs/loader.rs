#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

use core::{ffi::c_void, hint::black_box, mem, ptr::null_mut};
use crystal_bindings::tcg::{EntryPoint, LoadDLL, ParseDLL, PicoCodeSize, PicoDataSize, PicoEntryPoint, PicoGetExport, PicoLoad, ProcessImports, SizeOfDLL, DLLDATA, IMPORTFUNCS,};
use crystal_sdk::{append_data,import};
use winapi::{shared::{minwindef::{DWORD, FARPROC, HMODULE, LPVOID},ntdef::LPCSTR,},um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE},};

append_data!(my_hooks, findAppendedHOOKS, "__HOKDATA__");
append_data!(my_data, findAppendedDLL, "__DLLDATA__");

import!(KERNEL32!VirtualAlloc(lpAddress: LPVOID, dwSize: usize, flAllocationType: DWORD, flProtect: DWORD) -> LPVOID);
import!(LoadLibraryA(arg1: LPCSTR) -> HMODULE);
import!(GetProcAddress(arg1: HMODULE, arg2: LPCSTR) -> FARPROC);

type PicoMainFunc3 = unsafe extern "C" fn(loader: *const u8, dll_entry: *const u8, dll_base: *const u8);

unsafe extern "C" {
    fn __tag_freeandrun() -> i32;
}

#[inline(never)]
#[unsafe(no_mangle)]
extern "C" fn setupHooks(src_hooks: *const u8, dst_hooks: *const u8, data: *const DLLDATA, dst_dll: *const u8,) {
    black_box(src_hooks);
    black_box(dst_hooks);
    black_box(data);
    black_box(dst_dll);
}

fn setup_coff(funcs: &mut IMPORTFUNCS, src_data: *const u8) -> *const c_void {
    unsafe {
        let dst_code;
        let dst_data;

        /* allocate memory, we're combining everything into one memory region */
        dst_code = VirtualAlloc(
            null_mut(),
            (PicoDataSize(src_data as _) + PicoCodeSize(src_data as _)) as _,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        );
        dst_data = dst_code as usize + PicoCodeSize(src_data as _) as usize;

        /* load our pico into our destination address, thanks! */
        PicoLoad(funcs, src_data as _, dst_code as _, dst_data as _);

        dst_code as _
    }
}

#[unsafe(no_mangle)]
extern "C" fn init() {
    unsafe {
        let src_dll = findAppendedDLL(); /* find our DLL appended to this PIC */
        let dst_dll;
        let src_hooks;
        let dst_hooks;
        let mut data: DLLDATA = mem::zeroed();

        let mut funcs = IMPORTFUNCS {
            LoadLibraryA: Some(LoadLibraryA_ptr()),
            GetProcAddress: Some(GetProcAddress_ptr()),
        };

        /* parse our DLL! */
        ParseDLL(src_dll as _, &mut data);

        /* allocate memory for our DLL and the other stuff within our layout.  */
        dst_dll = VirtualAlloc(
            null_mut(),
            SizeOfDLL(&mut data) as _,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        );

        /* Before we go ANY further, let's setup our hooks PICO */
        src_hooks = findAppendedHOOKS();
        dst_hooks = setup_coff(&mut funcs, src_hooks);

        /* Our hooks PICO will hook GetProcAddres within funcs, so it takes effect on LoadDLL */
        PicoEntryPoint(src_hooks as _, dst_hooks as _).unwrap_unchecked()(
            &mut funcs as *mut _ as _,
        );

        /* Run our hook setup logic (tradecraft specific) */
        setupHooks(src_hooks as _, dst_hooks as _, &data, dst_dll as _);

        /* load the damned DLL */
        LoadDLL(&mut data, src_dll as _, dst_dll as _);

        /* process the imports */
        ProcessImports(&mut funcs, &mut data, dst_dll as _);

        /* run DLL via our freeAndRun exported function merged into our hooks PICO */
        mem::transmute::<_, PicoMainFunc3>(PicoGetExport(
            src_hooks as _,
            dst_hooks as _,
            __tag_freeandrun(),
        ))(
            getStart() as _,
            EntryPoint(&mut data, dst_dll as _).unwrap_unchecked() as _,
            dst_dll as _,
        );
    }
}

/*
 * Our entry point for the loader. init() is a join point for any setup functionality (e.g., redirect "init" "_my_init")
 */
#[unsafe(no_mangle)]
extern "C" fn go() {
    init();
}

#[unsafe(no_mangle)]
extern "C" fn getStart() -> *const c_void {
    go as _
}
