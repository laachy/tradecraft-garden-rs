use std::ptr::null_mut;
use winapi::{shared::{minwindef::{DWORD, HINSTANCE, LPVOID}, ntdef::{TRUE}}, um::{winnt::{BOOLEAN, DLL_PROCESS_ATTACH}, winuser::{MB_OK, MessageBoxA}}};

#[unsafe(no_mangle)]
extern "system" fn DllMain(_hinst_dll: HINSTANCE, fdw_reason: DWORD, _lpv_reserved: LPVOID) -> BOOLEAN {
    match fdw_reason {
		DLL_PROCESS_ATTACH => {
			unsafe { MessageBoxA(null_mut(), c"rusty Hello World".as_ptr(), c"Test!".as_ptr(), MB_OK) };
        }
        _ => {}
	}

	TRUE
}
