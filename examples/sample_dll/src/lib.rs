const DLL_PROCESS_ATTACH: u32 = 1;
const DLL_PROCESS_DETACH: u32 = 0;

#[unsafe(no_mangle)]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(
    dll_module: *mut std::ffi::c_void,
    fdw_reason: u32,
    lpv_reserved: *mut std::ffi::c_void,
) -> bool {
    match fdw_reason {
        DLL_PROCESS_ATTACH => println!("    [*][DLL] Process attach"),
        DLL_PROCESS_DETACH => println!("    [*][DLL] Process detach"),
        _ => {}
    }

    true
}
