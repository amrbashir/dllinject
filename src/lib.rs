use std::ffi::{c_ushort, c_void};

unsafe extern "C" {
    pub fn InjectDll(
        hprocess: *mut c_void,
        dll32_path: *const c_ushort,
        dll64_path: *const c_ushort,
    ) -> u32;
}
