use unicorn_engine::Unicorn;
use crate::ExportMap;

/// # Safety
///
/// This function dereferences `emu_raw`. Callers must ensure `emu_raw` is a
/// valid, unique pointer to a live `EmuCore` instance that outlives the hook.
pub unsafe fn api_hook_handler(
    uc: &mut Unicorn<'_, ()>,
    dll: &str,
    func: &str,
    emu_raw: *mut crate::EmuCore,
    exports: &ExportMap,
) {
    log::debug!("API call: {}!{} at {:#x}", dll, func, uc.pc_read().unwrap_or(0));

    // Check if a user-provided exported function exists
    if let Some(func_map) = exports.get(dll) && let Some(f) = func_map.get(func) {
        // SAFETY: emu_raw is captured from the EmuCore instance which must outlive the Unicorn hooks
        unsafe {
            let emu: &mut crate::EmuCore = &mut *emu_raw;
            (f)(emu);
        }
        return;
    }

    // No exported handler — default behavior: set a zero return (EAX/RAX depending on arch)
    if let Some(emu) = unsafe { emu_raw.as_mut() } {
        let _ = emu.set_return_u64(0);
    }
}
