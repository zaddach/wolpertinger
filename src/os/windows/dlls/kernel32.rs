use wolpertinger_macros::export;

// Minimal stub for SetUnhandledExceptionFilter: return 0 in RAX
#[export(dll = "kernel32.dll", name = "SetUnhandledExceptionFilter")]

fn set_unhandled_exception_filter(emu: &mut crate::EmuCore) {
    // In Windows, SetUnhandledExceptionFilter returns previous filter pointer.
    // For now, we return NULL (0) and do not register any handler.
    let _ = emu.set_return_u64(0);
}
