use wolpertinger_macros::export;

// Minimal MessageBoxW stub: always return IDOK (1)
#[export(dll = "user32.dll", name = "MessageBoxW")]

fn message_box_w(_emu: &mut crate::EmuCore) {
    // IDOK is 1
    let _ = _emu.set_return_u64(1);
}
