use wolpertinger_macros::export;


#[export(dll = "msvcrt.dll")]
fn malloc(emu: &mut crate::EmuCore) {
    // Get requested size from appropriate calling convention
    if let Some(size) = emu.malloc_arg()
        && let Some(ptr) = emu.heap_alloc(size) {
        // Set return value in RAX/EAX
        let _ = emu.set_return_u64(ptr);
        return;
    }

    // If allocation failed or arg missing, return NULL
    let _ = emu.set_return_u64(0);
}

#[export(dll = "msvcrt.dll")]
fn _initterm(emu: &mut crate::EmuCore) {
    // Minimal implementation: return success
    let _ = emu.set_return_u64(0);
}

// exit(status): stop emulation and return 0
#[export(dll = "msvcrt.dll")]

fn exit(emu: &mut crate::EmuCore) {
    // Read status (not used here), then stop emulation
    let _ = emu.first_arg_u64();
    emu.emu_stop();
}

// Minimal _onexit stub: allocate a pointer-sized slot, store the function pointer there, and return the slot address in RAX.
#[export(dll = "msvcrt.dll")]

fn _onexit(emu: &mut crate::EmuCore) {
    if let Some(func_ptr) = emu.first_arg_u64() {
        let ptr_size = emu.ptr_size();
        if let Some(addr) = emu.heap_alloc(ptr_size) {
            let _ = emu.write_ptr(addr, func_ptr);
            let _ = emu.set_return_u64(addr);
            return;
        }
    }

    let _ = emu.set_return_u64(0);
}