use capstone::prelude::*;
use std::cell::OnceCell;
use crate::Architecture;

use log::debug;

thread_local! {
    static CAPSTONE: OnceCell<Capstone> = const { OnceCell::new() };
}

#[cfg(feature = "capstone")]
pub fn disasm_hook(uc: &mut unicorn_engine::Unicorn<'_, ()>, arch: Architecture) {
    CAPSTONE.with(|cs| {
        let cs = cs.get_or_init(|| {
            match arch {
                Architecture::X86 => {
                    Capstone::new()
                        .x86()
                        .mode(capstone::arch::x86::ArchMode::Mode32)
                        .syntax(capstone::arch::x86::ArchSyntax::Intel)
                        .build()
                        .unwrap()
                }
                Architecture::X86_64 => {
                    Capstone::new()
                        .x86()
                        .mode(capstone::arch::x86::ArchMode::Mode64)
                        .syntax(capstone::arch::x86::ArchSyntax::Intel)
                        .build()
                        .unwrap()
                }
            }
        });

        let pc = match uc.reg_read(unicorn_engine::RegisterX86::RIP) {
            Ok(pc) => pc,
            Err(_) => match uc.reg_read(unicorn_engine::RegisterX86::EIP) {
                Ok(pc) => pc,
                Err(_) => return,
            },
        };

        // Read a few bytes from PC
        let mut buf = [0u8; 16];
        if uc.mem_read(pc, &mut buf).is_ok()
            && let Ok(insns) = cs.disasm_count(&buf, pc, 1)
            && let Some(insn) = insns.iter().next()
        {
            // Format the instruction and registers into a single message and use the logger
            let mut msg = format!("{:#x}: {} | ", pc, insn);

            // Important registers to display
            let regs = [
                ("rax", unicorn_engine::RegisterX86::RAX),
                ("rbx", unicorn_engine::RegisterX86::RBX),
                ("rcx", unicorn_engine::RegisterX86::RCX),
                ("rdx", unicorn_engine::RegisterX86::RDX),
                ("rsi", unicorn_engine::RegisterX86::RSI),
                ("rdi", unicorn_engine::RegisterX86::RDI),
                ("r8", unicorn_engine::RegisterX86::R8),
                ("r9", unicorn_engine::RegisterX86::R9),
                ("rbp", unicorn_engine::RegisterX86::RBP),
                ("rsp", unicorn_engine::RegisterX86::RSP),
                ("rip", unicorn_engine::RegisterX86::RIP),
            ];

            let mut parts: Vec<String> = Vec::with_capacity(regs.len());
            for (name, reg) in regs.iter() {
                let part = if let Ok(val) = uc.reg_read(*reg) {
                    format!("{}: {:#x}", name, val)
                } else {
                    format!("{}: ???", name)
                };
                parts.push(part);
            }

            msg.push_str(&parts.join(", "));
            debug!("{}", msg);
        }
    });
}
