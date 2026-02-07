# Qiling (Windows-only) Rust Clone Design

Date: February 2, 2026

## Scope

This design extracts the architecture and control flow from the existing Qiling Python implementation and narrows it to Windows binary emulation only (x86 and x86_64). The original structure is rooted in the `Qiling` core, architecture abstraction, PE loader, Windows OS layer, and Unicorn hook dispatch. Key reference sources include:

- [qiling/qiling/core.py](qiling/qiling/core.py)
- [qiling/qiling/core_hooks.py](qiling/qiling/core_hooks.py)
- [qiling/qiling/loader/pe.py](qiling/qiling/loader/pe.py)
- [qiling/qiling/os/windows/windows.py](qiling/qiling/os/windows/windows.py)
- [qiling/qiling/os/windows/handle.py](qiling/qiling/os/windows/handle.py)
- [qiling/qiling/os/windows/thread.py](qiling/qiling/os/windows/thread.py)
- [qiling/qiling/os/windows/registry.py](qiling/qiling/os/windows/registry.py)
- [qiling/qiling/os/os.py](qiling/qiling/os/os.py)
- [qiling/qiling/os/memory.py](qiling/qiling/os/memory.py)

## Goals

- Execute Windows PE binaries (EXE/DLL) under Unicorn.
- Emulate enough of the Windows user-mode environment to handle common imports.
- Provide a structured API hook dispatcher for WinAPI functions.
- Support debugging with GDB remote protocol.
- Preserve Qiling’s component boundaries to keep behavior predictable and extensible.

## Non-goals

- Linux, macOS, UEFI, firmware, and bare-metal support.
- Non-x86 architectures.
- Full kernel-mode emulation.

## High-level Architecture

```
Cli -> Config -> Emulator Core
                 |-> Arch (x86/x64)
                 |-> Memory Manager
                 |-> PE Loader
                 |-> Windows OS Layer
                 |-> WinAPI Dispatch
                 |-> Thread/Handle/Registry/Heap
                 |-> Debugger (GDB stub)
```

The Rust clone should keep the same composition order as Qiling:

1. Determine target arch and OS.
2. Build `Unicorn` instance for the arch.
3. Initialize memory manager and logging.
4. Initialize loader and OS layer.
5. Load PE images, resolve imports, create stubs.
6. Register Unicorn hooks.
7. Start emulation at `entry_point`.

## Core Components

### 1) Emulator Core (`EmuCore`)

Analogous to `Qiling` in [qiling/qiling/core.py](qiling/qiling/core.py). Responsibilities:

- Owns the Unicorn instance, memory manager, loader, and OS layer.
- Stores runtime state: `entry_point`, `exit_point`, `timeout`, `instruction_count`.
- Provides hook APIs that wrap Unicorn’s `hook_add` with error handling.
- Serves as the dependency root for OS and loader.

### 2) Architecture Layer (`arch`)

Extracted from Qiling’s architecture abstraction (see `qiling/qiling/arch/*`). For Windows-only support:

- `x86` and `x86_64` register sets and register mapping.
- Packing/unpacking helpers for pointer-size operations.
- Snapshot/restore for thread switching and debugging.

### 3) Memory Manager (`memory`)

Mirrors [qiling/qiling/os/memory.py](qiling/qiling/os/memory.py):

- Owns virtual address map metadata, permissions, and MMIO stubs.
- Provides read/write helpers for words, strings, and buffers.
- Enforces page alignment and permissions.

### 4) PE Loader (`loader::pe`)

Based on [qiling/qiling/loader/pe.py](qiling/qiling/loader/pe.py). Core responsibilities:

- Parse PE headers and sections.
- Map the image into Unicorn memory at preferred base (or relocated base).
- Build Import Address Table (IAT) and `import_symbols` map.
- Load dependent DLLs, respecting system paths and canonicalized names.
- Provide `entry_point` and `exit_point` to `EmuCore`.

### 5) Windows OS Layer (`os::windows`)

Based on [qiling/qiling/os/windows/windows.py](qiling/qiling/os/windows/windows.py):

- Initializes GDT/segment structures (FS/GS) for x86/x64.
- Builds runtime environment: heap, handles, registry, threads.
- Dispatches WinAPI calls by intercepting IAT stubs.

### 6) WinAPI Hook Dispatcher

Qiling hooks WinAPI by intercepting executed addresses that match entries in `import_symbols` and dispatching into `dlls/` modules. The Rust clone should follow the same pattern:

- At load time, assign IAT stubs or “thunks” to a known code region.
- Maintain `import_symbols: Address -> ApiSymbol`.
- On `UC_HOOK_CODE`, check `pc` and dispatch the API handler if present.
- Provide a user override table that can intercept `CALL`, `ENTER`, and `EXIT` phases (mirroring `QL_INTERCEPT`).

### 7) Thread/Handle/Registry

- **Handles**: a numeric handle table (see [qiling/qiling/os/windows/handle.py](qiling/qiling/os/windows/handle.py)).
- **Threads**: a cooperative scheduler using `UC_HOOK_CODE` to switch contexts (see [qiling/qiling/os/windows/thread.py](qiling/qiling/os/windows/thread.py)).
- **Registry**: load from hive files, with JSON “diff” overlay (see [qiling/qiling/os/windows/registry.py](qiling/qiling/os/windows/registry.py)).

### 8) Debugging (GDB)

Provide a GDB remote stub layer that:

- Translates `gdbstub` operations into Unicorn single-step or continue.
- Reads/writes registers via the `arch` module.
- Adds breakpoints using a `UC_HOOK_CODE` filter or a code patch strategy.

## Unicorn Hook Usage

Qiling’s core hook infrastructure is in [qiling/qiling/core_hooks.py](qiling/qiling/core_hooks.py). The Rust clone should register the same classes of hooks and group dispatch through a central hook manager.

### Hook Types in Use

- `UC_HOOK_CODE`: instruction execution tracing and WinAPI dispatch.
- `UC_HOOK_BLOCK`: basic-block tracing and optional disassembly.
- `UC_HOOK_INTR`: interrupt handling (kept for parity; rarely used in Windows-only mode).
- `UC_HOOK_INSN`: specific instruction types (optional; used for syscall interception in non-Windows flows, still useful for `SYSCALL` in x64).
- `UC_HOOK_INSN_INVALID`: invalid opcode handler.
- Memory hooks:
  - `UC_HOOK_MEM_READ`
  - `UC_HOOK_MEM_WRITE`
  - `UC_HOOK_MEM_FETCH`
  - `UC_HOOK_MEM_READ_AFTER`
  - `UC_HOOK_MEM_READ_UNMAPPED`
  - `UC_HOOK_MEM_WRITE_UNMAPPED`
  - `UC_HOOK_MEM_FETCH_UNMAPPED`
  - `UC_HOOK_MEM_READ_PROT`
  - `UC_HOOK_MEM_WRITE_PROT`
  - `UC_HOOK_MEM_FETCH_PROT`
  - `UC_HOOK_MEM_READ_INVALID`
  - `UC_HOOK_MEM_WRITE_INVALID`
  - `UC_HOOK_MEM_FETCH_INVALID`

### Hook Purpose in Windows Mode

- **API dispatch**: `UC_HOOK_CODE` checks `pc` against `import_symbols` and calls the WinAPI handler.
- **Thread scheduling**: `UC_HOOK_CODE` fires a scheduler callback every N instructions, switching saved contexts.
- **Memory fault handling**: `UC_HOOK_MEM_*` for reporting and optionally lazy mapping.
- **Debugging**: `UC_HOOK_CODE` to stop on breakpoints; `UC_HOOK_INSN` optional for single-step.

## Component Wiring to Unicorn

1. **Create `Unicorn`** for `x86` or `x86_64`.
2. **Attach `HookManager`** (wrapper around Unicorn’s hook API).
3. **Create `MemoryManager`** bound to Unicorn.
4. **Create `PeLoader`** with `MemoryManager` and `Unicorn`.
5. **Create `WindowsOs`** with heap, handles, registry, and API dispatcher.
6. **Load target PE** via `PeLoader`, build `import_symbols`, populate `entry_point`.
7. **Register hooks**:
   - `UC_HOOK_CODE` -> API dispatcher + thread scheduler + debugger breakpoints.
   - Memory hooks -> fault handling/logging.
   - Optional `UC_HOOK_INSN_INVALID` -> crash handler.
8. **Start emulation** via `emu_start(entry_point, exit_point, timeout, count)`.

## Suggested Rust Module Layout

```
src/
  main.rs
  cli.rs
  core/
    mod.rs
    hooks.rs
    state.rs
  arch/
    mod.rs
    x86.rs
    x64.rs
  memory/
    mod.rs
    map.rs
  loader/
    mod.rs
    pe.rs
  os/
    mod.rs
    windows/
      mod.rs
      api.rs
      handle.rs
      registry.rs
      thread.rs
      heap.rs
  debug/
    mod.rs
    gdb.rs
  util/
    log.rs
    path.rs
```

## Crate Selection

Mandatory crates (per requirement):

- `log`
- `env_logger`
- `unicorn`
- `clap` (with `derive` feature)
- `gdbstub`

Recommended crates for the Rust clone:

- `anyhow` or `thiserror`: structured errors.
- `bitflags`: permission and hook flags.
- `goblin` or `object`: PE parsing.
- `serde` + `serde_json`: registry diff and configuration.
- `bytes`: buffer utilities.
- `memmap2`: fast image mapping.
- `parking_lot`: fast locks for shared state.
- `smallvec`: reduce allocations in hot paths.

## Windows PE Loader Details

The loader should emulate Qiling’s flow:

- Parse DOS/NT headers.
- Map sections with appropriate permissions.
- Apply relocations if preferred base is unavailable.
- Build a synthetic IAT and populate `import_symbols` for dispatch.
- Load dependent DLLs, resolve exports, and patch thunks.

## WinAPI Dispatch Flow

1. `UC_HOOK_CODE` fires at each instruction.
2. If `pc` is in `import_symbols`, resolve `ApiSymbol`.
3. Find the hook by name in `os::windows::api` or user override table.
4. Call handler with `FunctionCall` helper to read parameters.
5. Update return value and advance `pc` to return address.

## Logging and CLI

- `env_logger` initializes logging.
- `clap` provides arguments for:
  - input binary
  - rootfs path
  - verbosity
  - gdb port
  - optional `--entry`/`--exit`

## Testing Strategy

- Use small Windows test binaries with known API calls.
- Validate IAT resolution and WinAPI call flow.
- Add snapshot tests for memory maps and registry access.
- Add gdbstub smoke tests to check breakpoint and register read/write.

## Implementation Notes

- Keep hook dispatch lightweight (hot path).
- Prefer iterator-based parsing and mapping where possible.
- Build the API handler table from function name strings.
- Avoid global mutable state; store per-emulator state in `EmuCore`.

