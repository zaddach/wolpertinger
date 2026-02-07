
After qltool is invoked with a Windows binary (e.g., qltool run binary.exe --rootfs rootfs), Qiling performs a series of initialization and emulation steps. Based on analyzing the Qiling source code, here's a fine-grained breakdown of the process:

1. Command-Line Parsing and Argument Preparation (qltool)
qltool parses CLI arguments using argparse.
For the run subcommand, it prepares ql_args containing:
argv: The binary path and arguments (e.g., ['binary.exe']).
rootfs: The root filesystem path (e.g., rootfs).
Additional options like env, verbose, profile, etc., are added to ql_args.
2. Qiling Instance Creation (Qiling.__init__)
Validates argv[0] as an existing file and rootfs as a directory.
Guesses architecture (arch) and OS type if not provided (using ql_guess_emu_env based on file headers).
Sets default endianness (little-endian if unspecified).
Initializes the architecture layer (self._arch) using select_arch, which creates a Unicorn emulator instance tailored to the arch (e.g., x86/x64).
Initializes core structures (QlCoreStructs) and hooks (QlCoreHooks) with the Unicorn instance.
Sets up logging, profile (from YAML/config), and components:
Loader: select_loader creates QlLoaderPE (for Windows PE files), passing libcache for DLL caching.
Memory Manager: select_component('os', 'memory') creates the memory manager.
OS Layer: select_os creates QlOsWindows.
Runs the Loader: self.loader.run() to load and map the binary into memory.
3. Loader Execution (QlLoaderPE.run() and load())
Defines system DLLs to load (e.g., ntdll.dll, kernel32.dll).
Parses the PE file using pefile:
Extracts image base, size, entry point, and sections.
Relocates the image if the default base address conflicts.
Maps memory regions:
Stack at stack_address (from profile, e.g., 0x200000 for x86).
PE image at image_base (e.g., 0x400000).
Initializes Windows-specific structures:
TEB (Thread Environment Block): Sets up thread-local storage.
PEB (Process Environment Block): Includes command line, environment, and loader data.
LDR Data: Maintains loaded module lists.
Exports and imports tables.
Writes the PE image bytes to memory.
Sets stack and base pointers (e.g., esp/rsp to top of stack).
Loads system DLLs (e.g., kernel32.dll) via super().load_dll().
Initializes imports: Resolves DLL functions and sets up hooks for imported APIs.
For executables, calls DllMain if it's a DLL, or prepares for main/WinMain.
4. OS Layer Initialization (QlOsWindows.__init__ and load())
Sets up function calling conventions (fcall) for Windows (e.g., stdcall, cdecl, ms64).
Initializes heap (QlMemoryHeap) at heap_address (from profile).
Configures paths: windir, winsys (e.g., C:\Windows\System32), userprofile.
Calls load():
GDT Setup: Configures Global Descriptor Table and segments (CS, DS, FS, GS) for x86/x64.
Component Setup: Initializes managers for handles, registry, clipboard, fibers, and threads.
WinAPI Hooking: Registers a code hook (hook_winapi) on all instructions to intercept API calls.
5. Emulation Start (ql.run())
Updates entry/exit points, timeout, and instruction count from CLI args.
Initializes debugger if specified (e.g., GDB).
Applies binary patches (do_bin_patch).
Writes an exit trap to detect program termination.
Calls os.run():
Sets final entry/exit addresses.
Invokes ql.emu_start(begin, end, timeout, count).
6. Active Emulation (emu_start)
Calls self.uc.emu_start() (Unicorn's emulation loop).
During execution:
The hook_winapi code hook triggers on each instruction.
If the current address matches an imported function (from import_symbols), it:
Resolves the API name (e.g., MessageBoxA).
Looks up the hook implementation (user-defined or built-in in qiling.os.windows.dlls).
Executes the hook (e.g., simulates MessageBoxA by logging or returning mock values).
If no hook exists, logs a warning and optionally stops if debug_stop is set.
Memory, registry, and thread operations are handled by the respective managers.
Emulation continues until exit point, timeout, or error.
7. Post-Emulation Cleanup
Saves registry state.
Logs statistics (e.g., syscall counts).
Generates a report if requested (--json).
This process ensures the Windows binary runs in a sandboxed environment with emulated APIs, memory, and system structures, allowing cross-platform execution without native Windows dependencies.