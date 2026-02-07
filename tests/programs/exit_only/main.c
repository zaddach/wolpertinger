#if defined(__i386__)
extern void _exit(int);
void start() {
    _exit(0);
}
#elif defined(__x86_64__)
extern void ExitProcess(int);


__attribute__((naked))
void start() {
    __asm__(
        ".intel_syntax noprefix\n"
        "sub rsp, 32\n"
        "xor rcx, rcx\n"
        "call ExitProcess\n"
    );
}
#else
#error "Unsupported architecture for tests/programs/exit_only"
#endif