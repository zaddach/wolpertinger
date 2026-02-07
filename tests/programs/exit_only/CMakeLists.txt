cmake_minimum_required(VERSION 3.10)

project(exit_only C)

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -nostartfiles -Wl,-e,_start")

add_executable(exit_only main.c)

# Link both msvcrt (for _exit) and kernel32 (for ExitProcess on x86_64)
target_link_libraries(exit_only msvcrt kernel32)