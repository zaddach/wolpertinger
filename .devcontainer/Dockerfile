FROM mcr.microsoft.com/devcontainers/rust:trixie

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        libunicorn-dev \
        libclang-dev \
        pkgconf \
        cmake \
        gcc-mingw-w64-i686-win32 \
        gcc-mingw-w64-i686-win32-runtime \
        gcc-mingw-w64-x86-64-win32 \
        gcc-mingw-w64-x86-64-win32-runtime && \
    rm -rf /var/lib/apt/lists/*

USER vscode
RUN cargo install cargo-make
    

