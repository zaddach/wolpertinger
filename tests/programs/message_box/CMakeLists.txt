cmake_minimum_required(VERSION 3.28)
project(tiny)

add_executable(tiny
	tiny.c
)

target_include_directories(tiny
	PRIVATE
		/usr/share/mingw-w64/include
)
