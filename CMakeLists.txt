cmake_minimum_required(VERSION 3.10)

project(SEPHIX VERSION 0.1.0)

set(SYSCONF_DIR "/etc/sephix" CACHE STRING "")

configure_file(
	${CMAKE_SOURCE_DIR}/include/sephix_config.h.in
	${CMAKE_BINARY_DIR}/include/sephix_config.h
)
file(GLOB_RECURSE SRC_FILES
	"${CMAKE_SOURCE_DIR}/src/*.c"
	"${CMAKE_SOURCE_DIR}/include/*.h"
)
add_executable(sephix ${SRC_FILES})
target_include_directories(sephix
	PRIVATE ${CMAKE_SOURCE_DIR}/include
	PRIVATE ${CMAKE_BINARY_DIR}/include
)
target_compile_definitions(sephix
	PRIVATE _GNU_SOURCE _XOPEN_SOURCE
)
