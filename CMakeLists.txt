cmake_minimum_required(VERSION 3.10)

project(SEPHIX VERSION 0.1.0)

set(SYSCONF_DIR "/etc/sephix" CACHE STRING "")
# Dependencies

find_package(PkgConfig REQUIRED)
pkg_check_modules(CONFUSE REQUIRED libconfuse)

# Configure

configure_file(
	${CMAKE_SOURCE_DIR}/include/sephix_build_config.h.in
	${CMAKE_BINARY_DIR}/include/sephix_build_config.h
)

# Compile

file(GLOB_RECURSE SRC_FILES
	${CMAKE_SOURCE_DIR}/src/*.c
	${CMAKE_SOURCE_DIR}/include/*.h
	${CMAKE_BINARY_DIR}/src/*.c
	${CMAKE_BINARY_DIR}/include/*.h
)
add_executable(sephix ${SRC_FILES})
target_include_directories(sephix
	PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_BINARY_DIR}/include
	PRIVATE ${FLEX_INCLUDE_DIRS} ${CONFUSE_INCLUDE_DIRS}
)

target_compile_definitions(sephix
	PRIVATE _GNU_SOURCE _XOPEN_SOURCE _DEFAULT_SOURCE
)
target_link_libraries(sephix
	PRIVATE ${CONFUSE_LIBRARIES}
)
