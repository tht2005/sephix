cmake_minimum_required(VERSION 3.10)

project(SEPHIX VERSION 0.1.0)

set(SYSCONF_DIR "/etc/sephix" CACHE STRING "")
option(YYDEBUG "" OFF)

# Dependencies

find_package(FLEX 2.6.4 REQUIRED)
find_package(BISON 3.8.2 REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(CONFUSE REQUIRED libconfuse)

# Configure

configure_file(
	${CMAKE_SOURCE_DIR}/include/sephix_build_config.h.in
	${CMAKE_BINARY_DIR}/include/sephix_build_config.h
)

# flex_target(config_lexer ${CMAKE_SOURCE_DIR}/src/config/lexer.l 
# 	${CMAKE_BINARY_DIR}/src/config_lexer.c
# 	DEFINES_FILE ${CMAKE_BINARY_DIR}/include/config_lexer.h
# )
# bison_target(config_parser ${CMAKE_SOURCE_DIR}/src/config/parser.y
# 	${CMAKE_BINARY_DIR}/src/config_parser.tab.c
# 	DEFINES_FILE ${CMAKE_BINARY_DIR}/include/config_parser.tab.h
# )
# add_flex_bison_dependency(config_lexer config_parser)

# Compile

file(GLOB_RECURSE SRC_FILES
	${CMAKE_SOURCE_DIR}/src/*.c
	${CMAKE_SOURCE_DIR}/include/*.h
	${CMAKE_BINARY_DIR}/src/*.c
	${CMAKE_BINARY_DIR}/include/*.h
)
add_executable(sephix
	${SRC_FILES}
	${FLEX_config_lexer_OUTPUTS}
	${BISON_config_parser_OUTPUTS}
)

target_include_directories(sephix
	PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_BINARY_DIR}/include
	PRIVATE ${FLEX_INCLUDE_DIRS} ${CONFUSE_INCLUDE_DIRS}
)

target_compile_definitions(sephix
	PRIVATE _GNU_SOURCE _XOPEN_SOURCE _DEFAULT_SOURCE
)
if (YYDEBUG)
	target_compile_definitions(sephix PRIVATE YYDEBUG)
endif()

target_link_libraries(sephix
	PRIVATE ${FLEX_LIBRARIES}
	PRIVATE ${CONFUSE_LIBRARIES}
)
