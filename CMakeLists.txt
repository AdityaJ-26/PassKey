# root CMakeLists.txt

cmake_minimum_required(VERSION 3.31)

project(PassKey)

# ------------------------
# libsodium
# ------------------------
add_library(libsodium SHARED IMPORTED)

set_target_properties(libsodium PROPERTIES
	IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium/libsodium.so.26.3.0"
	INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium"
)

add_subdirectory(core)

add_executable(passkey main.cpp)

target_link_libraries(passkey
	PRIVATE
		libsodium
		core_lib
)

target_sources(passkey
	PRIVATE
		cli/src/cli.cpp
	PRIVATE
		FILE_SET cli_header
		TYPE HEADERS
		BASE_DIRS
			cli/src
		FILES
			cli/src/cli.h
)
