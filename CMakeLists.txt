# root CMakeLists.txt

cmake_minimum_required(VERSION 3.31)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED False)

project(PassKey)


# -----libsodium-----
add_library(libsodium SHARED IMPORTED)

if (LINUX)
	set_target_properties(libsodium PROPERTIES
		IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium/libsodium.so"
		INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium"
	)
elseif (WIN32)
	set_target_properties(libsodium PROPERTIES
		IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium/libsodium.dll"
		IMPORTED_IMPLIB "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium/libsodium.lib"
		INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium"
	)
endif()


add_subdirectory(core/)

# -----TARGET-----
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

# -----post build operations-----
if (WIN32)
    add_custom_command(TARGET passkey POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium/libsodium.dll"
            "$<TARGET_FILE_DIR:passkey>"
        COMMENT "Copying libsodium.dll to executable directory"
    )
endif()
