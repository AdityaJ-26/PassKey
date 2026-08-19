# root CMakeLists.txt

cmake_minimum_required(VERSION 3.31)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED False)

project(PassKey)

# libsodium
add_library(libsodium SHARED IMPORTED)

if (LINUX)
	set_target_properties(libsodium PROPERTIES
		IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium/libsodium.so"
		INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium"
	)
elseif (WIN32)
	if (CMAKE_BUILD_TYPE STREQUAL "Debug")
		set_target_properties(libsodium PROPERTIES
			IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium/debug/libsodium.dll"
			IMPORTED_IMPLIB "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium/debug/libsodium.lib"
			INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium"
			)
	else()
		set_target_properties(libsodium PROPERTIES
			IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium/release/libsodium.dll"
			IMPORTED_IMPLIB "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium/release/libsodium.lib"
			INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium"
		)
	endif()
endif()

add_subdirectory(core)

add_executable(passkey main.cpp)

target_link_libraries(passkey
	PRIVATE
		libsodium
		core_lib
)


# TARGET
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

if (WIN32)
	add_custom_command(TARGET passkey POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<$<CONFIG:Debug>:${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium/debug/libsodium.dll>"
            "$<$<NOT:$<CONFIG:Debug>>:${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium/release/libsodium.dll>"
            "$<TARGET_FILE_DIR:passkey>"
        COMMENT "Copying libsodium.dll to executable directory"
    )
endif()
