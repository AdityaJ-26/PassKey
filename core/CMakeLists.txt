# core/CMakeLists.txt

add_library(core_lib)

target_compile_features(core_lib PRIVATE cxx_std_17)

target_sources(core_lib
	PRIVATE
		src/data.cpp
		src/system.cpp
		src/utils.cpp
		src/security.cpp
		src/user.cpp
		src/files.cpp
)

target_include_directories(core_lib
	PUBLIC
		"${CMAKE_CURRENT_SOURCE_DIR}/include"
	PRIVATE
		"${CMAKE_CURRENT_SOURCE_DIR}/src"
)

target_link_libraries(core_lib
	PUBLIC
		libsodium
)
