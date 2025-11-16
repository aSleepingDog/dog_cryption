cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

#这里请改成你自己的vcpkg路径
set(CMAKE_PREFIX_PATH cmake "E:\\C\\vcpkg_master\\installed\\x64-windows")

if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")

elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")

else()

endif()

project("dog_torch" VERSION 1.0 DESCRIPTION "A simple C++ library for encryption and decryption written by dog")

if(MSVC)
    #add_compile_options(/W0)
else()
    add_compile_options(-w)
endif()
#set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/dll)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)


add_subdirectory(dog_torch_core)
add_subdirectory(dog_torch_task)


include_directories("${CMAKE_SOURCE_DIR}/dog_torch_task/include")
include_directories("${CMAKE_SOURCE_DIR}/dog_torch_core/include")

add_subdirectory(test)
add_subdirectory(application/cmd)
add_subdirectory(application/qtweb)
add_subdirectory(application/oatpp_server)