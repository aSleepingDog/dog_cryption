cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project("dog_cryption" VERSION 1.0 DESCRIPTION "A simple C++ library for encryption and decryption written by dog")

if(MSVC)
    #add_compile_options(/W0)
else()
    add_compile_options(-w)
endif()
#set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}../../../bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}../../../dll)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}../../../lib)

add_subdirectory(libcryption)
add_subdirectory(libtask)

add_subdirectory(test)
add_subdirectory(gui/qt)