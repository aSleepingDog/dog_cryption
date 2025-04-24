cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 23)

#set(Qt6_DIR "E:/Qt/6.8.3/msvc2022_64/lib/cmake/Qt6")

set(CMAKE_PREFIX_PATH ${Qt6_DIR})
set(CMAKE_INCLUDE_CURRENT_DIR ON)

project("dog_cryption" VERSION 1.0 DESCRIPTION "A simple C++ library for encryption and decryption written by dog")

find_package(Qt6 COMPONENTS 
    Core
    Gui
    Widgets
    WebEngineWidgets
    WebEngineCore
    WebChannel 
REQUIRED)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}../../../bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}../../../lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}../../../lib)

add_library(dog_cryption)
target_sources(dog_cryption
    PRIVATE
        lib/big_number.h
        lib/big_number.cpp
        lib/data_bytes.h
        lib/data_bytes.cpp
        lib/hash_method.h
        lib/hash_method.cpp
        lib/symmetric_encryption.h
        lib/symmetric_encryption.cpp
        lib/dog_cryption.h
)

add_library(dog_cryption_task)
target_sources(dog_cryption_task
    PRIVATE
        extend/util.h
        extend/util.cpp
)
target_link_libraries(dog_cryption_task PRIVATE dog_cryption)

add_executable(cmd_test)
set_target_properties(cmd_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/cmd_test")
target_sources(cmd_test
    PRIVATE
        test/cmd_test.cpp
)
target_link_libraries(cmd_test PRIVATE dog_cryption)

add_executable(bigInteger_radix_test)
set_target_properties(bigInteger_radix_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/bigInteger_radix_test")
target_sources(bigInteger_radix_test
    PRIVATE
    test/bigInteger_radix/test.cpp
)
target_link_libraries(bigInteger_radix_test PRIVATE dog_cryption)

add_executable(bigInteger_add_test)
set_target_properties(bigInteger_add_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/bigInteger_add_test")
target_sources(bigInteger_add_test
    PRIVATE
    test/bigInteger_add/test.cpp
)
target_link_libraries(bigInteger_add_test PRIVATE dog_cryption)

add_executable(bigInteger_multiply_test)
set_target_properties(bigInteger_multiply_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/bigInteger_multiply_test")
target_sources(bigInteger_multiply_test
    PRIVATE
    test/bigInteger_multiply/ctest0.cpp
    test/bigInteger_multiply/ctest1.cpp
)
target_link_libraries(bigInteger_multiply_test PRIVATE dog_cryption)

add_executable(hash_text_test)
set_target_properties(hash_text_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/hash_text_test")
target_sources(hash_text_test
    PRIVATE
        test/hash_text/hash_text_test.cpp
)
target_link_libraries(hash_text_test PRIVATE dog_cryption)

add_executable(hash_file_test)
set_target_properties(hash_file_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/hash_file_test")
target_sources(hash_file_test
    PRIVATE
        test/hash_file/hash_file_test.cpp
)
target_link_libraries(hash_file_test PRIVATE dog_cryption)

add_executable(crypt_text_test)
set_target_properties(crypt_text_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/crypt_text_test")
target_sources(crypt_text_test
    PRIVATE
        test/crypt_text/crypt_text_test.cpp
)
target_link_libraries(crypt_text_test PRIVATE dog_cryption)

add_executable(crypt_file_test)
set_target_properties(crypt_file_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/crypt_file_test")
target_sources(crypt_file_test
    PRIVATE
        test/crypt_file/crypt_file_test.cpp
)
target_link_libraries(crypt_file_test PRIVATE dog_cryption)


set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

add_executable(mainWin)
set_target_properties(mainWin PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/main")
target_sources(mainWin
    PRIVATE
        win/qtwin.cpp
)
target_link_libraries(mainWin PRIVATE dog_cryption dog_cryption_task Qt6::Core Qt6::Widgets Qt6::Gui Qt6::WebEngineWidgets)