cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 23)

add_subdirectory(libcryption)
add_subdirectory(libtask)

add_executable(cmd_test)
set_target_properties(cmd_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/cmd_test")
target_sources(cmd_test
    PRIVATE
        test/cmd_test.cpp
)
target_link_libraries(cmd_test PRIVATE dog_cryption dog_cryption_task)

add_executable(crypt_file_test)
set_target_properties(crypt_file_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/crypt_file_test")
target_sources(crypt_file_test
    PRIVATE
        test/crypt_file/crypt_file_test.cpp
)
target_link_libraries(crypt_file_test PRIVATE dog_cryption)

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