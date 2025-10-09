cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project("dog_cryption_core" VERSION 1.0)

set(resource_code_file
    include/cryption/dog_exception.h
    include/cryption/big_number.h
    include/cryption/data_bytes.h
    include/cryption/hash.h
    include/cryption/symmetric_encryption.h
    include/cryption/dog_cryption.h
    src/dog_exception.cpp
    src/big_number.cpp
    src/data_bytes.cpp
    src/hash.cpp
    src/symmetric_encryption.cpp
)

add_library(static_dog_cryption_core STATIC)
target_sources(static_dog_cryption_core
PRIVATE
    ${resource_code_file}
)

add_library(shared_dog_cryption_core SHARED)
set_target_properties(shared_dog_cryption_core PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/shared_dog_cryption_core")
target_compile_definitions(shared_dog_cryption_core PRIVATE SHARED DOG_CRYPTION_CORE_EXPORT)
target_sources(shared_dog_cryption_core
PRIVATE
    include/cryption/export.h
    ${resource_code_file}
)
#加一行注释…………之后会删掉