cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project("dog_cryption_task" VERSION 1.0)

set(resource_code_file
    include/task/task.h
    include/task/param.h
    src/task.cpp
    src/param.cpp
)

add_library(static_dog_cryption_task STATIC)
target_sources(static_dog_cryption_task 
PRIVATE
    ${resource_code_file}
)
target_link_libraries(static_dog_cryption_task PRIVATE static_dog_cryption_core)

add_library(shared_dog_cryption_task SHARED)
set_target_properties(shared_dog_cryption_task PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/shared_dog_cryption_task")
target_compile_definitions(shared_dog_cryption_task PRIVATE SHARED DOG_TASK_CORE_EXPORT)
target_sources(shared_dog_cryption_task
PRIVATE
    include/task/export.h
    ${resource_code_file}
)
target_link_libraries(shared_dog_cryption_task PRIVATE shared_dog_cryption_core)