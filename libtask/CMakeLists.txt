cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project("dog_cryption_task" VERSION 1.0)

add_library(libdog_cryption_task STATIC)
target_sources(libdog_cryption_task 
PRIVATE
    include/task/task.h
    src/task.cpp
)

add_library(dlldog_cryption_task SHARED)
set_target_properties(dlldog_cryption_task PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/dlldog_cryption_task")
target_compile_definitions(dlldog_cryption_task PRIVATE SHARED DOG_TASK_CORE_EXPORT)
target_sources(dlldog_cryption_task
PRIVATE
    include/task/export.h
    include/task/task.h
    src/task.cpp
)
target_link_libraries(dlldog_cryption_task PRIVATE dlldog_cryption_core)