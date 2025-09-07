cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 23)

project("cmd")

add_executable(cmdStatic)
set_target_properties(cmdStatic PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/cmdStatic")
target_sources(cmdStatic
    PRIVATE
        cmd.cpp
)
target_link_libraries(cmdStatic PRIVATE libdog_cryption_core libdog_cryption_task)

add_executable(cmdShared)
target_compile_definitions(cmdShared PRIVATE SHARED)
set_target_properties(cmdShared PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/cmdShared")
target_sources(cmdShared
    PRIVATE
        cmd.cpp
)
target_link_libraries(cmdShared PRIVATE dlldog_cryption_core dlldog_cryption_task)