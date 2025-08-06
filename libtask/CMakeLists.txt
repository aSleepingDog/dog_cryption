cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project("dog_cryption_task" VERSION 1.0)

add_library(dog_cryption_task STATIC)
target_sources(dog_cryption_task 
PRIVATE
    include/task/task.h
    src/task.cpp
)