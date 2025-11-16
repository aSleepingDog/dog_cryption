cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories("${CMAKE_SOURCE_DIR}/dog_torch_task/include")

function(paking PATH ROOT)
    file(GLOB DIR RELATIVE "${CMAKE_SOURCE_DIR}/${ROOT}/${PATH}" ${PATH}/*)
    foreach(ITEM ${DIR})
        if(IS_DIRECTORY "${CMAKE_SOURCE_DIR}/${ROOT}/${PATH}/${ITEM}")
            paking("${PATH}/${ITEM}" "${ROOT}")
        else()
            list(APPEND FILES "${PATH}/${ITEM}")
        endif()
    endforeach(ITEM)
    string(REPLACE "include" "" PATH ${PATH})
    if(NOT PATH STREQUAL "")
        string(REPLACE "/" "\\\\" PATH ${PATH})
    endif()
    source_group("Header Files\\\\${PATH}" FILES ${FILES})
    # message("source_group(Header Files\\\\${PATH} FILES ${FILES})")
endfunction(paking PATH ROOT)

paking("include" "dog_torch_task")

include_directories("${CMAKE_SOURCE_DIR}/dog_torch_core/include")

file(GLOB_RECURSE resource_h_file RELATIVE "${CMAKE_SOURCE_DIR}/dog_torch_task" include/*.h)
file(GLOB_RECURSE resource_cpp_file RELATIVE "${CMAKE_SOURCE_DIR}/dog_torch_task" src/*.cpp)

set(resource_code_file "")
foreach (file ${resource_h_file})
    list(APPEND resource_code_file "${CMAKE_SOURCE_DIR}/dog_torch_task/${file}")
endforeach ()

foreach (file ${resource_cpp_file})
    list(APPEND resource_code_file "${CMAKE_SOURCE_DIR}/dog_torch_task/${file}")
endforeach ()

# message("${resource_code_file}")

add_library(static_dog_torch_task STATIC)
target_sources(static_dog_torch_task
PRIVATE
    ${resource_code_file}
)
target_link_libraries(static_dog_torch_task PRIVATE static_dog_torch_core)

add_library(shared_dog_torch_task SHARED)
set_target_properties(shared_dog_torch_task PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/shared_dog_torch_task")
target_compile_definitions(shared_dog_torch_task PRIVATE SHARED DOG_TASK_CORE_EXPORT)
target_sources(shared_dog_torch_task
PRIVATE
    include/task/export.h
    ${resource_code_file}
)
target_link_libraries(shared_dog_torch_task PRIVATE shared_dog_torch_core)