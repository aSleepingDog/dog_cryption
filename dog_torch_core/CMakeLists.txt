cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

function(packing PATH ROOT)
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
endfunction(packing PATH ROOT)

packing("include" "dog_torch_core")

include_directories("${CMAKE_SOURCE_DIR}/dog_torch_core/include")

file(GLOB_RECURSE resource_h_file RELATIVE "${CMAKE_SOURCE_DIR}/dog_torch_core" include/*.h)
file(GLOB_RECURSE resource_cpp_file RELATIVE "${CMAKE_SOURCE_DIR}/dog_torch_core" src/*.cpp)

set(resource_code_file "")
foreach (file ${resource_h_file})
    list(APPEND resource_code_file "${CMAKE_SOURCE_DIR}/dog_torch_core/${file}")
endforeach ()

foreach (file ${resource_cpp_file})
    list(APPEND resource_code_file "${CMAKE_SOURCE_DIR}/dog_torch_core/${file}")
endforeach ()

#foreach(files ${resource_code_file})
#    message("${files}")
#endforeach()

add_library(static_dog_torch_core STATIC)
target_sources(static_dog_torch_core
PRIVATE
    ${resource_code_file}
)

add_library(shared_dog_torch_core SHARED)
set_target_properties(shared_dog_torch_core PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/shared_dog_torch_core")
target_compile_definitions(shared_dog_torch_core PRIVATE SHARED DOG_TORCH_CORE_EXPORT)
target_sources(shared_dog_torch_core
PRIVATE
    ${resource_code_file}
)