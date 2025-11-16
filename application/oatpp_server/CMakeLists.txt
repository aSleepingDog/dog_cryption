cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(OATPP_SRC)

include_directories("${CMAKE_SOURCE_DIR}/application/oatpp_server/include")

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

paking("include" "application/oatpp_server")

file(GLOB CPP_FILES RELATIVE "${CMAKE_SOURCE_DIR}/application/oatpp_server" src/*.cpp)
file(GLOB_RECURSE HEADER_FILES RELATIVE "${CMAKE_SOURCE_DIR}/application/oatpp_server" include/*.h)
list(APPEND OATPP_SRC ${HEADER_FILES})
list(APPEND OATPP_SRC ${CPP_FILES})
list(APPEND OATPP_SRC "main_server.cpp")

find_package(oatpp          1.3.0 REQUIRED)
find_package(oatpp-swagger  1.3.0 REQUIRED)

add_executable(oatppServerStatic)
set_target_properties(oatppServerStatic PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/oatppServerStatic")
target_sources(oatppServerStatic
    PRIVATE
    ${OATPP_SRC}
)
target_link_libraries(oatppServerStatic 
PRIVATE
    static_dog_torch_core
    static_dog_torch_task
    oatpp::oatpp
    oatpp::oatpp-swagger
)
target_compile_definitions(oatppServerStatic 
PRIVATE
    OATPP_DISABLE_LOGV=1
    OATPP_DISABLE_LOGD=1
)