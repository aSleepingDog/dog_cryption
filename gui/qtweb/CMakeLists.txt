cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 23)

#将其改为本地的QT6.8.3版本
set(Qt6_DIR "E:/Qt/6.8.3/msvc2022_64/lib/cmake/Qt6")

set(CMAKE_PREFIX_PATH ${Qt6_DIR})
set(CMAKE_INCLUDE_CURRENT_DIR ON)

project("qtWeb")

find_package(Qt6 COMPONENTS 
    Core
    Gui
    Widgets
    WebEngineWidgets
    WebEngineCore
    WebChannel 
REQUIRED)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

add_executable(qtWebFileCheck)
set_target_properties(qtWebFileCheck PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/qtWebFileCheck")
target_sources(qtWebFileCheck
    PRIVATE
        file_check.cpp
)
target_link_libraries(qtWebFileCheck PRIVATE static_dog_cryption_core)

#出现Cannot find source file: file_check_hash. 请将qtWebFileCheck拖到gui/qtweb/目录下运行
add_executable(qtWebStatic)
set_target_properties(qtWebStatic PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/qtWebStatic")
target_sources(qtWebStatic
    PRIVATE
        file_check_hash.h
        qtwin.cpp
)
target_link_libraries(qtWebStatic PRIVATE static_dog_cryption_core static_dog_cryption_task Qt6::Core Qt6::Widgets Qt6::Gui Qt6::WebEngineWidgets)

add_executable(qtWebShared)
target_compile_definitions(qtWebShared PRIVATE SHARED)
set_target_properties(qtWebShared PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/qtWebShared")
target_sources(qtWebShared
    PRIVATE
        file_check_hash.h
        qtwin.cpp
)
target_link_libraries(qtWebShared PRIVATE shared_dog_cryption_core shared_dog_cryption_task Qt6::Core Qt6::Widgets Qt6::Gui Qt6::WebEngineWidgets)