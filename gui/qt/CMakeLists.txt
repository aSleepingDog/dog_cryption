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

add_executable(qtWebStatic)
set_target_properties(qtWebStatic PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/qtWebStatic")
target_sources(qtWebStatic
    PRIVATE
        qtwin.cpp
)
target_link_libraries(qtWebStatic PRIVATE libdog_cryption_core libdog_cryption_task Qt6::Core Qt6::Widgets Qt6::Gui Qt6::WebEngineWidgets)

add_executable(qtWebShared)
target_compile_definitions(qtWebShared PRIVATE SHARED)
set_target_properties(qtWebShared PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/qtWebShared")
target_sources(qtWebShared
    PRIVATE
        qtwin.cpp
)
target_link_libraries(qtWebShared PRIVATE dlldog_cryption_core dlldog_cryption_task Qt6::Core Qt6::Widgets Qt6::Gui Qt6::WebEngineWidgets)