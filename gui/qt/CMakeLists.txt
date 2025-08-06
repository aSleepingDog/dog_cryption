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

add_executable(qtWeb)
set_target_properties(qtWeb PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/main")
target_sources(qtWeb
    PRIVATE
        qtwin.cpp
)
target_link_libraries(qtWeb PRIVATE dog_cryption_core dog_cryption_task Qt6::Core Qt6::Widgets Qt6::Gui Qt6::WebEngineWidgets)