# 简单的密码学程序

## 简介

一个用于密码学的C++第三方库，还有一些其他的工具封装

### 使用(CMake构建)

```cmake
add_subdirectory(dog_torch_core)

#静态库
add_executable(项目名)
target_sources(项目名
    PRIVATE
       你的代码源文件.cpp
)
target_link_libraries(项目名 PRIVATE static_dog_torch_core)

#动态库
add_executable(项目名)
target_compile_definitions(项目名 PRIVATE SHARED)#记得加上宏定义或者在构建时设置宏定义
target_sources(项目名
    PRIVATE
        你的代码源文件.cpp
)
target_link_libraries(项目名 PRIVATE shared_dog_torch_core)
#构建完成时记得复制构建的.dll(windows)或.so(linux)到当前可执行程序下或者到系统目录下
```
