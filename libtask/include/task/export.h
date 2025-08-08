#pragma once
// 导出符号宏定义
#ifdef DOG_TASK_CORE_EXPORT
    #ifdef _WIN32
        #define DOG_TASK_API __declspec(dllexport)
    #else
        #define DOG_TASK_API __attribute__((visibility("default")))
    #endif
#else
    #ifdef _WIN32
        #define DOG_TASK_API __declspec(dllimport)
    #else
        #define DOG_TASK_API
    #endif
#endif