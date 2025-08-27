# 简单的密码学程序

## 简介

一个用于密码学的C++第三方库，同时使用了Qt web制作了界面方便非开放人员使用

## 算法支持

### 散列

SHA2全系

SM3

### 对称加密

AES全系

SM4

camellia全系

## 设计

```C++
namespace dog_number
{
    class      NumberException;         //抛出的异常
    namespace  integer;                 //对uintXX_t封装的相关操作
    namespace  galois_field;            //伽罗瓦域的操作
    namespace  region;                  //范围字符串的操作
    class      BigInteger;              //封装的高精度整数类,支持 加 减 乘 求绝对值 输出二进制 八进制 十进制 十六进制 的快速操作
}
```

```C++
namespace dog_data
{
    class      Data;                    //封装的std::vector<uint8_t>在原有基础上,支持 utf-8 hex base64类型字符串的导出导出 前后移动操作
    class      DataStream:              //封装的Data流对象,支持单独输出每个字符
    namespace  serialize;               //内部的序列化方法
    namespace  print;                   //针对Data的控制台打印方法
}
```

```c++
namespace dog_hash
{
    class HashException;               //散列的通用异常
    class HashConfig;                  //散列展示配置
    class HashCrypher;                 //散列发生器
    namespace <算法名>                  //散列算法的实现
}
```

```C++
namespace dog_cryption
{
	namespace utils;                    //算法通用的工具方法
    class CryptionException;            //算法通用的异常
    class WrongKeyException;            //密钥错误的异常
    class WrongConfigException;         //配置错误的异常
    class CryptionConfig;               //加解密器配置类
    class Cryptor;                      //加解密器类
    namespace padding;                  //填充方法
    namespace mode;                     //工作模式方法
    class AlgorithmConfig;              //加解密算法展示配置
}
```

## 使用

### 程序体验

#### Windows10及以上

进入Release下载支持的版本(为确保程序不被篡改,请务必校验散列值后使用),解压后运行mainWin.exe

### 库使用(cmake构建)

```cmake
add_subdirectory(libcryption)
add_subdirectory(libtask)

#静态库
add_executable(项目名)
target_sources(项目名
    PRIVATE
       你的代码源文件.cpp
)
target_link_libraries(项目名 PRIVATE libdog_cryption_core)

#动态库
add_executable(项目名)
target_compile_definitions(项目名 PRIVATE SHARED)#记得加上宏定义或者在构建时设置宏定义
target_sources(项目名
    PRIVATE
        你的代码源文件.cpp
)
target_link_libraries(项目名 PRIVATE dlldog_cryption_core)
#构建完成时记得复制构建的.dll(windows)或.so(linux)到当前可执行程序下或者到系统目录下
```



