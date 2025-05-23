#include "big_number.h"
#include "data_bytes.h"
#include "hash_method.h"
#include "symmetric_encryption.h"
/*
* 2025.5.16
* 开始对之前的代码进行整理,确认使用Google的代码规范
* 2025.5.17
* 基本对之前的标识符进行修改,统一了对称加密算法的规定函数
* 重写部分加密配置类,使其能添加额外的配置
* 2025.5.22
* 完成camelia密钥扩展,单例校验通过
*/