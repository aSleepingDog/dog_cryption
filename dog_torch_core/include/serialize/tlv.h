#pragma once
#ifdef SHARED
#include "export.h"
#else
#define DOG_CRYPTION_API
#endif
#include <any>
#include <map>
#include <array>
#include <vector>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <variant>
#include <iostream>
#include <unordered_map>

#include "BinaryData.h"
#include "math/integer.h"
#include "utils/Exception.h"

/**
```
	null                -> 0000 0000                                                          | 0
	bool                -> 0010 (0000/1111=false/true)                                        | 2
	int                 -> 100 (0/1=+/-) 0001-1000(0-8):length                                | 8
	float               -> 101X (4/8=float/double)                                            | A
	bytes               -> 010X 0000-1000(1-8):length length + int(length) + bytes            | 4
	string              -> 011X 0000-1000(1-8):length length + int(length) + bytes(utf8)      | 6
	array               -> 110X 0000-1000(1-8):length length + int(length) + other            | C
	object(hash table)  -> 111X 0000-1000(0-8):length length + int(length) + string:other     | E
```
*/
namespace dog_torch::serialize::tlv
{
	using BinaryData = dog_torch::serialize::BinaryData;

	/**
	* 类型安全的tlv值类
	*/
	class DOG_CRYPTION_API Value
	{
		using in_t = std::variant<
			std::nullptr_t,
			bool,
			uint64_t,
			int64_t,
			double,
			std::vector<uint8_t>,
			std::string,
			std::vector<Value>,
			std::unordered_map<std::string, Value>
		>;
	public:
		in_t value;
		Value();
		Value(in_t value);
		BinaryData to_bin_data() const;
	};

	/**
	* 将null转换成字节序 转换规则见命名空间注释
	*/
	DOG_CRYPTION_API BinaryData null_type();
	/**
	* 将null转换成字节序 转换规则见命名空间注释
	*/
	DOG_CRYPTION_API BinaryData null_type(std::nullptr_t value);

	/**
	* 将bool转换成字节序 转换规则见命名空间注释
	*/
	DOG_CRYPTION_API BinaryData boolean(bool b);

	/**
	* 将无符号整型转换成字节序 转换规则见命名空间注释
	*/
	DOG_CRYPTION_API BinaryData integer_num(uint64_t num);
	/**
	* 将有符号整型转换成字节序 转换规则见命名空间注释
	*/
	DOG_CRYPTION_API BinaryData integer_num(int64_t num);

	/**
	* 将IEEE754-32位浮点数转换成字节序 转换规则见命名空间注释
	*/
	DOG_CRYPTION_API BinaryData float_num(float num);
	/**
	* 将IEEE754-64位浮点数转换成字节序 转换规则见命名空间注释
	*/
	DOG_CRYPTION_API BinaryData float_num(double num);

	/**
	* 将字节序封装 转换规则见命名空间注释
	*/
	DOG_CRYPTION_API BinaryData bytes(const std::vector<uint8_t>& bytes);
	/**
	* 将字节序封装 转换规则见命名空间注释
	*/
	DOG_CRYPTION_API BinaryData bytes(const uint8_t* bytes, uint64_t size);
	/**
	* 将字节序封装 转换规则见命名空间注释
	*/
	DOG_CRYPTION_API BinaryData bytes(std::istream& stream);

	/**
	* 将utf8字符串转成字节序 转换规则见命名空间注释
	*/
	DOG_CRYPTION_API BinaryData string(const char* str);
	/**
	* 将utf8字符串转成字节序 转换规则见命名空间注释
	*/
	DOG_CRYPTION_API BinaryData string(std::string str);

	/**
	* 将子项为std:any的列表转换成字节序 转换规则见命名空间注释
	*/
	DOG_CRYPTION_API BinaryData array(const std::vector<std::any>& arr);
	/**
	* 将子项为tlv::Value的列表转换成字节序 转换规则见命名空间注释
	*/
	DOG_CRYPTION_API BinaryData array(const std::vector<Value>& arr);

	/**
	* 将子项为std:any的对应序列转换成字节序 转换规则见命名空间注释
	*/
	DOG_CRYPTION_API BinaryData object(const std::unordered_map<std::string, std::any>& obj);
	/**
	* 将子项为std:any的对应序列转换成字节序 转换规则见命名空间注释
	*/
	DOG_CRYPTION_API BinaryData object(const std::map<std::string, std::any>& obj);
	/**
	* 将子项为tlv::Value的对应序列转换成字节序 转换规则见命名空间注释
	*/
	DOG_CRYPTION_API BinaryData object(const std::unordered_map<std::string, Value>& obj);
	/**
	* 将子项为tlv::Value的对应序列转换成字节序 转换规则见命名空间注释
	*/
	DOG_CRYPTION_API BinaryData object(const std::map<std::string, Value>& obj);


	/**
	* 读取字节序并返回std:any
	*/
	DOG_CRYPTION_API std::any read_any(std::istream& data);
	/**
	* 读取字节序并返回std:any
	*/
	DOG_CRYPTION_API std::any read_any(const BinaryData& data);

	/**
	* 读取字节序并返回tlv::Value
	*/
	DOG_CRYPTION_API Value read_value(std::istream& data);
	/**
	* 读取字节序并返回tlv::Value
	*/
	DOG_CRYPTION_API Value read_value(const BinaryData& data);
};