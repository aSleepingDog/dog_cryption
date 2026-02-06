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

#include "utils/Exception.h"

namespace dog_torch::serialize
{
	/**
	* 封装的字节序
	*/
	class DOG_CRYPTION_API BinaryData
	{
	private:
		/**
		* 内部字节序
		*/
		std::vector<uint8_t> inside_data;
	public:
		/**
		* UTF8指示位
		*/
		const static int UTF8 = 0;
		/**
		* Base64指示位
		*/
		const static int BASE64 = 1;
		/**
		* Hex 16进制指示位
		*/
		const static int HEX = 2;

		/**
		* 默认构造函数 字节序为空
		*/
		BinaryData() = default;
		/**
		* 按照指示位解析字符串 如果指示位不为 0 1 2时则为空
		* @param str 字符串
		* @param type 指示位 默认按照Hex 16进制解析
		*/
		BinaryData(std::string str, const int type = 2);
		/**
		* 按照指示位解析C style字符串 如果指示位不为 0 1 2时则为空
		* @param str 字符串
		* @param type 指示位 默认按照Hex 16进制解析
		*/
		BinaryData(const char* str, const int type = 2) : BinaryData(std::string(str), type) {};
		/**
		* 从std::vector<uint8_t>构造字节序
		*/
		BinaryData(const std::vector<uint8_t>& data);
		/**
		* 预先分配空间构造字节序 同std::vector<>(size)
		*/
		BinaryData(uint64_t size);

		/**
		* 拷贝构造
		*/
		BinaryData(const BinaryData& other);
		/**
		* 拷贝赋值
		*/
		BinaryData operator=(const BinaryData& other);
		/**
		* 移动构造
		*/
		BinaryData(BinaryData&& other) noexcept;
		/**
		* 移动赋值
		*/
		BinaryData operator=(BinaryData&& other) noexcept;
		/**
		* 析构函数
		*/
		~BinaryData();

		/**
		* @return 索引i的左值引用
		*/
		uint8_t& at(uint64_t i);
		/**
		* @return 索引i的常量左值引用
		*/
		const uint8_t& at(uint64_t i) const;
		/**
		* @return 索引i的左值引用
		*/
		uint8_t& operator[](uint64_t i);
		/**
		* @return 索引i的常量左值引用
		*/
		const uint8_t& operator[](uint64_t i) const;
		/**
		* @return 返回第一个引用
		*/
		uint8_t& front();
		/**
		* @return 返回最后一个引用
		*/
		uint8_t& back();
		/**
		* @return 返回缓冲区第一个地址
		*/
		uint8_t* data();
		/**
		* @return 返回缓冲区第一个常量地址
		*/
		const uint8_t* data() const;
		/**
		* @return 返回缓冲区第一个地址
		*/
		int8_t* char_data();

		/**
		* 迭代器别名
		*/
		using it = std::vector<uint8_t>::iterator;
		/**
		* 常量迭代器别名
		*/
		using cit = std::vector<uint8_t>::const_iterator;
		/**
		* 倒序迭代器别名
		*/
		using rit = std::reverse_iterator<it>;
		/**
		* 倒序常量迭代器别名
		*/
		using crit = std::reverse_iterator<cit>;

		/**
		* @return 第一个迭代器
		*/
		it   begin();
		/**
		* @return 最后一个迭代器
		*/
		it   end();
		/**
		* @return 第一个常量迭代器
		*/
		cit  cbegin() const;
		/**
		* @return 最后一个常量迭代器
		*/
		cit  cend() const;
		/**
		* @return 倒序第一个迭代器
		*/
		rit  rbegin();
		/**
		* @return 倒序最后一个迭代器
		*/
		rit  rend();
		/**
		* @return 倒序第一个常量迭代器
		*/
		crit crbegin() const;
		/**
		* @return 倒序最后一个常量迭代器
		*/
		crit crend() const;

		/**
		* 转std::vector<byte>
		*/
		std::vector<uint8_t> to_byte_vector() const;
		/**
		* 转编码为utf8的std::vector<char>
		*/
		std::vector<char> to_utf8_vector() const;
		/**
		* 转编码为Base64的std::vector<char>
		*/
		std::vector<char> to_base64_vector() const;
		/**
		* 转编码为Base64的std::vector<char> 用a替代+ 用b替代/
		* @param a 替代+的字符
		* @param b 替代/的字符
		*/
		std::vector<char> to_base64_vector(char a, char b) const;
		/**
		* 转编码为Base64的std::vector<char> 用a替代+ 用b替代/ 用c替换=
		* @param a 替代+的字符
		* @param b 替代/的字符
		* @param c 替代=的字符
		*/
		std::vector<char> to_base64_vector(char a, char b, char c) const;
		/**
		* 转编码为Hex的std::vector<char>
		* @param is_upper 输出字母是否大写
		*/
		std::vector<char> to_hex_vector(bool is_upper = true) const;

		/**
		* 转编码为utf8的std::string
		*/
		std::string to_utf8_string() const;
		/**
		* 转编码为Base64的std::string
		*/
		std::string to_base64_string() const;
		/**
		* 转编码为Base64的std::vector<char> 用a替代+ 用b替代/
		* @param a 替代+的字符
		* @param b 替代/的字符
		*/
		std::string to_base64_string(char a, char b) const;
		/**
		* 转编码为Base64的std::vector<char> 用a替代+ 用b替代/ 用c替代=
		* @param a 替代+的字符
		* @param b 替代/的字符
		* @param c 替代=的字符
		*/
		std::string to_base64_string(char a, char b, char c) const;
		/**
		* 转编码为Hex的std::string
		* @param is_upper 输出字母是否大写
		*/
		std::string to_hex_string(bool is_upper = true) const;
		/**
		* 转编码为Bin的std::string
		*/
		std::string to_bin_string() const;

		/**
		* 截取字节序
		* @param start 开始位置
		* @param end 结束位置
		* @result 截取从start开始 到end前一个结束的子字节序 [start,end)
		*/
		BinaryData sub_bytes_by_pos(uint64_t start, uint64_t end) const;
		/**
		* 按字节截取字节序
		* @param start 开始位置
		* @param len 截取字节长度
		* @result 截取从start开始 截取len个字节组成字节序 剩余长度不够则提前停止
		*/
		BinaryData sub_bytes_by_len(uint64_t start, uint64_t len) const;
		/**
		* 按字节截取字节序
		* @param start 开始位置
		* @param end 结束位置
		* @result 截取从start开始 到end前一个结束的子字节序 [start,end)
		*/
		BinaryData sub_bytes_by_pos(std::vector<uint8_t>::iterator start, std::vector<uint8_t>::iterator end) const;
		/**
		* 按字节截取字节序
		* @param start 开始位置
		* @param len 截取字节长度
		* @result 截取从start开始 截取len个字节组成字节序 剩余长度不够则提前停止
		*/
		BinaryData sub_bytes_by_len(std::vector<uint8_t>::iterator start, uint64_t len) const;

		/**
		* 按位截取字节序
		* @param start 字节开始位置
		* @param start_bit_pos 开始字节内部开始位置
		* @param end 字节结束位置
		* @param end_bit_pos 结束字节结束位置
		* @result 从第start字节第start_bit_pos位开始 到第end自己第end_bit_pos位前结束 剩余长度不够则提前停止 剩余位不满一字节后补0
		*/
		BinaryData sub_bits_by_pos(uint64_t start, uint64_t start_bit_pos, uint64_t end, uint64_t end_bit_pos) const;
		/**
		* 按位截取字节序
		* @param start 字节开始位置
		* @param start_bit_pos 开始字节内部开始位置
		* @param len 截取位长度
		* @result 从第start字节第start_bit_pos位开始 截取len个位 剩余长度不够则提前停止 剩余位不满一字节后补0
		*/
		BinaryData sub_bits_by_len(uint64_t start, uint64_t start_bit_pos, uint64_t len) const;
		/**
		* 按位截取字节序
		* @param start 字节开始位置
		* @param start_bit_pos 开始字节内部开始位置
		* @param end 字节结束位置
		* @param end_bit_pos 结束字节结束位置
		* @result 从第start字节第start_bit_pos位开始 到第end自己第end_bit_pos位前结束 剩余长度不够则提前停止 剩余位不满一字节后补0
		*/
		BinaryData sub_bits_by_pos(std::vector<uint8_t>::iterator start, uint64_t start_bit_pos, std::vector<uint8_t>::iterator end, uint64_t end_bit_pos) const;
		/**
		* 按位截取字节序
		* @param start 字节开始位置
		* @param start_bit_pos 开始字节内部开始位置
		* @param len 截取位长度
		* @result 从第start字节第start_bit_pos位开始 截取len个位 剩余长度不够则提前停止 剩余位不满一字节后补0
		*/
		BinaryData sub_bits_by_len(std::vector<uint8_t>::iterator start, uint64_t start_bit_pos, uint64_t len) const;

		/**
		* @result 字节串是否为空
		*/
		bool empty() const;
		/**
		* @result 字节串字节数量
		*/
		uint64_t size() const;
		/**
		* @result 字节串预分配存储字节数量
		*/
		uint64_t max_size() const;
		/**
		* 预留n个字节位置
		*/
		void reserve(uint64_t n);

		/**
		* 在i位置后插入一个b
		*/
		void insert(const uint64_t i, uint8_t b);
		/**
		* 在pos位置后插入一个b
		*/
		void insert(const std::vector<uint8_t>::iterator pos, uint8_t b);

		/**
		* 删除i处
		*/
		void erase(const uint64_t i);
		/**
		* 删除pos处
		*/
		void erase(const std::vector<uint8_t>::iterator pos);

		/**
		* 清除所有数据,不保留位置
		* 等效于vector.clear()
		*/
		void rm_pos();
		/**
		* 将所有位置重置为0
		*/
		void set_zero();

		/**
		* 末尾加入b
		*/
		void push_back(uint8_t b);
		/**
		* 末尾删除
		*/
		void pop_back();

		/**
		* 颠倒顺序 
		*/
		void reverse();

		/**
		* 交换两个字节序内容
		*/
		void swap(BinaryData& d);
		
		/**
		* @return 按位不扩容左移shift字节序
		*/
		BinaryData bit_left_move_norise(uint64_t shift);
		/**
		* 按位不扩容自左移shift字节序
		*/
		void bit_left_move_norise_self(uint64_t shift);

		/**
		* @return 按位扩容左移shift字节序
		*/
		BinaryData bit_left_move_rise(uint64_t shift);
		/**
		* 按位扩容自左移shift字节序
		*/
		void bit_left_move_rise_self(uint64_t shift);

		/**
		* @return 按位不扩容右移shift字节序
		*/
		BinaryData bit_right_move_norise(uint64_t shift);
		/**
		* 按位不扩容自右移shift字节序
		*/
		void bit_right_move_norise_self(uint64_t shift);

		/**
		* @return 按位扩容右移shift字节序
		*/
		BinaryData bit_right_move_rise(uint64_t shift);
		/**
		* 按位扩容自右移shift字节序
		*/
		void bit_right_move_rise_self(uint64_t shift);

		/**
		* 按位循环左移
		*/
		BinaryData bit_circle_left_move(uint64_t shift);
		/**
		* 按位循环右移
		*/
		BinaryData bit_circle_right_move(uint64_t shift);

		/**
		* 判断是否与d字节序相同
		*/
		bool is_equal(const BinaryData& d) const;
		/**
		* 判断是否与d字节序相同
		*/
		DOG_CRYPTION_API friend bool operator==(const BinaryData& d1, const BinaryData& d2);
		/**
		* 判断是否与d字节序不同
		*/
		DOG_CRYPTION_API friend bool operator!=(const BinaryData& d1, const BinaryData& d2);

		/**
		* 字节序按位取反
		*/
		DOG_CRYPTION_API friend BinaryData operator~(const BinaryData& d);
		
		/**
		* 按位与
		* @return d1 & d2
		* @throw DOG_ERROR_SIZE_NO_EQUAL 两字节序必须相等
		*/
		DOG_CRYPTION_API friend BinaryData operator&(const BinaryData& d1, const BinaryData& d2);
		/**
		* 按位自与
		* d1 &= d2
		* @throw DOG_ERROR_SIZE_NO_EQUAL 两字节序必须相等
		*/
		DOG_CRYPTION_API friend void operator&=(BinaryData& d1, const BinaryData& d2);
		/**
		* 按位与
		* @param d1
		* @param d2
		* @param size 有效计算字节数
		* @return d1 & d2
		* @throw 超出索引
		*/
		static BinaryData AND(const BinaryData& d1, const BinaryData& d2, uint64_t size);
		/**
		* 按位自与
		* @param d1
		* @param d2
		* @param size 有效计算字节数
		* d1 &= d2
		* @throw 超出索引
		*/
		static void AND_self(BinaryData& d1, const BinaryData& d2, uint64_t size);

		/**
		* 按位或
		* @return d1 | d2
		* @throw DOG_ERROR_SIZE_NO_EQUAL 两字节序必须相等
		*/
		DOG_CRYPTION_API friend BinaryData operator|(const BinaryData& d1, const BinaryData& d2);
		/**
		* 按位自或
		* d1 |= d2
		* @throw DOG_ERROR_SIZE_NO_EQUAL 两字节序必须相等
		*/
		DOG_CRYPTION_API friend void operator|=(BinaryData& d1, const BinaryData& d2);
		/**
		* 按位或
		* @param d1
		* @param d2
		* @param size 有效计算字节数
		* @return d1 | d2
		* @throw 超出索引
		*/
		static BinaryData OR(const BinaryData& d1, const BinaryData& d2, uint64_t size);
		/**
		* 按位自或
		* @param d1
		* @param d2
		* @param size 有效计算字节数
		* d1 |= d2
		* @throw 超出索引
		*/
		static void OR_self(BinaryData& d1, const BinaryData& d2, uint64_t size);
		
		/**
		* 按位异或
		* @return d1 ^ d2
		* @throw DOG_ERROR_SIZE_NO_EQUAL 两字节序必须相等
		*/
		DOG_CRYPTION_API friend BinaryData operator^(const BinaryData& d1, const BinaryData& d2);
		/**
		* 按位自异或
		* d1 ^= d2
		* @throw DOG_ERROR_SIZE_NO_EQUAL 两字节序必须相等
		*/
		DOG_CRYPTION_API friend void operator^=(BinaryData& d1, const BinaryData& d2);
		/**
		* 按位异或
		* @param d1
		* @param d2
		* @param size 有效计算字节数
		* @return d1 ^ d2
		* @throw 超出索引
		*/
		static BinaryData XOR(const BinaryData& d1, const BinaryData& d2, uint64_t size);
		/**
		* 按位自异或
		* @param d1
		* @param d2
		* @param size 有效计算字节数
		* d1 ^= d2
		* @throw 超出索引
		*/
		static void XOR_self(BinaryData& d1, const BinaryData& d2, uint64_t size);

		/**
		* 按字节拼接字节序
		*/
		DOG_CRYPTION_API friend BinaryData operator+(const BinaryData& d1, const BinaryData& d2);
		/**
		* 按字节自拼接字节序
		*/
		DOG_CRYPTION_API friend void operator+=(BinaryData& d1, const BinaryData& d2);

		/**
		* 按字节拼接字节序
		*/
		BinaryData concat(const BinaryData& d) const;

	};


	/**
	* 按Hex解析字符串为字节序BinaryData
	*/
	BinaryData operator"" _DogHexData(const char* str, size_t len);

	class DOG_CRYPTION_API DataStream
	{
	private:
		dog_torch::serialize::BinaryData data_;
		uint64_t pos_ = 0;
	public:
		DataStream(dog_torch::serialize::BinaryData& data);
		uint8_t* data();
		uint8_t get();
		uint8_t peek();
		void unget();
		uint64_t tellg() const;

	};

	/**
	* 简单的处理utf8字符串
	*/
	namespace utf8
	{
		/**
		* 将unicode码转成utf8格式
		*/
		DOG_CRYPTION_API std::string to_utf8(uint64_t code);
		/**
		* 求得一个符合utf8字符串的长度 复杂度O(n)
		*/
		DOG_CRYPTION_API uint64_t utf8_size(std::string str);
		/**
		* 求得一个符合utf8 Cstyle字符串的长度 复杂度O(n)
		*/
		DOG_CRYPTION_API uint64_t utf8_size(const char* str);
		/**
		* 获得utf8下第offset个utf8字符
		*/
		DOG_CRYPTION_API std::string get_utf8_char(std::string str, uint64_t offset);
		/**
		* 获得utf8下第offset个utf8字符
		*/
		DOG_CRYPTION_API std::string get_utf8_char(const char* str, uint64_t offset);
	};

}