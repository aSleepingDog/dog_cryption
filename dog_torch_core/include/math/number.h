#pragma once
#ifdef SHARED
	#include "export.h"
#else
	#define DOG_CRYPTION_API
#endif

#include <queue>
#include <array>
#include <regex>
#include <string>
#include <vector>
#include <memory>
#include <bitset>
#include <compare>
#include <cstring>
#include <utility>
#include <complex>
#include <iostream>
#include <algorithm>
#include <exception>
#include <functional>

#include "utils/Exception.h"

namespace dog_torch::math::number
{
	using NumberException = dog_torch::utils::Exception;

	/**
	* 大数类 内部为256进制的原码数组
	*/
	class DOG_CRYPTION_API BigInteger
	{
	private:
		/**
		  符号位 0x01表示正数 0xff=-1表示负数 0x00表示0
		*/
		char sign_ = 0;
		/**
		  内部数字位
		*/
		std::vector<uint8_t> num_;

	public:
		/**
		  10进制标识符
		*/
		const static int DEC = 10;
		/**
		  16进制标识符
		*/
		const static int HEX = 16;
		/**
		  8进制标识符
		*/
		const static int OCT = 8;
		/**
		  2进制标识符
		*/
		const static int BIN = 2;

		/**
		* 无参构造函数,得到默认值为0
		*/
		BigInteger();
		/**
		  有参构造函数 将不同进制的数字转为256进制
		  @param str 字面量字符串
		  @param sign 标识符
			可选 HEX-16进制 DEC-10进制 OCT-8进制 BIN-2进制
		*/
		BigInteger(const char* str, const int radix = 10);
		/**
		  有参构造函数 将不同进制的数字转为256进制
		  @param str std字符串
		  @param sign 标识符
			可选 HEX-16进制 DEC-10进制 OCT-8进制 BIN-2进制
		*/
		BigInteger(const std::string& str, const int radix = 10);
		/**
		  有参构造函数 将不同进制的数字转为256进制
		  @param str std字符数组
		  @param sign 标识符
			可选 HEX-16进制 DEC-10进制 OCT-8进制 BIN-2进制
		*/
		BigInteger(const std::vector<char>& str, const int radix = 10);

		/**
		* 将基本数据类型转换成大数类
		* @param n
		*/
		BigInteger(uint8_t n);
		/**
		* 将基本数据类型转换成大数类
		* @param n
		*/
		BigInteger(uint16_t n);
		/**
		* 将基本数据类型转换成大数类
		* @param n
		*/
		BigInteger(uint32_t n);
		/**
		* 将基本数据类型转换成大数类
		* @param n
		*/
		BigInteger(uint64_t n);
		/**
		* 将基本数据类型转换成大数类
		* @param n
		*/
		BigInteger(int8_t n);
		/**
		* 将基本数据类型转换成大数类
		* @param n
		*/
		BigInteger(int16_t n);
		/**
		* 将基本数据类型转换成大数类
		* @param n
		*/
		BigInteger(int32_t n);
		/**
		* 将基本数据类型转换成大数类
		* @param n
		*/
		BigInteger(int64_t n);
		/**
		* 将std::vector作为原码 指定指定标识符的大整数
		* @param v 原码数组
		* @param sign 符号位 如果原码为0则忽略输入值
		*/
		static BigInteger from_vector(const std::vector<uint8_t>& v, char sign = 1);
		/**
		* 交换两个大数类
		* @param b 另一个交换的数字
		*/
		void swap(BigInteger& b);

	private:
		//输出函数
		/**
		  输出16进制数 字母大写
		  @result 字母大写的16进制的std字符串
		*/
		std::string getUpHEX() const;
		/**
		  输出16进制数 字母小写
		  @result 字母小写的16进制的std字符串
		*/
		std::string getLowHEX() const;
		/**
		  输出10进制
		  @result 10进制的std字符串
		*/
		std::string getDEC() const;
	public:
		/**
		* 输出2-16之间任意进制的数字字符串
		* @param radix 进制数 仅支持2-16 默认为10
		* @param isUpper 遇到字母是否大写 在radix>10时生效
		* @result 指定radix进制 字母格式为isUpper的数字字符串
		* @throw DOG_ERROR_WRONG_RADIX radix不在2-16时抛出
		*/
		std::string to_num_string(int radix = 10, bool isUpper = true) const;
		/**
		* 输出原码字节串
		* @result std字节串
		*/
		std::vector<uint8_t> to_byte_vector() const;
		/**
		* 输出最高64位的原码
		* @result 输出64无符号整型
		*/
		uint64_t to_abs_uint64() const;
		int64_t to_int64() const;
		double to_float64() const;

		//基本操作
		/**
		* 返回256进制数大小
		* @result 256进制数大小
		*/
		uint64_t size() const;
		/**
		* 预留n个字节空间
		*/
		void reserve(uint64_t n);
		/**
		* 在末尾添加一个字节n
		*/
		void push_back(uint8_t n);
		/**
		* 删除末尾一个字节
		*/
		void pop_back();
		/**
		* 返回第i个字节的引用
		* @result 第i个字节的引用
		*/
		uint8_t& at(uint64_t i);
		/**
		* 返回第i个字节的引用
		* @result 第i个字节的引用
		*/
		uint8_t& operator[](uint64_t i);
		/**
		* 返回第i个字节的常量引用
		* @result 第i个字节的常量引用
		*/
		const uint8_t& at(uint64_t i) const;
		/**
		* 返回第i个字节的常量引用
		* @result 第i个字节的常量引用
		*/
		const uint8_t& operator[](uint64_t i) const;
		/**
		* 在pos位置插入一个字节n
		* @param pos位置 n 插入的字节
		*/
		void insert(const std::vector<uint8_t>::iterator pos, uint8_t n);
		/**
		* 返回BigInteger符号
		* @result BigInteger符号 -1表示负数 1表示正数 0表示0
		*/
		char get_sign() const;
		/**
		* 将BigInteger符号反向
		*/
		void change_sign();
		/**
		* 置为正数
		*/
		void set_positive();
		/**
		* 置为负数
		*/
		void set_negative();
		/**
		* 转置BigInteger
		*/
		void reverse();
		/**
		* 快速设置2^n-1;
		*/
		void set2b(uint64_t n);
		/**
		* 快速设置0
		*/
		void set0();

		/**
		  去除高位0 释放无效空间 并保证符号正确
		*/
		void trims();

		/**
		* 类内简化
		*/
		using it = std::vector<uint8_t>::iterator;
		/**
		* 类内简化
		*/
		using cit = std::vector<uint8_t>::const_iterator;
		/**
		* 类内简化
		*/
		using rit = std::reverse_iterator<std::vector<uint8_t>::iterator>;
		/**
		* 类内简化
		*/
		using rcit = std::reverse_iterator<std::vector<uint8_t>::const_iterator>;
		
		/**
		* 返回正序第一个迭代器
		* @result 正序第一个迭代器
		*/
		it begin();
		/**
		* 返回正序最后一个迭代器 不得解引用
		* @result 正序最后一个迭代器 不得解引用
		*/
		it end();
		/**
		* 返回正序第一个常量迭代器
		* @result 正序第一个常量迭代器
		*/
		cit cbegin() const;
		/**
		* 返回正序最后一个常量迭代器 不得解引用
		* @result 正序最后一个常量迭代器 不得解引用
		*/
		cit cend() const;
		/**
		* 返回倒序第一个迭代器
		* @result 倒序第一个迭代器
		*/
		rit rbegin();
		/**
		* 返回倒序最后一个迭代器 不得解引用
		* @result 倒序最后一个迭代器 不得解引用
		*/
		rit rend();
		/**
		* 返回倒序第一个常量迭代器
		* @result 倒序第一个常量迭代器
		*/
		rcit crbegin() const;
		/**
		* 返回倒序最后一个常量迭代器 不得解引用
		* @result 倒序最后一个常量迭代器 不得解引用
		*/
		rcit crend() const;

	public:
		//静态整型转换函数
		/**
		* 将基本类型n转换成大整数
		* @result n对应的大整数
		*/
		static BigInteger toBigInteger(uint8_t n);
		/**
		* 将基本类型n转换成大整数
		* @result n对应的大整数
		*/
		static BigInteger toBigInteger(uint16_t n);
		/**
		* 将基本类型n转换成大整数
		* @result n对应的大整数
		*/
		static BigInteger toBigInteger(uint32_t n);
		/**
		* 将基本类型n转换成大整数
		* @result n对应的大整数
		*/
		static BigInteger toBigInteger(uint64_t n);
		/**
		* 将基本类型n转换成大整数
		* @result n对应的大整数
		*/
		static BigInteger toBigInteger(int8_t n);
		/**
		* 将基本类型n转换成大整数
		* @result n对应的大整数
		*/
		static BigInteger toBigInteger(int16_t n);
		/**
		* 将基本类型n转换成大整数
		* @result n对应的大整数
		*/
		static BigInteger toBigInteger(int32_t n);
		/**
		* 将基本类型n转换成大整数
		* @result n对应的大整数
		*/
		static BigInteger toBigInteger(int64_t n);

		/**
		* 返回大数类的绝对值
		* @param a
		* @return |a|
		*/
		static BigInteger abs(BigInteger a);
		/**
		* 对BigInteger类进行绝对值比较
		* @param a,b 两个BigInteger类
		* @return 1  |a| > |b|
		* @return 0  |a| = |b|
		* @return -1 |a| < |b|
		*/
		static int abs_compare(const BigInteger& a, const BigInteger& b);
		/**
		* 对BigInteger类进行值比较
		* @param a,b 两个BigInteger类
		* @return 1  a > b
		* @return 0  a = b
		* @return -1 a < b
		*/
		static int value_compare(const BigInteger& a, const BigInteger& b);
		/**
		* 同时进行值和绝对值比较 哪边大 哪边1
		* ```
		*  X X | X X | X X | X X
		*  0 0 -> a==0
		*  0 1 -> a>0
		*  1 0 -> a<0
		*        0 0 -> b==0
		*        0 1 -> b>0
		*        1 0 -> b<0
		*              0 0 -> |a|==|b|
		*              1 0 -> |a|>|b|
		*              0 1 -> |a|<|b|
		*                     0 0 -> a==b
		*                     1 0 -> a>b
		*                     0 1 -> a<b
		* ```
		* @return 见上表
		*/
		static uint8_t plenty_compare(const BigInteger& a, const BigInteger& b);

		DOG_CRYPTION_API friend bool operator==(const BigInteger& a, const BigInteger& b);
		DOG_CRYPTION_API friend bool operator!=(const BigInteger& a, const BigInteger& b);
		DOG_CRYPTION_API friend bool operator>(const BigInteger& a, const BigInteger& b);
		DOG_CRYPTION_API friend bool operator>=(const BigInteger& a, const BigInteger& b);
		DOG_CRYPTION_API friend bool operator<(const BigInteger& a, const BigInteger& b);
		DOG_CRYPTION_API friend bool operator<=(const BigInteger& a, const BigInteger& b);

		/**
		* 符号位取反 0时无效
		*/
		BigInteger operator-();

		/**
		* 将a和b相加
		* @param 大整数a
		* @param 大整数b
		* @result a+b
		*/
		static BigInteger add(BigInteger a, BigInteger b);
		/**
		* 将a和b相加
		* @param 大整数a
		* @param 大整数b
		* @result a+b
		*/
		DOG_CRYPTION_API friend BigInteger operator+(BigInteger a, BigInteger b);

		/**
		* 将a自加n a+=n
		* @param 大整数n
		* @result a+n
		*/
		BigInteger add_other(BigInteger n);
		/**
		* 将a自加b a+=b
		* @param 大整数b
		*/
		DOG_CRYPTION_API friend void operator+=(BigInteger& a, BigInteger b);
		/**
		* 将a自加b a+=b
		* @param 整数b
		*/
		DOG_CRYPTION_API friend void operator+=(BigInteger& a, uint64_t b);
		
		/**
		* 将a和b相减
		* @param 大整数a
		* @param 大整数b
		* @result a-b
		*/
		static BigInteger subtract(BigInteger a, BigInteger b);
		/**
		* 将a和b相减
		* @param 大整数a
		* @param 大整数b
		* @result a-b
		*/
		DOG_CRYPTION_API friend BigInteger operator-(BigInteger a, BigInteger b);

		/**
		* 将a自减b a-=b
		* @param 大整数a
		* @param 大整数b
		* @result a-b
		*/
		BigInteger subtract_other(BigInteger n);
		/**
		* 将a自减b a-=b
		* @param 大整数a
		* @param 大整数b
		*/
		DOG_CRYPTION_API friend void operator-=(BigInteger& a, BigInteger b);

		/**
		* @result a[0]*b[0]
		*/
		static BigInteger multiplysingle(BigInteger a, BigInteger b);
		/**
		* 分配法计算乘法 复杂度O(n^2)
		* @result a*b
		*/
		static BigInteger multiplyDistribute(BigInteger a, BigInteger b);
		/**
		* 分配法计算乘法对uint64_t的特殊实现 复杂度O(n)
		* @result a*b
		*/
		static BigInteger multiplyDistributeUint64(BigInteger a, uint64_t b);
		/**
		* Karatsuba法分治计算乘法迭代实现 复杂度O(n^log3(2))
		* @result a*b
		*/
		static BigInteger multiplyKaratsuba0(BigInteger a, BigInteger b);
		//static BigInteger multiplyKaratsuba0_showing(BigInteger a, BigInteger b, std::string space = "");
		/**
		* Karatsuba法分治计算乘法栈实现 复杂度O(n^log3(2))
		* @result a*b
		*/
		static BigInteger multiplyKaratsuba1(BigInteger a, BigInteger b);
		/**
		* ToomCook3法分治计算乘法递归 未实现 不支持
		* @throw DOG_ERROR_NO_SUPPORT
		*/
		static BigInteger multiplyToomCook30(BigInteger a, BigInteger b);
		/**
		* ToomCook3法分治计算乘法栈 未实现 不支持
		* @throw DOG_ERROR_NO_SUPPORT
		*/
		static BigInteger multiplyToomCook31(BigInteger a, BigInteger b);
	private:
		/**
		* FFT 递归子函数 (不允许外部调用)
		*/
		static void FFT0(std::vector<std::complex<double>>& a, int inverse);
		/**
		* FFT 迭代子函数 (不允许外部调用)
		*/
		static void FFT1(std::vector<std::complex<double>>& a, int inverse, std::vector<uint64_t>& rev);
		/**
		* FNTT 递归子函数 (不允许外部调用)
		*/
		static void FNTT0(std::vector<uint64_t>& a, int inverse);
		/**
		* FNTT 递归子函数 (不允许外部调用)
		*/
		static void FNTT1(std::vector<uint64_t>& a, int inverse, std::vector<uint64_t>& rev);

		/**
		* FNTT求逆子函数 未实现
		* @throw DOG_ERROR_NO_SUPPORT
		*/
		static void FNTTinv(std::vector<uint64_t>& a, std::vector<uint64_t>& rev);
	public:
		/**
		* FFT计算乘法递归实现 复杂度O(n*logn)
		* @result a*b
		*/
		static BigInteger multiplyFFT0(BigInteger a, BigInteger b);
		/**
		* FFT计算乘法迭代实现 复杂度O(n*logn)
		* @result a*b
		*/
		static BigInteger multiplyFFT1(BigInteger a, BigInteger b);
		/**
		* FNTT计算乘法递归实现 复杂度O(n*logn)
		* @result a*b
		*/
		static BigInteger multiplyFNTT0(BigInteger a, BigInteger b);
		/**
		* FNTT计算乘法迭代实现 复杂度O(n*logn)
		* @result a*b
		*/
		static BigInteger multiplyFNTT1(BigInteger a, BigInteger b);

		/**
		* 综合乘法实现 复杂度最低O(n)-分配法 最高O(n*logn)-FNTT0
		* @result a*b
		*/
		static BigInteger multiply(BigInteger a, BigInteger b);
		/*
		* 综合乘法实现 复杂度最低O(n)-分配法 最高O(n*logn)-FNTT0
		* @result a*b
		*/
		DOG_CRYPTION_API friend BigInteger operator*(BigInteger a, BigInteger b);

		/**
		* 综合自乘实现 复杂度最低O(n)-分配法 最高O(n*logn)-FNTT0 a*=n
		* @result a*n
		*/
		BigInteger multiply_other(BigInteger n);
		/**
		* 综合自乘实现 复杂度最低O(n)-分配法 最高O(n*logn)-FNTT0 a*=n
		*/
		DOG_CRYPTION_API friend void operator*=(BigInteger& a, BigInteger b);

		/**
		* 试商法整除法实现 复杂度O(n)
		* @param is_round_zero 余数取整方式 默认true:向0取整/截断 false:向小数取整
		* @result first 商
		* @result second 余数
		* @throw DOG_ERROR_DIVIDE_BY_ZERO 除0错误
		*/
		static std::pair<BigInteger, BigInteger> divideDistribute(BigInteger a, BigInteger b, bool is_round_zero = true);
		/**
		* FNTT逆元法整除法实现 复杂度O(n*logn)
		* @throw DOG_ERROR_NO_SUPPORT 暂不支持
		* @throw DOG_ERROR_DIVIDE_BY_ZERO 除0错误
		*/
		static BigInteger divideFNTT1(BigInteger a, BigInteger b);
		
		/**
		* Knuth整除法实现 复杂度O(n) 与C/C++常规数字类型/运算符结果一致
		* @param is_round_zero 余数取整方式 默认true:向0取整/截断 false:向小数取整
		* @throw DOG_ERROR_DIVIDE_BY_ZERO 除0错误
		* @result a/b
		*/
		static BigInteger divideKnuth(BigInteger a, BigInteger b, bool is_round_zero = true);
        /**
		* 综合除法实现 平均复杂度O(n)
		* @return a/b
		*/
		static BigInteger divide(BigInteger a, BigInteger b);
		/**
		* 综合除法实现 平均复杂度O(n)
		* @return a/b
		*/
		DOG_CRYPTION_API friend BigInteger operator/(BigInteger a, BigInteger b);
		/**
		* Knuth整除法实现求余 复杂度O(n)
		* 计算结果等效于 c=a/b(向0取整) d=a-c*b 返回d 与C/C++常规数字类型%运算符结果一致
		* @throw DOG_ERROR_DIVIDE_BY_ZERO 除0错误
		* @result a%b
		*/
		static BigInteger remainderKnuth(BigInteger a, BigInteger b);

		DOG_CRYPTION_API friend BigInteger operator%(BigInteger a, BigInteger b);

		/**
		* Knuth整除法实现取模 复杂度O(n)
		* 计算结果等效于 c=a/b(向负无穷取整) d=a-c*b 返回d
		* @throw DOG_ERROR_DIVIDE_BY_ZERO 除0错误
		* @result a mod b
		*/
		static BigInteger moduloKnuth(BigInteger a, BigInteger b);


		/**
		* 更相减损术迭代实现求最大公约数 复杂度O(n)
		* @return gcd(a,b)
		*/
		static BigInteger gcdSubtract(BigInteger a, BigInteger b);
		/**
		* 辗转相除法迭代实现求最大公约数 复杂度O(n)
		* @return gcd(a,b)
		*/
		static BigInteger gcdMultiply(BigInteger a, BigInteger b);
	};
	/**
	* 大整数0常量
	*/
	DOG_CRYPTION_API extern const BigInteger ZERO;
	/**
	* 大整数无符号32位整数最大值常量
	*/
	DOG_CRYPTION_API extern const BigInteger BIG_UINT32_MAX;
	/**
	* 大整数无符号64位整数最大值常量
	*/
	DOG_CRYPTION_API extern const BigInteger BIG_UINT64_MAX;
	/**
	* 大整数无符号128位整数最大值常量
	*/
	DOG_CRYPTION_API extern const BigInteger BIG_UINT128_MAX;
}