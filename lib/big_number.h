#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <memory>
#include <exception>
#include <complex>
#include <queue>
#include <functional>
#include <utility>
#include <array>
#include <regex>

#include "data_bytes.h"

namespace dog_number
{

	class NumberException : public std::exception
	{
	private:
		std::string msg;
	public:
		NumberException(const char* msg, const char* file, const char* function, uint64_t line);
		~NumberException() = default;
		virtual const char* what() const throw();
	};

	namespace integer
	{
		/*
		* 返回n的有效数位
		* e.g.
		*  0x0123 -> 2
		*  0x0024 -> 1
		*  0x0000 -> 1
		*/
		uint8_t available_size(uint64_t n);
		uint8_t available_size(uint32_t n);
		uint8_t available_size(uint16_t n);

		/*
		* 返回n的第i位
		*  0x01 23 45 67 89 AB CD EF 取 7 位 -> 0x23
		*/
		uint8_t pick_byte(uint64_t n, uint8_t i);
		uint8_t pick_byte(uint32_t n, uint8_t i);
		uint8_t pick_byte(uint16_t n, uint8_t i);

		/*
		* 循环移动
		*/
		uint64_t CRMB(uint64_t n, uint32_t i);
		uint32_t CRMB(uint32_t n, uint32_t i);
		uint16_t CRMB(uint16_t n, uint32_t i);
		uint8_t CRMB(uint8_t n, uint32_t i);
		uint64_t CLMB(uint64_t n, uint32_t i);
		uint32_t CLMB(uint32_t n, uint32_t i);
		uint16_t CLMB(uint16_t n, uint32_t i);
		uint8_t CLMB(uint8_t n, uint32_t i);
	}

	namespace region
	{
		bool is_effective(std::string region_str);
		bool is_fall(std::string region_str, uint64_t n);

		namespace array
		{
			/* XX,XX,XX|XX*/
			bool is_effective(std::string region_str);
			std::vector<uint64_t> get_list(std::string region_str);
			bool is_fall(std::string region_str, uint64_t n);
		}
		namespace gap
		{
			/*
			* [a,b]c -> a    ,a+c  ,a+2c , ...  ,b-2c ,b-1c ,b
			*/
			bool is_effective(std::string region_str);
			std::array<uint64_t, 3> get_list(std::string region_str);
			bool is_fall(std::string region_str, uint64_t n);
		}
	}

	/*
	* 大数类，内部为256进制的原码数组
	*/
	class BigInteger
	{
	private:
		/*
		  符号位 0x01表示正数，0xff表示负数 0x00表示0
		*/
		char sign_ = 0;
		/*
		  内部数字位
		*/
		std::vector<uint8_t> num_;

	public:
		/*
		  10进制标识符
		*/
		const static int DEC = 10;
		/*
		  16进制标识符
		*/
		const static int HEX = 16;
		/*
		  8进制标识符
		*/
		const static int OCT = 8;
		/*
		  2进制标识符
		*/
		const static int BIN = 2;

		/*
		* 无参构造函数,得到默认值为0
		*/
		BigInteger();
		/*
		  有参构造函数，将不同进制的数字转为256进制
		  @param str 字符串
		  @param sign 标识符
			可选 HEX-16进制 DEC-10进制 OCT-8进制 BIN-2进制
		*/
		BigInteger(const char* str, const int radix = 10);
		BigInteger(const std::string& str, const int radix = 10);
		BigInteger(const std::vector<char>& str, const int radix = 10);

		BigInteger(uint8_t n);
		BigInteger(uint16_t n);
		BigInteger(uint32_t n);
		BigInteger(uint64_t n);
		BigInteger(int8_t n);
		BigInteger(int16_t n);
		BigInteger(int32_t n);
		BigInteger(int64_t n);

		void swap(BigInteger& b);

	private:
		//输出函数
		/*
		  输出16进制数，字母大写
		*/
		std::string getUpHEX();
		/*
		  输出16进制数，字母小写
		*/
		std::string getLowHEX();
		/*
		  输出10进制
		*/
		std::string getDEC();
	public:
		std::string get_num(int radix = 10, bool isUpper = true);

		std::vector<uint8_t> get_bytes();

		//基本操作
		/*
		* 返回256进制数大小
		* @result 256进制数大小
		*/
		uint64_t size();

		/*
		* 预留n个字节空间
		*/
		void reserve(uint64_t n);

		/*
		* 在末尾添加一个字节n
		*/
		void push_back(uint8_t n);

		/*
		* 删除末尾一个字节
		*/
		void pop_back();

		/*
		* 返回第i个字节的引用
		* @result 第i个字节的引用
		*/
		uint8_t& at(uint64_t i);

		/*
		* 在pos位置插入一个字节n
		* @param pos位置 n 插入的字节
		*/
		void insert(const std::vector<uint8_t>::iterator pos, uint8_t n);

		/*
		* 返回BigInteger符号
		* @result BigInteger符号 -1表示负数，1表示正数，0表示0
		*/
		char get_sign();

		/*
		* 将BigInteger符号反向
		*/
		void change_sign();

		void set_positive();
		void set_negative();

		/*
		* 转置BigInteger
		*/
		void reverse();

		/*
		* 快速设置2^n-1;
		*/
		void set2b(uint64_t n);

		/*
		* 快速设置0
		*/
		void set0();

		/*
		  去除高位0，释放无效空间
		*/
		void trims();

		std::vector<uint8_t>::iterator begin();
		std::vector<uint8_t>::iterator end();
		std::vector<uint8_t>::const_iterator cbegin();
		std::vector<uint8_t>::const_iterator cend();
		std::reverse_iterator<std::vector<uint8_t>::iterator> rbegin();
		std::reverse_iterator<std::vector<uint8_t>::iterator> rend();
		std::reverse_iterator<std::vector<uint8_t>::const_iterator> crbegin();
		std::reverse_iterator<std::vector<uint8_t>::const_iterator> crend();

	public:
		//静态整型转换函数
		static BigInteger toBigInteger(uint8_t n);
		static BigInteger toBigInteger(uint16_t n);
		static BigInteger toBigInteger(uint32_t n);
		static BigInteger toBigInteger(uint64_t n);
		static BigInteger toBigInteger(int8_t n);
		static BigInteger toBigInteger(int16_t n);
		static BigInteger toBigInteger(int32_t n);
		static BigInteger toBigInteger(int64_t n);

		uint8_t& operator[](uint64_t i);

		friend bool operator>(BigInteger a, BigInteger b);
		friend bool operator>(BigInteger a, uint8_t b);
		friend bool operator>(BigInteger a, uint16_t b);
		friend bool operator>(BigInteger a, uint32_t b);
		friend bool operator>(BigInteger a, uint64_t b);
		friend bool operator>(BigInteger a, int8_t b);
		friend bool operator>(BigInteger a, int16_t b);
		friend bool operator>(BigInteger a, int32_t b);
		friend bool operator>(BigInteger a, int64_t b);

		friend bool operator>=(BigInteger a, BigInteger b);
		friend bool operator>=(BigInteger a, uint8_t b);
		friend bool operator>=(BigInteger a, uint16_t b);
		friend bool operator>=(BigInteger a, uint32_t b);
		friend bool operator>=(BigInteger a, uint64_t b);
		friend bool operator>=(BigInteger a, int8_t b);
		friend bool operator>=(BigInteger a, int16_t b);
		friend bool operator>=(BigInteger a, int32_t b);
		friend bool operator>=(BigInteger a, int64_t b);

		friend bool operator<(BigInteger a, BigInteger b);
		friend bool operator<(BigInteger a, int8_t b);
		friend bool operator<(BigInteger a, int16_t b);
		friend bool operator<(BigInteger a, int32_t b);
		friend bool operator<(BigInteger a, int64_t b);
		friend bool operator<(BigInteger a, uint8_t b);
		friend bool operator<(BigInteger a, uint16_t b);
		friend bool operator<(BigInteger a, uint32_t b);
		friend bool operator<(BigInteger a, uint64_t b);

		friend bool operator<=(BigInteger a, BigInteger b);
		friend bool operator<=(BigInteger a, int8_t b);
		friend bool operator<=(BigInteger a, int16_t b);
		friend bool operator<=(BigInteger a, int32_t b);
		friend bool operator<=(BigInteger a, int64_t b);
		friend bool operator<=(BigInteger a, uint8_t b);
		friend bool operator<=(BigInteger a, uint16_t b);
		friend bool operator<=(BigInteger a, uint32_t b);
		friend bool operator<=(BigInteger a, uint64_t b);

		friend bool operator==(BigInteger a, BigInteger b);
		friend bool operator==(BigInteger a, int8_t b);
		friend bool operator==(BigInteger a, int16_t b);
		friend bool operator==(BigInteger a, int32_t b);
		friend bool operator==(BigInteger a, int64_t b);
		friend bool operator==(BigInteger a, uint8_t b);
		friend bool operator==(BigInteger a, uint16_t b);
		friend bool operator==(BigInteger a, uint32_t b);
		friend bool operator==(BigInteger a, uint64_t b);

		friend bool operator!=(BigInteger a, BigInteger b);
		friend bool operator!=(BigInteger a, int8_t b);
		friend bool operator!=(BigInteger a, int16_t b);
		friend bool operator!=(BigInteger a, int32_t b);
		friend bool operator!=(BigInteger a, int64_t b);
		friend bool operator!=(BigInteger a, uint8_t b);
		friend bool operator!=(BigInteger a, uint16_t b);
		friend bool operator!=(BigInteger a, uint32_t b);
		friend bool operator!=(BigInteger a, uint64_t b);

		BigInteger operator-();

		/*
		* 返回大数类的绝对值
		* @param a
		* @return |a|
		*/
		static BigInteger abs(BigInteger a);
		/*
		* 对BigInteger类进行绝对值比较
		* @param a,b 两个BigInteger类
		* @return 1  |a| > |b|
		* @return 0  |a| = |b|
		* @return -1 |a| < |b|
		*/
		static int abs_compare(BigInteger a, BigInteger b);


		static BigInteger add(BigInteger a, BigInteger b);
		friend BigInteger operator+(BigInteger a, BigInteger b);

		BigInteger add_other(BigInteger n);
		friend void operator+=(BigInteger& a, BigInteger b);

		static BigInteger subtract(BigInteger a, BigInteger b);
		friend BigInteger operator-(BigInteger a, BigInteger b);

		BigInteger subtract_other(BigInteger n);
		friend void operator-=(BigInteger& a, BigInteger b);

		static BigInteger multiplysingle(BigInteger a, BigInteger b);
		static BigInteger multiplyDistribute(BigInteger a, BigInteger b);
		static BigInteger multiplyKaratsuba0(BigInteger a, BigInteger b);
		//static BigInteger multiplyKaratsuba0_showing(BigInteger a, BigInteger b, std::string space = "");
		static BigInteger multiplyKaratsuba1(BigInteger a, BigInteger b);
		static BigInteger multiplyToomCook30(BigInteger a, BigInteger b);
		static BigInteger multiplyToomCook31(BigInteger a, BigInteger b);
	private:
		static void FFT0(std::vector<std::complex<double>>& a, int inverse);
		static void FFT1(std::vector<std::complex<double>>& a, int inverse, std::vector<uint64_t>& rev);
		static void FNTT0(std::vector<uint64_t>& a, int inverse);
		static void FNTT1(std::vector<uint64_t>& a, int inverse, std::vector<uint64_t>& rev);

		static void FNTTinv(std::vector<uint64_t>& a, std::vector<uint64_t>& rev);
	public:
		static BigInteger multiplyFFT0(BigInteger a, BigInteger b);
		static BigInteger multiplyFFT1(BigInteger a, BigInteger b);
		static BigInteger multiplyFNTT0(BigInteger a, BigInteger b);
		static BigInteger multiplyFNTT1(BigInteger a, BigInteger b);

		static BigInteger multiply(BigInteger a, BigInteger b);
		friend BigInteger operator*(BigInteger a, BigInteger b);

		BigInteger multiply_other(BigInteger n);
		friend void operator*=(BigInteger& a, BigInteger b);

		static std::pair<BigInteger, BigInteger> divideDistribute(BigInteger a, BigInteger b, bool is_round_zero = true);
		static BigInteger divideNTT1(BigInteger a, BigInteger b);


	};

	const BigInteger ZERO = "0";
	const BigInteger BIG_INT32_MAX = "4294967295";
	const BigInteger BIG_INT64_MAX = "18446744073709551615";
	const BigInteger BIG_INT128_MAX = "340282366920938463463374607431768211455";
}