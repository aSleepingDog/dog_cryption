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

#include "data_bytes.h"

namespace DogNumber
{

	class number_exception : public std::exception
	{
	private:
		std::string msg;
	public:
		number_exception(const char* msg, const char* file, const char* function, uint64_t line);
		~number_exception() = default;
		virtual const char* what() const throw();
	};

	typedef uint64_t Ullong;
	typedef uint32_t Uint;
	typedef uint16_t Ushort;
	typedef uint8_t byte;

	/*
	* 大数类，内部为256进制的原码数组
	*/
	class BigInteger
	{
	private:
		/*
		  符号位 0x01表示正数，0xff表示负数 0x00表示0
		*/
		char sign = 0;
		/*
		  内部数字位
		*/
		std::vector<byte> num;

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

		std::string getNum(int radix = 10, bool isUpper = true);

		std::vector<byte> getBytes();

		//基本操作
		/*
		* 返回256进制数大小
		* @result 256进制数大小
		*/
		Ullong size();

		/*
		* 预留n个字节空间
		*/
		void reserve(Ullong n);

		/*
		* 在末尾添加一个字节n
		*/
		void push_back(byte n);

		/*
		* 删除末尾一个字节
		*/
		void pop_back();

		/*
		* 返回第i个字节的引用
		* @result 第i个字节的引用
		*/
		byte& at(Ullong i);

		/*
		* 在pos位置插入一个字节n
		* @param pos位置 n 插入的字节
		*/
		void insert(const std::vector<byte>::iterator pos, byte n);

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
		void set2b(Ullong n);

		/*
		* 快速设置0
		*/
		void set0();

		/*
		  去除高位0，释放无效空间
		*/
		void trims();

		std::vector<byte>::iterator begin();
		std::vector<byte>::iterator end();
		std::vector<byte>::const_iterator cbegin();
		std::vector<byte>::const_iterator cend();
		std::reverse_iterator<std::vector<DogNumber::byte>::iterator> rbegin();
		std::reverse_iterator<std::vector<DogNumber::byte>::iterator> rend();
		std::reverse_iterator<std::vector<DogNumber::byte>::const_iterator> crbegin();
		std::reverse_iterator<std::vector<DogNumber::byte>::const_iterator> crend();

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

		byte& operator[](Ullong i);

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
		static void FFT1(std::vector<std::complex<double>>& a, int inverse, std::vector<Ullong>& rev);
		static void FNTT0(std::vector<Ullong>& a, int inverse);
		static void FNTT1(std::vector<Ullong>& a, int inverse, std::vector<Ullong>& rev);

		static void FNTTinv(std::vector<Ullong>& a, std::vector<Ullong>& rev);
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
}