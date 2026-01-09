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
#include "math/integer.h"

namespace dog_torch::serialize
{
	class DOG_CRYPTION_API BinaryData
	{
	private:
		std::vector<uint8_t> inside_data;
	public:
		const static int UTF8 = 0;
		const static int BASE64 = 1;
		const static int HEX = 2;

		BinaryData() = default;
		BinaryData(std::string str, const int type = 2);
		BinaryData(const char* str, const int type = 2) : BinaryData(std::string(str), type) {};
		BinaryData(const std::vector<uint8_t>& data);
		BinaryData(uint64_t size);

		BinaryData(const BinaryData& other);
		void operator=(const BinaryData& other);
		BinaryData(BinaryData&& other) noexcept;
		~BinaryData();

		uint8_t& at(uint64_t i);
		uint8_t at(uint64_t i) const;
		uint8_t& operator[](uint64_t i);
		uint8_t operator[](uint64_t i) const;
		uint8_t& front();
		uint8_t& back();
		uint8_t* data();
		const uint8_t* data() const;

		using it = std::vector<uint8_t>::iterator;
		using cit = std::vector<uint8_t>::const_iterator;
		using rit = std::reverse_iterator<it>;
		using crit = std::reverse_iterator<cit>;

		it   begin();
		it   end();
		cit  cbegin() const;
		cit  cend() const;
		rit  rbegin();
		rit  rend();
		crit crbegin() const;
		crit crend() const;

		std::vector<uint8_t> to_byte_vector() const;
		std::vector<char> to_utf8_vector() const;
		std::vector<char> to_base64_vector() const;
		std::vector<char> to_base64_vector(char a, char b) const;
		std::vector<char> to_base64_vector(char a, char b, char c) const;
		std::vector<char> to_hex_vector(bool is_upper = true) const;

		std::string to_utf8_string() const;
		std::string to_base64_string() const;
		std::string to_base64_string(char a, char b) const;
		std::string to_base64_string(char a, char b, char c) const;
		std::string to_hex_string(bool is_upper = true) const;

		BinaryData sub_by_pos(uint64_t start, uint64_t end) const;
		BinaryData sub_by_len(uint64_t start, uint64_t len) const;

		BinaryData sub_by_pos(std::vector<uint8_t>::iterator start, std::vector<uint8_t>::iterator end) const;
		BinaryData sub_by_len(std::vector<uint8_t>::iterator start, uint64_t len) const;

		bool empty() const;
		uint64_t size() const;
		uint64_t max_size() const;
		void reserve(uint64_t n);

		void insert(const uint64_t i, uint8_t b);
		void insert(const std::vector<uint8_t>::iterator pos, uint8_t b);

		void erase(const uint64_t i);
		void erase(const std::vector<uint8_t>::iterator pos);

		/*
		* 清除所有数据,不保留位置
		* 等效于vector.clear()
		*/
		void rm_pos();
		/*
		* 将所有位置重置为0
		*/
		void set_zero();

		void push_back(uint8_t b);
		void pop_back();

		/* 颠倒顺序 */
		void reverse();

		void swap(BinaryData& d);
		void swap(BinaryData d);

		BinaryData bit_left_move_norise(uint64_t shift);
		void bit_left_move_norise_self(uint64_t shift);

		BinaryData bit_left_move_rise(uint64_t shift);
		void bit_left_move_rise_self(uint64_t shift);

		BinaryData bit_right_move_norise(uint64_t shift);
		void bit_right_move_norise_self(uint64_t shift);

		BinaryData bit_right_move_rise(uint64_t shift);
		void bit_right_move_rise_self(uint64_t shift);

		BinaryData bit_circle_left_move(uint64_t shift);
		BinaryData bit_circle_right_move(uint64_t shift);

		bool is_equal(const BinaryData& d) const;
		friend bool operator==(const BinaryData& d1, const BinaryData& d2);
		friend bool operator!=(const BinaryData& d1, const BinaryData& d2);

		friend BinaryData operator~(const BinaryData& d);
		friend BinaryData operator&(const BinaryData& d1, const BinaryData& d2);
		friend void operator&=(BinaryData& d1, const BinaryData& d2);
		static BinaryData AND(const BinaryData& d1, const BinaryData& d2, uint64_t size);
		static void AND_self(BinaryData& d1, const BinaryData& d2, uint64_t size);


		friend BinaryData operator|(const BinaryData& d1, const BinaryData& d2);
		friend void operator|=(BinaryData& d1, const BinaryData& d2);
		static BinaryData OR(const BinaryData& d1, const BinaryData& d2, uint64_t size);
		static void OR_self(BinaryData& d1, const BinaryData& d2, uint64_t size);
		
		friend BinaryData operator^(const BinaryData& d1, const BinaryData& d2);
		friend void operator^=(BinaryData& d1, const BinaryData& d2);
		static BinaryData XOR(const BinaryData& d1, const BinaryData& d2, uint64_t size);
		static void XOR_self(BinaryData& d1, const BinaryData& d2, uint64_t size);

		friend BinaryData operator+(const BinaryData& d1, const BinaryData& d2);
		friend void operator+=(BinaryData& d1, const BinaryData& d2);

		BinaryData concat(const BinaryData& d) const;

	};

	//未实现
	class DOG_CRYPTION_API DataStreamBuf : public std::basic_streambuf<uint8_t>
	{
	private:
		uint8_t* rbuf_start_ = nullptr;
		uint8_t* rbuf_end_ = nullptr;
		uint8_t* rbuf_pos_ = nullptr;

		uint8_t* wbuf_start_ = nullptr;
		uint8_t* wbuf_end_ = nullptr;
		uint8_t* wbuf_pos_ = nullptr;

	public:
		void imbue(const std::locale& loc) override;
		std::basic_streambuf<uint8_t>* setbuf(char_type* s, std::streamsize n) override;
		pos_type seekoff(off_type off, std::ios_base::seekdir dir,
			std::ios_base::openmode which = std::ios_base::in | std::ios_base::out) override;
		pos_type seekpos(pos_type pos,
			std::ios_base::openmode which = std::ios_base::in | std::ios_base::out) override;
		int sync() override;
		std::streamsize showmanyc() override;
		int_type underflow() override;
		int_type uflow() override;
		std::streamsize xsgetn(char_type* s, std::streamsize count) override;
		std::streamsize xsputn(const char_type* s, std::streamsize count) override;
		int_type overflow(int_type ch) override;
		int_type pbackfail(int_type c) override;

	};

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

	namespace utf8
	{
		DOG_CRYPTION_API std::string to_utf8(uint64_t code);
		DOG_CRYPTION_API uint64_t utf8_size(std::string str);
		DOG_CRYPTION_API uint64_t utf8_size(const char* str);
		DOG_CRYPTION_API std::string get_utf8_char(std::string str, uint64_t offset);
		DOG_CRYPTION_API std::string get_utf8_char(const char* str, uint64_t offset);
	};

}