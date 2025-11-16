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

namespace dog_torch { namespace serialize
{
	class DOG_CRYPTION_API Data
	{
	private:
		std::vector<uint8_t> inside_data;
	public:
		const static int UTF8 = 0;
		const static int BASE64 = 1;
		const static int HEX = 2;

		Data() = default;
		Data(std::string str, const int type = 2);
		Data(const char* str, const int type = 2) : Data(std::string(str), type) {};
		Data(uint64_t size);

		Data(const Data& other);
		void operator=(const Data& other);
		Data(Data&& other) noexcept;
		~Data();

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

		std::vector<char> to_utf8_vector();
		std::vector<char> to_base64_vector();
		std::vector<char> to_base64_vector(char a, char b);
		std::vector<char> to_base64_vector(char a, char b, char c);
		std::vector<char> to_hex_vector(bool is_upper = true);

		std::string to_utf8_string();
		std::string to_base64_string();
		std::string to_base64_string(char a, char b);
		std::string to_base64_string(char a, char b, char c);
		std::string to_hex_string(bool is_upper = true);

		dog_torch::serialize::Data sub_by_pos(uint64_t start, uint64_t end) const;
		dog_torch::serialize::Data sub_by_len(uint64_t start, uint64_t len) const;

		dog_torch::serialize::Data sub_by_pos(std::vector<uint8_t>::iterator start, std::vector<uint8_t>::iterator end) const;
		dog_torch::serialize::Data sub_by_len(std::vector<uint8_t>::iterator start, uint64_t len) const;

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

		void swap(Data& d);
		void swap(Data d);

		dog_torch::serialize::Data bit_left_move_norise(uint64_t shift);
		void bit_left_move_norise_self(uint64_t shift);

		dog_torch::serialize::Data bit_left_move_rise(uint64_t shift);
		void bit_left_move_rise_self(uint64_t shift);

		dog_torch::serialize::Data bit_right_move_norise(uint64_t shift);
		void bit_right_move_norise_self(uint64_t shift);

		dog_torch::serialize::Data bit_right_move_rise(uint64_t shift);
		void bit_right_move_rise_self(uint64_t shift);

		dog_torch::serialize::Data bit_circle_left_move(uint64_t shift);
		dog_torch::serialize::Data bit_circle_right_move(uint64_t shift);

		dog_torch::serialize::Data operator~();
		friend dog_torch::serialize::Data operator&(const Data d1, const Data d2);
		friend dog_torch::serialize::Data operator|(const Data d1, const Data d2);
		friend dog_torch::serialize::Data operator^(const Data d1, const Data d2);

		//friend bool operator==(const Data& d1, const Data& d2);
		//friend bool operator==(const Data d1, const Data& d2);
		//friend bool operator==(const Data& d1, const Data d2);

		friend bool operator==(const Data d1, const Data d2);
		bool is_equal(const Data& d2) const;

		//friend bool operator!=(const Data& d1, const Data& d2);
		//friend bool operator!=(const Data d1, const Data& d2);
		//friend bool operator!=(const Data& d1, const Data d2);

		friend bool operator!=(const Data d1, const Data d2);

		friend void operator+=(Data& d1, const Data& d2);

		friend Data operator+(const Data& a, const Data b);
		Data concat(const Data& b) const;
	};

	class DOG_CRYPTION_API DataStream
	{
	private:
		dog_torch::serialize::Data data_;
		uint64_t pos_ = 0;
	public:
		DataStream(dog_torch::serialize::Data& data);
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

}}