#pragma once
#include <iostream>
#include <vector>
#include <any>
#include <map>
#include <unordered_map>
#include <array>

#include "big_number.h"

class DogException : public std::exception
{
private:
	std::string msg;
public:
	DogException(const char* msg, const char* file, const char* function, uint64_t line);
	~DogException() = default;
	virtual const char* what() const throw();
};

namespace dog_data
{
	class Data
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

		std::vector<uint8_t>::iterator begin();
		std::vector<uint8_t>::iterator end();
		std::vector<uint8_t>::const_iterator cbegin() const;
		std::vector<uint8_t>::const_iterator cend() const;
		std::reverse_iterator<std::vector<uint8_t>::iterator> rbegin();
		std::reverse_iterator<std::vector<uint8_t>::iterator> rend();
		std::reverse_iterator<std::vector<uint8_t>::const_iterator> crbegin() const;
		std::reverse_iterator<std::vector<uint8_t>::const_iterator> crend() const;

		std::vector<char> getUTF8Vector();
		std::vector<char> getBase64Vector();
		std::vector<char> getBase64Vector(char a, char b);
		std::vector<char> getBase64Vector(char a, char b, char c);
		std::vector<char> getHexVector(bool is_upper = true);
		
		std::string getUTF8String();
		std::string getBase64String();
		std::string getBase64String(char a, char b);
		std::string getBase64String(char a, char b, char c);
		std::string getHexString(bool is_upper = true);
		
		dog_data::Data sub_by_pos(uint64_t start, uint64_t end) const;
		dog_data::Data sub_by_len(uint64_t start, uint64_t len) const;

		dog_data::Data sub_by_pos(std::vector<uint8_t>::iterator start, std::vector<uint8_t>::iterator end) const;
		dog_data::Data sub_by_len(std::vector<uint8_t>::iterator start, uint64_t len) const;

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
		void clear_leave_pos();
		/*
		* 将所有位置重置为0
		*/
		void clear_set_zero();

		void push_back(uint8_t b);
		void pop_back();

		/* 颠倒顺序 */
		void reverse();

		void swap(Data& d);
		void swap(Data d);

		dog_data::Data bit_left_move_norise(uint64_t shift);
		void bit_left_move_norise_self(uint64_t shift);

		dog_data::Data bit_left_move_rise(uint64_t shift);
		void bit_left_move_rise_self(uint64_t shift);

		dog_data::Data bit_right_move_norise(uint64_t shift);
		void bit_right_move_norise_self(uint64_t shift);

		dog_data::Data bit_right_move_rise(uint64_t shift);
		void bit_right_move_rise_self(uint64_t shift);

		dog_data::Data bit_circle_left_move(uint64_t shift);
		dog_data::Data bit_circle_right_move(uint64_t shift);


		dog_data::Data operator~();
		friend dog_data::Data operator&(const Data d1, const Data d2);
		friend dog_data::Data operator|(const Data d1, const Data d2);
		friend dog_data::Data operator^(const Data d1, const Data d2);

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

	const Data EMPTY_DATA = "";

	class DataStream
	{
	private:
		dog_data::Data data_;
		uint64_t pos_ = 0;
	public:
		DataStream(dog_data::Data& data);
		uint8_t* data();
		uint8_t get();
		uint8_t peek();
		void unget();
		uint64_t tellg() const;
	};

	namespace buffer
	{
		uint64_t get_buffer_size(uint64_t file_size);
	}

	namespace serialize
	{
		/*
		   null  -> 0000 0000
		  start  -> 0000 0001
		   end   -> 0000 0010
		   bool  -> 0010 (0000/1111=false/true)
		   int   -> 100 (0/1=+/-) 0001-1000(0-8):length
		  float  -> 101X (4/8=float/double)
		  bytes  -> 010X 0000-1000(0-8):length length + int(length) + bytes
		 string  -> 011X 0000-1000(0-8):length length + int(length) + bytes(utf8)
		  array  -> 110X 0000-1000(0-8):length length + int(length) + other
		 object(hash table)  -> 111X 0000-1000(0-8):length length + int(length) + string:other
		*/
		dog_data::Data boolean(bool b);

		dog_data::Data integer_num(uint64_t num);
		dog_data::Data integer_num(int64_t num);

		dog_data::Data float_num(float num);
		dog_data::Data float_num(double num);

		dog_data::Data bytes(const std::vector<uint8_t>& bytes);
		dog_data::Data bytes(const uint8_t* bytes, uint64_t size);
		dog_data::Data bytes(std::istream& stream);

		dog_data::Data string(const char* str);
		dog_data::Data string(std::string str);

		dog_data::Data array(const std::vector<std::any>& arr);

		dog_data::Data object(const std::unordered_map<std::string, std::any>& obj);
		dog_data::Data object(const std::map<std::string, std::any>& obj);

		std::any read(std::istream& data);
		std::any read(dog_data::DataStream& data);
		std::any read(dog_data::Data data);

	}

	namespace print
	{
		void block(dog_data::Data data, uint64_t column = 16);
		void block(const char* data, uint64_t size, uint64_t column = 16);

		void space(dog_data::Data data, uint64_t column = 16);
		void space(const char* data, uint64_t size, uint64_t column = 16);
	}
}