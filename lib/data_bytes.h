#pragma once
#include <iostream>
#include <vector>

class dog_exception : public std::exception
{
private:
	std::string msg;
public:
	dog_exception(const char* msg, const char* file, const char* function, uint64_t line);
	~dog_exception() = default;
	virtual const char* what() const throw();
};

namespace DogData
{
	typedef uint64_t Ullong;
	typedef uint32_t Uint;
	typedef uint16_t Ushort;
	typedef uint8_t byte;

	class Data
	{
	private:
		std::vector<byte> inside_data;

	public:
		const static int UTF8 = 0;
		const static int BASE64 = 1;
		const static int HEX = 2;

		Data() = default;
		Data(std::string str, const int type = 2);
		Data(const char* str, const int type = 2) : Data(std::string(str), type) {};
		Data(Ullong size);

        Data(const Data& other);
		void operator=(const Data& other);
		Data(Data&& other);
		~Data();

		byte& at(Ullong i);
		byte at(Ullong i) const;
		byte& operator[](Ullong i);
		byte operator[](Ullong i) const;
		byte& front();
		byte& back();
		byte* data();

		std::vector<byte>::iterator begin();
		std::vector<byte>::iterator end();
		std::vector<byte>::const_iterator cbegin() const;
		std::vector<byte>::const_iterator cend() const;
		std::reverse_iterator<std::vector<byte>::iterator> rbegin();
		std::reverse_iterator<std::vector<byte>::iterator> rend();
		std::reverse_iterator<std::vector<byte>::const_iterator> crbegin() const;
		std::reverse_iterator<std::vector<byte>::const_iterator> crend() const;

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
		
		DogData::Data sub_by_pos(Ullong start, Ullong end) const;
		DogData::Data sub_by_len(Ullong start, Ullong len) const;

		bool empty() const;
		Ullong size() const;
		Ullong max_size() const;
		void reserve(Ullong n);

		//void insert(const Ullong i, byte b);
		void insert(const std::vector<byte>::iterator pos, byte b);

		//void erase(const Ullong i);
		void erase(const std::vector<byte>::iterator pos);

		void clear_leave_pos();
		void clear_set_zero();

		void push_back(byte b);
		void pop_back();

		void reverse();

		void swap(Data& d);
		void swap(Data d);

		friend DogData::Data operator<<(Data& d,Ullong shift);
		friend DogData::Data operator>>(Data& d, Ullong shift);

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

	namespace buffer
	{
		Ullong get_buffer_size(Ullong file_size);
	}

	namespace print
	{
		void block(DogData::Data data, Ullong column = 16);
		void block(const char* data, Ullong size, Ullong column = 16);

		void space(DogData::Data data, Ullong column = 16);
		void space(const char* data, Ullong size, Ullong column = 16);
	}
}