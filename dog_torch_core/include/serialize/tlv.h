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
#include "utils/Exception.h"

namespace dog_torch::serialize::tlv
{
	/*
		null    -> 0000 0000                                                                    | 0
		bool    -> 0010 (0000/1111=false/true)                                                  | 2
		int     -> 100 (0/1=+/-) 0001-1000(0-8):length                                          | 8
		float   -> 101X (4/8=float/double)                                                      | A
		bytes   -> 010X 0000-1000(1-8):length length + int(length) + bytes                      | 4
		string  -> 011X 0000-1000(1-8):length length + int(length) + bytes(utf8)                | 6
		array   -> 110X 0000-1000(1-8):length length + int(length) + other                      | C
		object(hash table)  -> 111X 0000-1000(0-8):length length + int(length) + string:other   | E
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
	};

	DOG_CRYPTION_API dog_torch::serialize::BinaryData null_type();
	DOG_CRYPTION_API dog_torch::serialize::BinaryData null_type(std::nullptr_t value);

	DOG_CRYPTION_API dog_torch::serialize::BinaryData boolean(bool b);

	DOG_CRYPTION_API dog_torch::serialize::BinaryData integer_num(uint64_t num);
	DOG_CRYPTION_API dog_torch::serialize::BinaryData integer_num(int64_t num);

	DOG_CRYPTION_API dog_torch::serialize::BinaryData float_num(float num);
	DOG_CRYPTION_API dog_torch::serialize::BinaryData float_num(double num);

	DOG_CRYPTION_API dog_torch::serialize::BinaryData bytes(const std::vector<uint8_t>& bytes);
	DOG_CRYPTION_API dog_torch::serialize::BinaryData bytes(const uint8_t* bytes, uint64_t size);
	DOG_CRYPTION_API dog_torch::serialize::BinaryData bytes(std::istream& stream);

	DOG_CRYPTION_API dog_torch::serialize::BinaryData string(const char* str);
	DOG_CRYPTION_API dog_torch::serialize::BinaryData string(std::string str);

	DOG_CRYPTION_API dog_torch::serialize::BinaryData array(const std::vector<std::any>& arr);

	DOG_CRYPTION_API dog_torch::serialize::BinaryData array(const std::vector<Value>& arr);

	DOG_CRYPTION_API dog_torch::serialize::BinaryData object(const std::unordered_map<std::string, std::any>& obj);
	DOG_CRYPTION_API dog_torch::serialize::BinaryData object(const std::map<std::string, std::any>& obj);

	DOG_CRYPTION_API dog_torch::serialize::BinaryData object(const std::unordered_map<std::string, Value>& obj);

	DOG_CRYPTION_API std::any read_any(std::istream& data);
	DOG_CRYPTION_API std::any read_any(dog_torch::serialize::DataStream& data);
	DOG_CRYPTION_API std::any read_any(dog_torch::serialize::BinaryData data);

	DOG_CRYPTION_API Value read_value(std::istream& data);
	DOG_CRYPTION_API Value read_value(dog_torch::serialize::DataStream& data);
	DOG_CRYPTION_API Value read_value(dog_torch::serialize::BinaryData data);
};