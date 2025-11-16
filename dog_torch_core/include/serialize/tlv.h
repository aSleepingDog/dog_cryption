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

#include "Data.h"
#include "utils/Exception.h"

namespace dog_torch { namespace serialize { namespace tlv
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
	DOG_CRYPTION_API dog_torch::serialize::Data boolean(bool b);

	DOG_CRYPTION_API dog_torch::serialize::Data integer_num(uint64_t num);
	DOG_CRYPTION_API dog_torch::serialize::Data integer_num(int64_t num);

	DOG_CRYPTION_API dog_torch::serialize::Data float_num(float num);
	DOG_CRYPTION_API dog_torch::serialize::Data float_num(double num);

	DOG_CRYPTION_API dog_torch::serialize::Data bytes(const std::vector<uint8_t>& bytes);
	DOG_CRYPTION_API dog_torch::serialize::Data bytes(const uint8_t* bytes, uint64_t size);
	DOG_CRYPTION_API dog_torch::serialize::Data bytes(std::istream& stream);

	DOG_CRYPTION_API dog_torch::serialize::Data string(const char* str);
	DOG_CRYPTION_API dog_torch::serialize::Data string(std::string str);

	DOG_CRYPTION_API dog_torch::serialize::Data array(const std::vector<std::any>& arr);

	DOG_CRYPTION_API dog_torch::serialize::Data object(const std::unordered_map<std::string, std::any>& obj);
	DOG_CRYPTION_API dog_torch::serialize::Data object(const std::map<std::string, std::any>& obj);

	DOG_CRYPTION_API std::any read(std::istream& data);
	DOG_CRYPTION_API std::any read(dog_torch::serialize::DataStream& data);
	DOG_CRYPTION_API std::any read(dog_torch::serialize::Data data);
}}};