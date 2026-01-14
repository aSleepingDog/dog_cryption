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
#include "BinaryData.h"
#include "Json.h"
#include "Jsonx.h"

namespace dog_torch::serialize::jsont
{

	DOG_CRYPTION_API enum class Type
	{
		undefined = 0x00,
		null = 0x01,
		boolean = 0x02,
		int64 = 0x03,
		uint64 = 0x04,
		float64 = 0x05,
		string = 0x06,
		array = 0x07,
		object = 0x08,
	};
	DOG_CRYPTION_API std::string to_string(Type type);

	namespace any
	{
		void skip_whitespace  (std::string::const_iterator& now, std::string::const_iterator end);
		Type to_type          (std::string::const_iterator& now, std::string::const_iterator end);
		std::string to_string (std::string::const_iterator& now, std::string::const_iterator end);

		void skip_whitespace  (std::istream& input);
		Type to_type          (std::istream& input);
		std::string to_string (std::istream& input);
	};

	class DOG_CRYPTION_API Value;
	class DOG_CRYPTION_API Array;
	class DOG_CRYPTION_API Object;

	class DOG_CRYPTION_API Value
	{
	private:
		std::variant<
			Type, std::vector<Value>, std::unordered_map<std::string, Value>
		> value_;
	public:
		Value();
		Value(Type value);
		Value(std::vector<Value> value);
		Value(std::unordered_map<std::string, Value> value);
		Value(std::string::const_iterator& now, std::string::const_iterator end);
		Value(std::string str);
		Value(std::istream& input);
		Type get_type() const;

		std::vector<Value> to_std_vector() const;
		Array to_array() const;

		std::unordered_map<std::string, Value> to_std_map() const;
		Object to_object() const;

		std::string to_json_str(bool is_fmt, uint64_t depth) const;

		bool match(const dog_torch::serialize::json::Value& value) const;
		bool match(const dog_torch::serialize::jsonx::Value& value) const;
	};

	class DOG_CRYPTION_API Object
	{
		using object = std::unordered_map<std::string, Value>;
	private:
		std::unordered_map<std::string, Value> value_;
	public:
		Object();
		Object(std::unordered_map<std::string, Value> value);
		Object(std::string::const_iterator& now, std::string::const_iterator end);
		Object(std::string str);
		Object(std::istream& input);

		std::unordered_map<std::string, Value> to_std_map();
		std::string to_json_str(bool is_fmt, uint64_t depth);
		bool match(const dog_torch::serialize::json::Object& value) const;
		bool match(const dog_torch::serialize::jsonx::Object& value) const;
		//Capacity
		size_t size() const;
		size_t max_size() const;
		bool empty() const;
		//iterators
		using it = object::iterator;
		using cit = object::const_iterator;
		it begin();
		it end();
		cit cbegin() const;
		cit cend() const;
		//Lookup
		Value& at(const std::string& key);
		const Value& at(const std::string& key) const;
		Value& operator[](const std::string& key);
		const Value& operator[](const std::string& key) const;
		object::size_type count(const std::string& key) const;
		it find(const std::string& key);
		cit find(const std::string& key) const;
		bool contains(const std::string& key) const;
		std::pair<it, it> equal_range(const std::string& key);
		std::pair<cit, cit> equal_range(const std::string& key) const;
		//Modifiers
		void clear();
		std::pair<it, bool> insert(const std::pair<std::string, Value>& value);
		std::pair<it, bool> insert(std::pair<std::string, Value>&& value);
		it erase(cit pos);
		it erase(cit first, cit last);
	};

	class DOG_CRYPTION_API Array
	{
		using array = std::vector<Value>;
	private:
		std::vector<Value> value_;
	public:
		Array();
		Array(std::vector<Value> value);
		Array(std::string::const_iterator& now, std::string::const_iterator end);
		Array(std::string str);
		Array(std::istream& input);

		std::vector<Value> to_std_vector();
		std::string to_json_str(bool is_fmt, uint64_t depth);
		bool match(const dog_torch::serialize::json::Array& value) const;
		bool match(const dog_torch::serialize::jsonx::Array& value) const;
		//Element access
		Value& at(size_t pos);
		const Value& at(size_t pos) const;
		Value& operator[](size_t pos);
		const Value& operator[](size_t pos) const;
		Value& front();
		const Value& front() const;
		Value& back();
		const Value& back() const;
		Value* data();
		const Value* data() const;
		//Capacity
		size_t size() const;
		size_t max_size() const;
		bool empty() const;
		void reserve(size_t new_cap);
		array::size_type capacity() const;
		void shrink_to_fit();
		//Iterators
		using it = array::iterator;
		using cit = array::const_iterator;
		using rit = array::reverse_iterator;
		using crit = array::const_reverse_iterator;

		it begin();
		cit cbegin() const;

		it end();
		cit cend() const;

		rit rbegin();
		crit crbegin() const;

		rit rend();
		crit crend() const;
		//Modifiers
		void clear();
		it insert(cit pos, const Value& value);
		it insert(cit pos, Value&& value);
		void push_back(const Value& value);
		void push_back(Value&& value);
		void emplace(cit pos, Value&& value);
		void emplace_back(const Value& value);
		void emplace_back(Value&& value);
		void pop_back();
		it erase(cit pos);
		it erase(cit first, cit last);
		void resize(size_t count);
		void resize(size_t count, const Value& value);

	};

}