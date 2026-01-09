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

namespace dog_torch::serialize::json
{
	using array = std::vector<std::any>;
	using object = std::unordered_map<std::string, std::any>;
	namespace any
	{
		DOG_CRYPTION_API std::string to_json_str(std::nullptr_t value);
		DOG_CRYPTION_API std::string to_json_str(bool value);
		DOG_CRYPTION_API std::string to_json_str(double number);
		DOG_CRYPTION_API std::string to_json_str(const char* param);
		DOG_CRYPTION_API std::string to_json_str(std::string param);
		DOG_CRYPTION_API std::string to_json_str(array list, bool is_fmt, uint64_t depth);
		DOG_CRYPTION_API std::string to_json_str(array list, bool is_fmt);
		DOG_CRYPTION_API std::string to_json_str(object object, bool is_fmt, uint64_t depth);
		DOG_CRYPTION_API std::string to_json_str(object object, bool is_fmt);

		DOG_CRYPTION_API void            skip_whitespace(std::string::const_iterator& now, std::string::const_iterator end);
		DOG_CRYPTION_API std::nullptr_t  to_null        (std::string::const_iterator& now, std::string::const_iterator end);
		DOG_CRYPTION_API bool            to_bool        (std::string::const_iterator& now, std::string::const_iterator end);
		DOG_CRYPTION_API double          to_number      (std::string::const_iterator& now, std::string::const_iterator end);
		DOG_CRYPTION_API std::string     to_string      (std::string::const_iterator& now, std::string::const_iterator end);
		DOG_CRYPTION_API array           to_array       (std::string::const_iterator& now, std::string::const_iterator end);
		DOG_CRYPTION_API object          to_object      (std::string::const_iterator& now, std::string::const_iterator end);

		DOG_CRYPTION_API void            skip_whitespace(std::istream& input);
		DOG_CRYPTION_API std::nullptr_t  to_null        (std::istream& input);
		DOG_CRYPTION_API bool            to_bool        (std::istream& input);
		DOG_CRYPTION_API double          to_number      (std::istream& input);
		DOG_CRYPTION_API std::string     to_string      (std::istream& input);
		DOG_CRYPTION_API array           to_array       (std::istream& input);
		DOG_CRYPTION_API object          to_object      (std::istream& input);
	};
	DOG_CRYPTION_API enum class Type
	{
		undefined = 0x00,
		null = 0x01,
		boolean = 0x02,
		number = 0x03,
		string = 0x04,
		array = 0x05,
		object = 0x06,
	};
	DOG_CRYPTION_API std::string to_string(Type type);

	class DOG_CRYPTION_API Value;
	class DOG_CRYPTION_API Array;
	class DOG_CRYPTION_API Object;

	class DOG_CRYPTION_API Value
	{
	private:
		std::variant<
			std::nullptr_t, bool, double, std::string, std::vector<Value>, std::unordered_map<std::string, Value>
		> value_;
	public:
		Value();
		Value(std::nullptr_t value);
		Value(bool value);
		Value(double value);
		Value(std::string value);
		Value(std::string::const_iterator& now, std::string::const_iterator end);
		Value(std::istream& input);
		Value(std::vector<Value> value);
		Value(Array value);
		Value(std::unordered_map<std::string, Value> value);
		Value(Object value);
		Type get_type() const;

		std::nullptr_t to_null() const;
		bool to_bool() const;
		double to_number() const;
		std::string to_string() const;

		std::vector<Value> to_std_vector() const;
		Array to_array() const;

		std::unordered_map<std::string, Value> to_std_map() const;
		Object to_object() const;

		std::string to_json_str(bool is_fmt, uint64_t depth) const;
	};

	class DOG_CRYPTION_API Object
	{
		using object = std::unordered_map<std::string, Value>;
	private:
		object value_;
	public:
		Object();
		Object(object value);
		Object(std::string::const_iterator& now, std::string::const_iterator end);
		Object(std::string str) : Object((std::string::const_iterator&)str.cbegin(), str.cend()) {}
		Object(std::istream& input);

		object to_std_map();
		std::string to_json_str(bool is_fmt, uint64_t depth);
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
		array value_;
	public:
		Array();
		Array(array value);
		Array(std::string::const_iterator& now, std::string::const_iterator end);
		Array(std::string str) : Array((std::string::const_iterator&)str.cbegin(), str.cend()) {}
		Array(std::istream& input);

		array to_std_vector();
		std::string to_json_str(bool is_fmt, uint64_t depth);
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