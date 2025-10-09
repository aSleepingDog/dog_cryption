#pragma once
#ifdef SHARED
	#include "export.h"
#else
	#define DOG_TASK_API
#endif

#include <format>
#include <filesystem>

#include "../../../libcryption/include/cryption/dog_cryption.h"

namespace dog_param
{
#ifdef _MSC_VER
	class DOG_TASK_API WrongTypeException : public dog_exception::Exception
	{
	public:
		WrongTypeException(
			std::basic_stacktrace<std::allocator<std::stacktrace_entry>> stacktrace, std::thread::id thread_id,
			std::string file, std::string func, uint64_t line) : 
			dog_exception::Exception("输入类型错误,只能是UTF-8/Base64/Hex", stacktrace, thread_id, file, func, line) {}
	};
#elifdef __GNUC__
    class DOG_TASK_API WrongTypeException : public dog_exception::Exception
    {
    public:
        WrongTypeException(
                std::thread::id thread_id,
                std::string file, std::string func, uint64_t line) :
                dog_exception::Exception("输入类型错误,只能是UTF-8/Base64/Hex", thread_id, file, func, line) {}
    };

#endif

	class DOG_TASK_API IOConfig
	{
		/*
		ori_str      std::string    原始数据字符串
		is_file      bool           是否文件 若是忽略下方
		type         uint64_t       输入类型代码0/1/2
		if type==1                  即输入为Base64时
		replace0     char           替换+
		replace1     char           替换/
		replace2     char           替换=
		if type==2
		is_upper     bool           是否大写
		*/
	private:
		std::unordered_map<std::string, std::any> params_;
		bool is_input_;
	public:
		IOConfig(std::unordered_map<std::string, std::any> params, bool is_input);
		IOConfig(dog_data::JsonObject json, bool is_input);
		bool is_file();
		bool is_data();
		uint64_t get_data_type();
		std::string get_IO_string();
		char get_replace0();
		char get_replace1();
		char get_replace2();
		bool get_is_upper();
		dog_data::Data get_data();
		std::string get_file_path();
		std::string fmt_data(dog_data::Data data);
		std::string get_ori_str();
	};
}