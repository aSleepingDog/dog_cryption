#pragma once
#ifdef SHARED
	#include "export.h"
#else
	#define DOG_CRYPTION_API
#endif
#include<print>
#include<memory>
#include<format>
#include<thread>
#include<string>
#include<sstream>
#include<string_view>
#include<stacktrace>
#include<exception>

#ifdef STACKTACRE 

	#define DOG_EXCEPTION_MSG_PARAMS \
	std::string msg,\
	std::basic_stacktrace<std::allocator<std::stacktrace_entry>> stacktrace,\
	std::thread::id thread_id,\
	std::string file,\
	std::string func,\
	uint64_t line

	#define DOG_EXCEPTION_PARAMS 
	std::basic_stacktrace<std::allocator<std::stacktrace_entry>> stacktrace,\
	std::thread::id thread_id,\
	std::string file,\
	std::string func,\
	uint64_t line

	#define DOG_EXCEPTION_OPINION \
	std::stacktrace::current(),\
	std::this_thread::get_id(),\
	dog_torch::utils::Exception::get_abstract_path(__FILE__),\
	std::string(__FUNCTION__),\
	__LINE__

	#define DOG_EXCEPTION_MSG_OPINION(msg) \
	std::string(msg),DOG_EXCEPTION_OPINION


	#define DOG_EXCEPTION(msg) dog_torch::utils::Exception(DOG_EXCEPTION_MSG_OPINION(msg))

#else

	#define DOG_EXCEPTION_MSG_PARAMS \
	std::string msg,\
	std::thread::id thread_id,\
	std::string file,\
	std::string func,\
	uint64_t line

	#define DOG_EXCEPTION_PARAMS \
	std::thread::id thread_id, \
	std::string file, \
	std::string func, \
	uint64_t line

	#define DOG_EXCEPTION_OPINION \
	std::this_thread::get_id(),\
	dog_torch::utils::Exception::get_abstract_path(__FILE__),\
	std::string(__FUNCTION__),\
	__LINE__

	#define DOG_EXCEPTION_MSG_OPINION(msg) \
	std::string(msg), DOG_EXCEPTION_OPINION

	#define DOG_EXCEPTION(msg) dog_torch::utils::Exception(DOG_EXCEPTION_MSG_OPINION(msg))

#endif // STACKTACRE 

namespace dog_torch::utils
{
	class DOG_CRYPTION_API Exception : public std::exception
	{
	protected:
		std::string msg;
	public:
		Exception(DOG_EXCEPTION_MSG_PARAMS);
		const char* what() const noexcept override;

		constexpr static const char* get_abstract_path(const char* path)
		{
			std::string_view sv_path(path);
			constexpr std::string_view target = "dog_torch_core";

			size_t pos = sv_path.find(target);
			if (pos != std::string_view::npos)
			{
				return path + pos;
			}
			return nullptr;
		}
	};
}