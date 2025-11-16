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
#include<stacktrace>
#include<exception>

#ifdef _MSC_VER

#define DOG_EXCEPTION_MSG_PARAMS std::string msg, std::basic_stacktrace<std::allocator<std::stacktrace_entry>> stacktrace, std::thread::id thread_id, std::string file, std::string func, uint64_t line
#define DOG_EXCEPTION_PARAMS std::basic_stacktrace<std::allocator<std::stacktrace_entry>> stacktrace, std::thread::id thread_id, std::string file, std::string func, uint64_t line

#define DOG_EXCEPTION_MSG_OPINION(msg) \
std::string(msg),std::stacktrace::current(),std::this_thread::get_id(),\
std::string(__FILE__), std::string(__FUNCTION__), __LINE__

#define DOG_EXCEPTION_OPINION \
std::stacktrace::current(),std::this_thread::get_id(),\
std::string(__FILE__), std::string(__FUNCTION__), __LINE__

#define DOG_EXCEPTION(msg) dog_torch::utils::Exception(DOG_EXCEPTION_MSG_OPINION(msg))

namespace dog_torch{ namespace utils
{
	class DOG_CRYPTION_API Exception : public std::exception
	{
	protected:
		std::string msg;
	public:
		Exception(std::string msg, std::basic_stacktrace<std::allocator<std::stacktrace_entry>> stacktrace, std::thread::id thread_id, 
			std::string file, std::string func, uint64_t line);
		const char* what() const noexcept override;
	};
}}
#endif

#ifdef __GNUC__
#define DOG_EXCEPTION_MSG_PARAMS std::string msg, std::thread::id thread_id, std::string file, std::string func, uint64_t line
#define DOG_EXCEPTION_PARAMS std::thread::id thread_id, std::string file, std::string func, uint64_t line

#define DOG_EXCEPTION_MSG_OPINION(msg) \
std::string(msg),std::this_thread::get_id(),\
std::string(__FILE__), std::string(__FUNCTION__), __LINE__

#define DOG_EXCEPTION_OPINION \
std::this_thread::get_id(),\
std::string(__FILE__), std::string(__FUNCTION__), __LINE__

#define DOG_EXCEPTION(msg) dog_torch::utils::Exception(DOG_EXCEPTION_MSG_OPINION(msg))

namespace dog_torch {
	namespace utils
	{
		class DOG_CRYPTION_API Exception : public std::exception
		{
		protected:
			std::string msg;
		public:
			Exception(std::string msg, std::thread::id thread_id,
				std::string file, std::string func, uint64_t line);
			const char* what() const noexcept override;
		};
	}
}

#endif