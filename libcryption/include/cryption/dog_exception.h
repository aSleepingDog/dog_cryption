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

#define DOG_EXCEPTION_OPINION(msg) \
std::string(msg),std::stacktrace::current(),std::this_thread::get_id(),\
std::string(__FILE__), std::string(__FUNCTION__), __LINE__

#define DOG_EXCEPTION(msg) dog_exception::Exception(DOG_EXCEPTION_OPINION(msg))

namespace dog_exception
{
	class DOG_CRYPTION_API Exception : public std::exception
	{
	private:
		std::string msg;
	public:
		Exception(std::string msg, std::basic_stacktrace<std::allocator<std::stacktrace_entry>> stacktrace, std::thread::id thread_id, 
			std::string file, std::string func, uint64_t line);
		const char* what() const noexcept override;
	};
}