#include "../include/cryption/dog_exception.h"

dog_exception::Exception::Exception(
	std::string msg, std::basic_stacktrace<std::allocator<std::stacktrace_entry>> stacktrace, std::thread::id thread_id,
	std::string file, std::string func, uint64_t line)
{
	this->msg += std::format("{}\n[{}]\"{}\":{}->{}\n", msg, thread_id, file, line, func);
	for (auto& stack : stacktrace)
	{
		this->msg += std::format("|---\"{}\":{}->{}\n", stack.source_file(), stack.source_line(), stack.description());
	}
}
const char* dog_exception::Exception::what() const noexcept
{
	return this->msg.c_str();
}


