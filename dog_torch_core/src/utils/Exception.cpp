#include "utils/Exception.h"

#ifdef STACKTACRE 

dog_torch::utils::Exception::Exception(DOG_EXCEPTION_MSG_PARAMS)
{
    this->msg += std::format("{}\n[{}]\"{}\":{}->{}\n", msg, thread_id, file, line, func);
	for (auto& stack : stacktrace)
	{
		this->msg += std::format("|---\"{}\":{}->{}\n", stack.source_file(), stack.source_line(), stack.description());
	}
}


#else

dog_torch::utils::Exception::Exception(DOG_EXCEPTION_MSG_PARAMS)
{
    this->msg += std::format("{}\n[{}]\"{}\":{}->{}\n", msg, thread_id, file, line, func);
}


#endif // STACKTACRE 


const char* dog_torch::utils::Exception::what() const noexcept
{
    return this->msg.c_str();
}

constexpr std::string_view dog_torch::utils::Exception::get_abstract_path(std::string_view path)
{
    auto it = path.find("src");
    it += 4;
    return it != std::string_view::npos ? path.substr(it) : path;
}

