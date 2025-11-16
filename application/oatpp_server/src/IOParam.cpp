#include "../include/domain/param/IOParam.h"

dog_param::IOConfig IOParam::to_IOConfig(bool is_input)
{
    std::unordered_map<std::string, std::any> args;
#define CHECK_NULLPTR(ptr) \
if(this->ptr.get()) \
{ args[#ptr] = *(this->ptr); };

    CHECK_NULLPTR(ori_str)
    CHECK_NULLPTR(is_file)
    CHECK_NULLPTR(type)
#define CHECK_CHAR(ptr) \
if (this->ptr.get())\
{\
    if ((*(this->ptr)).size() > 0)\
    {\
        args[#ptr] = '\0';\
    }\
    else\
    {\
        args[#ptr] = (*(this->ptr))[0];\
    }\
}
    CHECK_CHAR(replace0)
    CHECK_CHAR(replace1)
    CHECK_CHAR(replace2)
    CHECK_NULLPTR(is_upper)
#undef CHECK_NULLPTR
#undef CHECK_CHAR
    return dog_param::IOConfig(args, is_input);
}
