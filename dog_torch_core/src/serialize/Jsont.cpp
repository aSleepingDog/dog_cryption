#include "serialize/Jsont.h"

#define DOG_ERROR_UNEXCEPT_END "Error:unexpected end of jsont string"
#define DOG_ERROR_UNEXCEPT_CHAR "Error: unexpected character of jsont string"

std::string dog_torch::serialize::jsont::to_string(Type type)
{
    switch (type)
    {
    case Type::undefined:return "undefined";
    case Type::null: return "null";
    case Type::boolean:return "boolean";
    case Type::int64: return "int64";
    case Type::uint64: return "uint64";
    case Type::float64: return "float64";
    case Type::string:return "string";
    case Type::array:return "array";
    case Type::object:return "object";
    }
}

#define CHECK_END if (now == end) throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_END);
void dog_torch::serialize::jsont::any::skip_whitespace(std::string::const_iterator& now, std::string::const_iterator end)
{
    int status = 0;//-1:退出 0:空白字符无/ 1:空白字符单/ 2:单行 3:多行无* 4:多行有*
    while (now != end)
    {
        switch (status)
        {
        case 0:
        {
            switch (*now)
            {
            case '/':
            {
                status = 1; 
                break;
            }
            case ' ':
            case '\t':
            case '\n':
            case '\r':
            {
                now++;
                break;
            }
            default:
            {
                status = -1;
            }
            }
            break;
        }
        case 1:
        {
            switch (*now)
            {
            case '/':
            {
                status = 2;
                break;
            }
            case '*':
            {
                status = 3;
                break;
            }
            default:
            {
                throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
            }
            }
            now++;
            break;
        }
        case 2:
        {
            if (*now == '\n')
            {
                status = 0;
            }
            now++;
            break;
        }
        case 3:
        {
            if (*now == '*')
            {
                status = 4;
            }
            now++;
            break;
        }
        case 4:
        {
            if (*now == '/')
            {
                status = 0;
            }
            else
            {
                status = 3;
            }
            now++;
            break;
        }
        }
        if (status == -1) break;
    }
}
dog_torch::serialize::jsont::Type dog_torch::serialize::jsont::any::to_type(std::string::const_iterator& now, std::string::const_iterator end)
{
    CHECK_END;
    switch (*now)
    {
    case 'n':
    {
        //null number
        if (now + 6 >= end)
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_END);
        }
        auto str = std::string(now, now + 6);
        if (str == "number")
        {
            now += 6;
            return Type::float64;
        }
        else if (str.substr(0, 4) == "null")
        {
            now += 4;
            return Type::null;
        }
        else
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        }
    }
    case 'b':
    {
        //boolean
        if (now + 7 >= end)
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_END);
        }
        auto str = std::string(now, now + 7);
        if (str != "boolean")
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        }
        now += 7;
        return Type::boolean;
    }
    case 's':
    {
        //string
        if (now + 6 >= end)
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_END);
        }
        auto str = std::string(now, now + 6);
        if (str != "string")
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        }
        now += 6;
        return Type::string;
    }
    case 'i':
    {
        //int64
        if (now + 5 >= end)
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_END);
        }
        auto str = std::string(now, now + 5);
        if (str != "int64")
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        }
        now += 5;
        return Type::int64;
    }
    case 'u':
    {
        //uint64
        if (now + 6 >= end)
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_END);
        }
        auto str = std::string(now, now + 6);
        if (str != "uint64")
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        }
        now += 6;
        return Type::uint64;
    }
    case 'f':
    {
        //float64
        if (now + 7 >= end)
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_END);
        }
        auto str = std::string(now, now + 7);
        if (str != "float64")
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        }
        now += 7;
        return Type::float64;
    }
    default:
    {
        throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    }
    }
}
std::string dog_torch::serialize::jsont::any::to_string(std::string::const_iterator& now, std::string::const_iterator end)
{
    CHECK_END;
    if (*now != '"')
    {
        throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    }
    now++;
    std::string result = "";
    int status = 0;//0-普通字符串 1-常规转义字符 2-转义unicode字符但0字符
    uint16_t unicode = 0;
    while (true)
    {
        CHECK_END;
        switch (status)
        {
        case 0:
        {
            if (*now == '"')
            {
                status = -1;
            }
            else if (*now == '\\')
            {
                status = 1;
            }
            else
            {
                result += *now;
            }
            break;
        }
        case 1:
        {
            if (*now == 'u')
            {
                status = 2;
                continue;
            }
            else
            {
                switch (*now)
                {
                case '"':
                {
                    result += '"';
                    break;
                }
                case '\\':
                {
                    result += '\\';
                    break;
                }
                case '/':
                {
                    result += '/';
                    break;
                }
                case 'b':
                {
                    result += '\b';
                    break;
                }
                case 'f':
                {
                    result += '\f';
                    break;
                }
                case 'n':
                {
                    result += '\n';
                    break;
                }
                case 'r':
                {
                    result += '\r';
                    break;
                }
                case 't':
                {
                    result += '\t';
                    break;
                }
                default:
                {
                    throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
                }
                }
                status = 0;
            }
            break;
        }
        case 2:
        {
            now++;
            for (int i = 0; i < 4; i++)
            {
                CHECK_END;
                if (*now >= '0' && *now <= '9')
                {
                    unicode <<= 4;
                    unicode |= *now - '0';
                }
                else if (*now >= 'a' && *now <= 'f')
                {
                    unicode <<= 4;
                    unicode |= *now - 'a' + 10;
                }
                else if (*now >= 'A' && *now <= 'F')
                {
                    unicode <<= 4;
                    unicode |= *now - 'A' + 10;
                }
                else
                {
                    throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
                }
                now++;
            }
            now++;
            result += dog_torch::serialize::utf8::to_utf8(unicode);
            status = 0;
        }
        }
        now++;
        if (status == -1)
        {
            break;
        }
    }
    return result;
}

#define CHECK_SEND if (input.eof()) throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_END);
void dog_torch::serialize::jsont::any::skip_whitespace(std::istream& input)
{
    int status = 0;//-1:退出 0:空白字符无/ 1:空白字符单/ 2:单行 3:多行无* 4:多行有*
    while (!input.eof())
    {
        switch (status)
        {
        case 0:
        {
            switch (input.peek())
            {
            case '/': status = 1;
            case ' ':
            case '\t':
            case '\n':
            case '\r':
            {
                input.get();
                break;
            }
            default:
            {
                status = -1;
            }
            }
            break;
        }
        case 1:
        {
            switch (input.peek())
            {
            case '/':
            {
                status = 2;
                break;
            }
            case '*':
            {
                status = 3;
                break;
            }
            default:
            {
                throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
            }
            }
            input.get();
            break;
        }
        case 2:
        {
            if (input.peek() == '\n')
            {
                status = 0;
            }
            input.get();
            break;
        }
        case 3:
        {
            if (input.peek() == '*')
            {
                status = 4;
            }
            input.get();
            break;
        }
        case 4:
        {
            if (input.peek() == '/')
            {
                status = 0;
            }
            else
            {
                status = 3;
            }
            input.get();
            break;
        }
        }
        if (status == -1) break;
    }
}
dog_torch::serialize::jsont::Type dog_torch::serialize::jsont::any::to_type(std::istream& input)
{
    CHECK_SEND;
    switch (input.peek())
    {
    case 'n':
    {
        //null 4 number 6
        std::string str = "012345";
        input.read(&str[0], 6);
        if (input.gcount() < 6)
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_END);
        }
        if (str == "number")
        {
            return Type::float64;
        }
        else if (str.substr(0, 4) == "null")
        {
            input.unget();
            input.unget();
            return Type::null;
        }
        else
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        }
    }
    case 'b':
    {
        //boolean 7
        std::string str = "0123456";
        input.read(&str[0], 7);
        if (input.gcount() < 7)
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_END);
        }
        if (str != "boolean")
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        }
        return Type::boolean;
    }
    case 's':
    {
        //string 6
        std::string str = "012345";
        input.read(&str[0], 6);
        if (input.gcount() < 6)
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_END);
        }
        if (str != "string")
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        }
        return Type::string;
    }
    case 'i':
    {
        //int64 5
        std::string str = "01234";
        input.read(&str[0], 5);
        if (input.gcount() < 5)
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_END);
        }
        if (str != "int64")
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        }
        return Type::int64;
    }
    case 'u':
    {
        //uint64 6
        std::string str = "012345";
        if (input.gcount() < 6)
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_END);
        }
        if (str != "uint64")
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        }
        return Type::uint64;
    }
    case 'f':
    {
        //float64 7
        std::string str = "0123456";
        input.read(&str[0], 7);
        if (input.gcount() < 7)
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_END);
        }
        if (str != "float64")
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        }
        return Type::float64;
    }
    default:
    {
        throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    }
    }
}
std::string dog_torch::serialize::jsont::any::to_string(std::istream& input)
{
    CHECK_SEND;
    if (input.peek() != '"')
    {
        throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    }
    input.get();
    std::string result = "";
    int status = 0;//0-普通字符串 1-常规转义字符 2-转义unicode字符但0字符
    uint16_t unicode = 0;
    while (true)
    {
        CHECK_SEND;
        switch (status)
        {
        case 0:
        {
            if (input.peek() == '"')
            {
                status = -1;
            }
            else if (input.peek() == '\\')
            {
                status = 1;
            }
            else
            {
                result += input.peek();
            }
            break;
        }
        case 1:
        {
            if (input.peek() == 'u')
            {
                status = 2;
                continue;
            }
            else
            {
                switch (input.peek())
                {
                case '"':
                {
                    result += '"';
                    break;
                }
                case '\\':
                {
                    result += '\\';
                    break;
                }
                case '/':
                {
                    result += '/';
                    break;
                }
                case 'b':
                {
                    result += '\b';
                    break;
                }
                case 'f':
                {
                    result += '\f';
                    break;
                }
                case 'n':
                {
                    result += '\n';
                    break;
                }
                case 'r':
                {
                    result += '\r';
                    break;
                }
                case 't':
                {
                    result += '\t';
                    break;
                }
                default:
                {
                    throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
                }
                }
                status = 0;
            }
            break;
        }
        case 2:
        {
            input.get();
            for (int i = 0; i < 4; i++)
            {
                CHECK_SEND;
                if (input.peek() >= '0' && input.peek() <= '9')
                {
                    unicode <<= 4;
                    unicode |= input.peek() - '0';
                }
                else if (input.peek() >= 'a' && input.peek() <= 'f')
                {
                    unicode <<= 4;
                    unicode |= input.peek() - 'a' + 10;
                }
                else if (input.peek() >= 'A' && input.peek() <= 'F')
                {
                    unicode <<= 4;
                    unicode |= input.peek() - 'A' + 10;
                }
                else
                {
                    throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
                }
                input.get();
            }
            input.get();
            result += dog_torch::serialize::utf8::to_utf8(unicode);
            status = 0;
        }
        }
        input.get();
        if (status == -1)
        {
            break;
        }
    }
    return result;
}

dog_torch::serialize::jsont::Value::Value()
{
    this->value_ = Type::null;
}
dog_torch::serialize::jsont::Value::Value(Type value)
{
    this->value_ = value;
}
dog_torch::serialize::jsont::Value::Value(std::vector<Value> value)
{
    this->value_ = value;
}
dog_torch::serialize::jsont::Value::Value(std::unordered_map<std::string, Value> value)
{
    this->value_ = value;
}
dog_torch::serialize::jsont::Value::Value(std::string::const_iterator& now, std::string::const_iterator end)
{
    if (*now == '[')
    {
        *this = Value(Array(now, end).to_std_vector());
    }
    else if (*now == '{')
    {
        *this = Value(Object(now, end).to_std_map());
    }
    else
    {
        *this = Value(dog_torch::serialize::jsont::any::to_type(now, end));
    }
}
dog_torch::serialize::jsont::Value::Value(std::string str)
{
    auto now = str.cbegin();
    *this = Value(now, str.cend());
}
dog_torch::serialize::jsont::Value::Value(std::istream& input)
{
    *this = Value(dog_torch::serialize::jsont::any::to_string(input));
}
dog_torch::serialize::jsont::Type dog_torch::serialize::jsont::Value::get_type() const
{
    struct visitor
    {
        Type operator()(dog_torch::serialize::jsont::Type value) { return value; }
        Type operator()(std::vector<Value> value) { return Type::array; }
        Type operator()(std::unordered_map<std::string, Value> value) { return Type::object; }
    };
    return std::visit(visitor(), this->value_);
}
std::vector<dog_torch::serialize::jsont::Value> dog_torch::serialize::jsont::Value::to_std_vector() const
{
    if (this->get_type() != Type::array)
    {
        throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    }
    return std::get<std::vector<Value>>(this->value_);
}
dog_torch::serialize::jsont::Array dog_torch::serialize::jsont::Value::to_array() const
{
    return Array(this->to_std_vector());
}
std::unordered_map<std::string, dog_torch::serialize::jsont::Value> dog_torch::serialize::jsont::Value::to_std_map() const
{
    if (this->get_type() != Type::object)
    {
        throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    }
    return std::get<std::unordered_map<std::string, Value>>(this->value_);
}
dog_torch::serialize::jsont::Object dog_torch::serialize::jsont::Value::to_object() const
{
    return Object(this->to_std_map());
}
std::string dog_torch::serialize::jsont::Value::to_json_str(bool is_fmt, uint64_t depth) const
{
    if (this->get_type() != Type::array && this->get_type() != Type::object)
    {
        return dog_torch::serialize::jsont::to_string(this->get_type());
    }
    else if (this->get_type() == Type::array)
    {
        return this->to_array().to_json_str(is_fmt, depth + 1);
    }
    else if (this->get_type() == Type::object)
    {
        return this->to_object().to_json_str(is_fmt, depth + 1);
    }
}
#define MATCH_TYPE(vtype,ttype) value.get_type() == dog_torch::serialize::vtype && this->get_type() == dog_torch::serialize::jsont::Type::ttype
bool dog_torch::serialize::jsont::Value::match(const dog_torch::serialize::json::Value& value) const
{
    if (MATCH_TYPE(json::Type::undefined, undefined))
    {
        return true;
    }
    else if (MATCH_TYPE(json::Type::null, null))
    {
        return true;
    }
    else if (MATCH_TYPE(json::Type::boolean, boolean))
    {
        return true;
    }
    else if (MATCH_TYPE(json::Type::number, float64))
    {
        return true;
    }
    else if (MATCH_TYPE(json::Type::string, string))
    {
        return true;
    }
    else if (MATCH_TYPE(json::Type::array, array))
    {
        this->to_array().match(value.to_array());
    }
    else if (MATCH_TYPE(json::Type::object, object))
    {
        this->to_object().match(value.to_object());
    }
    return false;
}
bool dog_torch::serialize::jsont::Value::match(const dog_torch::serialize::jsonx::Value& value) const
{
    if (MATCH_TYPE(jsonx::Type::undefined, undefined))
    {
        return true;
    }
    else if (MATCH_TYPE(jsonx::Type::null, null))
    {
        return true;
    }
    else if (MATCH_TYPE(jsonx::Type::boolean, boolean))
    {
        return true;
    }
    else if (MATCH_TYPE(jsonx::Type::int64, int64))
    {
        return true;
    }
    else if (MATCH_TYPE(jsonx::Type::uint64, uint64))
    {
        return true;
    }
    else if (MATCH_TYPE(jsonx::Type::float64, float64))
    {
        return true;
    }
    else if (MATCH_TYPE(jsonx::Type::string, string))
    {
        return true;
    }
    else if (MATCH_TYPE(jsonx::Type::array, array))
    {
        return this->to_array().match(value.to_array());
    }
    else if (MATCH_TYPE(jsonx::Type::object, object))
    {
        return this->to_object().match(value.to_object());
    }
    return false;
}

dog_torch::serialize::jsont::Object::Object()
{
}
dog_torch::serialize::jsont::Object::Object(std::unordered_map<std::string, Value> value)
{
    this->value_ = value;
}
dog_torch::serialize::jsont::Object::Object(std::string::const_iterator& now, std::string::const_iterator end)
{
    CHECK_END;
    if (*now != '{')
    {
        throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    }
    using namespace dog_torch::serialize::jsont::any;
    now++;
    std::string key = "";
    auto& result = this->value_;
    while (true)
    {
        skip_whitespace(now, end);
        if (*now == '}')
        {
            break;
        }
        key = to_string(now, end);
        skip_whitespace(now, end);
        if (*now != ':')
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        }
        now++;
        skip_whitespace(now, end);
        result[key] = Value(now, end);
        skip_whitespace(now, end);
        if (*now == '}')
        {
            break;
        }
        else if (*now == ',')
        {
            now++;
        }
        else
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        }

    }
    now++;
}
dog_torch::serialize::jsont::Object::Object(std::string str)
{
    auto now = str.cbegin();
    *this = Object(now, str.cend());
}
dog_torch::serialize::jsont::Object::Object(std::istream& input)
{
    CHECK_SEND;
    if (input.peek() != '{')
    {
        throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    }
    input.get();
    using namespace dog_torch::serialize::jsont::any;
    std::string key = "";
    auto& result = this->value_;
    while (true)
    {
        skip_whitespace(input);
        if (input.peek() == '}')
        {
            break;
        }
        key = to_string(input);
        skip_whitespace(input);
        if (input.peek() != ':')
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        }
        input.get();
        skip_whitespace(input);
        result[key] = Value(input);
        skip_whitespace(input);
        if (input.peek() == '}')
        {
            break;
        }
        else if (input.peek() == ',')
        {
            input.get();
        }
        else
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        }

    }
    input.get();
}
std::unordered_map<std::string, dog_torch::serialize::jsont::Value> dog_torch::serialize::jsont::Object::to_std_map()
{
    return this->value_;
}
std::string dog_torch::serialize::jsont::Object::to_json_str(bool is_fmt, uint64_t depth)
{
    std::string result = "{";
    if (is_fmt) result += '\n';
    for (auto& [key, value] : this->value_)
    {
        auto key_str = dog_torch::serialize::jsonx::any::to_json_str(key);
        std::string value_str = value.to_json_str(is_fmt, depth + 1);
        if (is_fmt)
        {
            for (uint64_t i = 0; i < depth + 1; ++i)
            {
                result += "    ";
            }
            result += std::format("{}: {},\n", key_str, value_str);
        }
        else
        {
            result += std::format("{}:{},", key_str, value_str);
        }
    }
    if (is_fmt)
    {
        result.pop_back();
        result.pop_back();
        result.push_back('\n');
        for (uint64_t i = 0; i < depth; ++i)
        {
            result += "    ";
        }
        result += '}';
    }
    else
    {
        *(result.end() - 1) = '}';
    }
    return result;
}
bool dog_torch::serialize::jsont::Object::match(const dog_torch::serialize::json::Object& value) const
{
    for (auto it = value.cbegin(); it != value.cend(); it++)
    {
        auto [key, v] = *it;
        if (!this->value_.contains(key))
        {
            return false;
        }
        if (!this->value_.at(key).match(v))
        {
            return false;
        }
    }
    return true;
}
bool dog_torch::serialize::jsont::Object::match(const dog_torch::serialize::jsonx::Object& value) const
{
    for (auto it = value.cbegin(); it != value.cend(); it++)
    {
        auto [key, v] = *it;
        if (!this->value_.contains(key))
        {
            return false;
        }
        if (!this->value_.at(key).match(v))
        {
            std::cout << v.to_json_str(false,0) << std::endl;
            return false;
        }
    }
    return true;
}
size_t dog_torch::serialize::jsont::Object::size() const
{
    return this->value_.size();
}
size_t dog_torch::serialize::jsont::Object::max_size() const
{
    return this->value_.max_size();
}
bool dog_torch::serialize::jsont::Object::empty() const
{
    return this->value_.empty();
}
dog_torch::serialize::jsont::Object::it dog_torch::serialize::jsont::Object::begin()
{
    return this->value_.begin();
}
dog_torch::serialize::jsont::Object::it dog_torch::serialize::jsont::Object::end()
{
    return this->value_.end();
}
dog_torch::serialize::jsont::Object::cit dog_torch::serialize::jsont::Object::cbegin() const
{
    return this->value_.cbegin();
}
dog_torch::serialize::jsont::Object::cit dog_torch::serialize::jsont::Object::cend() const
{
    return this->value_.cend();
}
dog_torch::serialize::jsont::Value& dog_torch::serialize::jsont::Object::at(const std::string& key)
{
    return this->value_.at(key);
}
const dog_torch::serialize::jsont::Value& dog_torch::serialize::jsont::Object::at(const std::string& key) const
{
    return this->value_.at(key);
}
dog_torch::serialize::jsont::Value& dog_torch::serialize::jsont::Object::operator[](const std::string& key)
{
    return this->value_[key];
}
const dog_torch::serialize::jsont::Value& dog_torch::serialize::jsont::Object::operator[](const std::string& key) const
{
    return this->value_.at(key);
}
std::unordered_map<std::string, dog_torch::serialize::jsont::Value>::size_type dog_torch::serialize::jsont::Object::count(const std::string& key) const
{
    return this->value_.count(key);
}
dog_torch::serialize::jsont::Object::it dog_torch::serialize::jsont::Object::find(const std::string& key)
{
    return this->value_.find(key);
}
dog_torch::serialize::jsont::Object::cit dog_torch::serialize::jsont::Object::find(const std::string& key) const
{
    return this->value_.find(key);
}
bool dog_torch::serialize::jsont::Object::contains(const std::string& key) const
{
    return this->value_.contains(key);
}
std::pair<dog_torch::serialize::jsont::Object::it, dog_torch::serialize::jsont::Object::it> dog_torch::serialize::jsont::Object::equal_range(const std::string& key)
{
    return this->value_.equal_range(key);
}
std::pair<dog_torch::serialize::jsont::Object::cit, dog_torch::serialize::jsont::Object::cit> dog_torch::serialize::jsont::Object::equal_range(const std::string& key) const
{
    return std::pair<cit, cit>();
}
void dog_torch::serialize::jsont::Object::clear()
{
    this->value_.clear();
}
std::pair<dog_torch::serialize::jsont::Object::it, bool> dog_torch::serialize::jsont::Object::insert(const std::pair<std::string, Value>& value)
{
    return this->value_.insert(value);
}
std::pair<dog_torch::serialize::jsont::Object::it, bool> dog_torch::serialize::jsont::Object::insert(std::pair<std::string, Value>&& value)
{
    return this->value_.insert(std::move(value));
}
dog_torch::serialize::jsont::Object::it dog_torch::serialize::jsont::Object::erase(cit pos)
{
    return this->value_.erase(pos);
}
dog_torch::serialize::jsont::Object::it dog_torch::serialize::jsont::Object::erase(cit first, cit last)
{
    return this->value_.erase(first, last);
}

dog_torch::serialize::jsont::Array::Array()
{
}
dog_torch::serialize::jsont::Array::Array(std::vector<Value> value)
{
    this->value_ = value;
}
dog_torch::serialize::jsont::Array::Array(std::string::const_iterator& now, std::string::const_iterator end)
{
    CHECK_END;
    if (*now != '[')
    {
        throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    }
    using namespace dog_torch::serialize::jsonx::any;
    auto& result = this->value_;
    now++;
    while (true)
    {
        skip_whitespace(now, end);
        result.emplace_back(Value(now, end));
        skip_whitespace(now, end);
        if (*now == ']')
        {
            break;
        }
        else if (*now == ',')
        {
            now++;
        }
        else
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        }
    }
    now++;
}
dog_torch::serialize::jsont::Array::Array(std::string str)
{
    auto now = str.cbegin();
    *this = Array(now, str.cend());
}
std::vector<dog_torch::serialize::jsont::Value> dog_torch::serialize::jsont::Array::to_std_vector()
{
    return this->value_;
}
std::string dog_torch::serialize::jsont::Array::to_json_str(bool is_fmt, uint64_t depth)
{
    std::string result = "[";
    if (is_fmt) result += '\n';
    for (auto& item : this->value_)
    {
        std::string value_str = item.to_json_str(is_fmt, depth + 1);
        if (is_fmt)
        {
            for (uint64_t i = 0; i < depth + 1; ++i)
            {
                result += "    ";
            }
            result += value_str + ",\n";
        }
        else
        {
            result += value_str + ',';
        }

    }
    if (is_fmt)
    {
        result.pop_back();
        result.pop_back();
        result.push_back('\n');
        for (uint64_t i = 0; i < depth; ++i)
        {
            result += "    ";
        }
        result += ']';
    }
    else
    {
        *(result.end() - 1) = ']';
    }
    return result;
}
bool dog_torch::serialize::jsont::Array::match(const dog_torch::serialize::json::Array& value) const
{
    if (this->value_.size() != value.size())
    {
        return false;
    }
    auto ctit = this->value_.cbegin();
    auto vcit = value.cbegin();
    for (; ctit != this->value_.cend() && vcit != value.cend(); ++ctit, ++vcit)
    {
        if (!ctit->match(*vcit))
        {
            return false;
        }
    }
    return true;
}
bool dog_torch::serialize::jsont::Array::match(const dog_torch::serialize::jsonx::Array& value) const
{
    if (this->value_.size() != value.size())
    {
        return false;
    }
    auto ctit = this->value_.begin();
    auto vcit = value.cbegin();
    for (; ctit != this->value_.cend() && vcit != value.cend(); ++ctit, ++vcit)
    {
        if (!ctit->match(*vcit))
        {
            return false;
        }
    }
    return true;
}
size_t dog_torch::serialize::jsont::Array::size() const
{
    return this->value_.size();
}
size_t dog_torch::serialize::jsont::Array::max_size() const
{
    return this->value_.max_size();
}
bool dog_torch::serialize::jsont::Array::empty() const
{
    return this->value_.empty();
}
void dog_torch::serialize::jsont::Array::reserve(size_t new_cap)
{
    this->value_.reserve(new_cap);
}
std::vector<dog_torch::serialize::jsont::Value>::size_type dog_torch::serialize::jsont::Array::capacity() const
{
    return this->value_.capacity();
}
void dog_torch::serialize::jsont::Array::shrink_to_fit()
{
    this->value_.shrink_to_fit();
}
dog_torch::serialize::jsont::Array::it dog_torch::serialize::jsont::Array::begin()
{
    return this->value_.begin();
}
dog_torch::serialize::jsont::Array::cit dog_torch::serialize::jsont::Array::cbegin() const
{
    return this->value_.cbegin();
}
dog_torch::serialize::jsont::Array::it dog_torch::serialize::jsont::Array::end()
{
    return this->value_.end();
}
dog_torch::serialize::jsont::Array::cit dog_torch::serialize::jsont::Array::cend() const
{
    return this->value_.cend();
}
dog_torch::serialize::jsont::Array::rit dog_torch::serialize::jsont::Array::rbegin()
{
    return this->value_.rbegin();
}
dog_torch::serialize::jsont::Array::crit dog_torch::serialize::jsont::Array::crbegin() const
{
    return this->value_.crbegin();
}
dog_torch::serialize::jsont::Array::rit dog_torch::serialize::jsont::Array::rend()
{
    return this->value_.rend();
}
dog_torch::serialize::jsont::Array::crit dog_torch::serialize::jsont::Array::crend() const
{
    return this->value_.crend();
}
void dog_torch::serialize::jsont::Array::clear()
{
    this->value_.clear();
}
dog_torch::serialize::jsont::Array::it dog_torch::serialize::jsont::Array::insert(cit pos, const Value& value)
{
    return this->value_.insert(pos, value);
}
dog_torch::serialize::jsont::Array::it dog_torch::serialize::jsont::Array::insert(cit pos, Value&& value)
{
    return this->value_.insert(pos, value);
}
void dog_torch::serialize::jsont::Array::push_back(const Value& value)
{
    this->value_.push_back(value);
}
void dog_torch::serialize::jsont::Array::push_back(Value&& value)
{
    this->value_.push_back(value);
}
void dog_torch::serialize::jsont::Array::emplace(cit pos, Value&& value)
{
    this->value_.emplace(pos, value);
}
void dog_torch::serialize::jsont::Array::emplace_back(const Value& value)
{
    this->value_.emplace_back(value);
}
void dog_torch::serialize::jsont::Array::emplace_back(Value&& value)
{
    this->value_.emplace_back(value);
}
void dog_torch::serialize::jsont::Array::pop_back()
{
    this->value_.pop_back();
}
dog_torch::serialize::jsont::Array::it dog_torch::serialize::jsont::Array::erase(cit pos)
{
    return this->value_.erase(pos);
}
dog_torch::serialize::jsont::Array::it dog_torch::serialize::jsont::Array::erase(cit first, cit last)
{
    return this->value_.erase(first, last);
}
void dog_torch::serialize::jsont::Array::resize(size_t count)
{
    this->value_.resize(count);
}
void dog_torch::serialize::jsont::Array::resize(size_t count, const Value& value)
{
    this->value_.resize(count, value);
}

#undef CHECK_END
#undef CHECK_SEND
#undef MATCH_TYPE

#undef DOG_ERROR_UNEXCEPT_END
#undef DOG_ERROR_UNEXCEPT_CHAR