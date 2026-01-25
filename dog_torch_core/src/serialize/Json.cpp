#include "serialize/Json.h"

#define DOG_ERROR_UNEXCEPT_END "Error:unexpected end of json string"
#define DOG_ERROR_UNEXCEPT_CHAR "Error: unexpected character of json string"

std::string dog_torch::serialize::json::any::to_json_str(std::nullptr_t value)
{
	return "null";
}
std::string dog_torch::serialize::json::any::to_json_str(bool value)
{
	return value ? "true" : "false";
}
std::string dog_torch::serialize::json::any::to_json_str(double number)
{
	return std::to_string(number);
}
std::string dog_torch::serialize::json::any::to_json_str(const char* param)
{
	return to_json_str(std::string(param));
}
std::string dog_torch::serialize::json::any::to_json_str(std::string param)
{
    auto it = param.begin();
    uint64_t pos = 0;
    while (it != param.end())
    {
        if (*it == '"' || *it == '\\' || *it == '/' || *it == '\b' || *it == '\f' || *it == '\n' || *it == '\r' || *it == '\t')
        {
            switch (*it)
            {
            case '\b':
            {
                *it = 'b';
                break;
            }
            case '\f':
            {
                *it = 'f';
                break;
            }
            case '\n':
            {
                *it = 'n';
                break;
            }
            case '\r':
            {
                *it = 'r';
                break;
            }
            case '\t':
            {
                *it = 't';
                break;
            }
            }
            param.insert(it - 1, '\\');
            pos++;
            it = param.begin() + pos;
        }
        else
        {
            it++;
            pos++;
        }
    }
    return "\"" + param + "\"";
}
std::string dog_torch::serialize::json::any::to_json_str(dog_torch::serialize::json::array list, bool is_fmt, uint64_t depth)
{
	std::string result = "[";
	if (is_fmt) result += '\n';
	for (auto& item : list)
	{
		std::string value_str = "undefined";
		if (item.type() == typeid(nullptr))
		{
			value_str = to_json_str(nullptr);
		}
		else if (item.type() == typeid(bool))
		{
			value_str = to_json_str(std::any_cast<bool>(item));
		}
		else if (item.type() == typeid(double))
		{
			value_str = to_json_str(std::any_cast<double>(item));
		}
		else if (item.type() == typeid(std::string))
		{
			value_str = to_json_str(std::any_cast<std::string>(item));
		}
		else if (item.type() == typeid(const char*))
		{
			value_str = to_json_str(std::any_cast<const char*>(item));
		}
		else if (item.type() == typeid(dog_torch::serialize::json::array))
		{
			value_str = to_json_str(std::any_cast<dog_torch::serialize::json::array>(item), is_fmt, depth + 1);
		}
		else if (item.type() == typeid(dog_torch::serialize::json::object))
		{
			value_str = to_json_str(std::any_cast<dog_torch::serialize::json::object>(item), is_fmt, depth + 1);
		}
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
std::string dog_torch::serialize::json::any::to_json_str(dog_torch::serialize::json::array list, bool is_fmt)
{
	return to_json_str(list, is_fmt, 0);
}
std::string dog_torch::serialize::json::any::to_json_str(dog_torch::serialize::json::object object, bool is_fmt, uint64_t depth)
{
    std::string result = "{";
    if (is_fmt) result += '\n';
    for (auto& [key, value] : object)
    {
        auto key_str = to_json_str(key);
        std::string value_str = "undefined";
        if (value.type() == typeid(nullptr))
        {
            value_str = to_json_str(nullptr);
        }
        else if (value.type() == typeid(bool))
        {
            value_str = to_json_str(std::any_cast<bool>(value));
        }
        else if (value.type() == typeid(double))
        {
            value_str = to_json_str(std::any_cast<double>(value));
        }
        else if (value.type() == typeid(const char*))
        {
            value_str = to_json_str(std::any_cast<const char*>(value));
        }
        else if (value.type() == typeid(std::string))
        {
            value_str = to_json_str(std::any_cast<std::string>(value));
        }
        else if (value.type() == typeid(dog_torch::serialize::json::array))
        {
            value_str = to_json_str(std::any_cast<dog_torch::serialize::json::array>(value), is_fmt, depth + 1);
        }
        else if (value.type() == typeid(dog_torch::serialize::json::object))
        {
            value_str = to_json_str(std::any_cast<std::unordered_map<std::string, std::any>>(value), is_fmt, depth + 1);
        }
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
std::string dog_torch::serialize::json::any::to_json_str(dog_torch::serialize::json::object object, bool is_fmt)
{
    return to_json_str(object, is_fmt, 0);
}

#define CHECK_END if (now == end) throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_END);
void dog_torch::serialize::json::any::skip_whitespace(std::string::const_iterator& now, std::string::const_iterator end)
{
	while (true)
	{
		CHECK_END;
		if (*now == ' ' || *now == '\t' || *now == '\n' || *now == '\r')
		{
			++now;
		}
		else
		{
			break;
		}
	}
}
std::nullptr_t dog_torch::serialize::json::any::to_null(std::string::const_iterator& now, std::string::const_iterator end)
{
	CHECK_END;
	if (now + 4 > end)
	{
		throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_END);
	}
    if (*now != 'n' || *(now + 1) != 'u' || *(now + 2) != 'l' || *(now + 3) != 'l')
    {
        throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    }
	return nullptr;
}
bool dog_torch::serialize::json::any::to_bool(std::string::const_iterator& now, std::string::const_iterator end)
{
    CHECK_END;
    if (*now == 't')
    {
        if (now + 4 > end)
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_END);
        }
        if (*now != 't' || *(now + 1) != 'r' || *(now + 2) != 'u' || *(now + 3) != 'e')
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        }
        now += 4;
        return true;
    }
    else if (*now == 'f')
    {
        if (now + 5 > end)
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_END);
        }
        if (*now != 'f' || *(now + 1) != 'a' || *(now + 2) != 'l' || *(now + 3) != 's' || *(now + 4) != 'e')
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        }
        now += 5;
        return false;
    }
    else
    {
        throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    }
}
double dog_torch::serialize::json::any::to_number(std::string::const_iterator& now, std::string::const_iterator end)
{
    CHECK_END;
    if ((*now < '0' || *now > '9') && (*now != '-'))
    {
        throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    }
    double num_sign = 1;
    uint64_t integer = 0;
    uint64_t decimal = 0;
    uint64_t decimal_num = 1;
    double exp_sign = 1;
    uint64_t exponent = 0;
    if (*now == '-')
    {
        num_sign = -1;
        now++;
    }
    if (*now == '0')
    {
        now++;
    }
    else
    {
        while (true)
        {
            CHECK_END;
            if (*now >= '0' && *now <= '9')
            {
                integer *= 10;
                integer += *now - '0';
            }
            else
            {
                break;
            }
            now++;
        }
    }
    if (*now == '.')
    {
        now++;
        while (true)
        {
            CHECK_END;
            if (*now >= '0' && *now <= '9')
            {
                decimal *= 10;
                decimal += *now - '0';
                decimal_num *= 10;
            }
            else
            {
                break;
            }
            now++;
        }
    }
    if (*now == 'e' || *now == 'E')
    {
        now++;
        if (*now == '-')
        {
            exp_sign = -1;
            now++;
        }
        else if (*now == '+')
        {
            exp_sign = 1;
            now++;
        }
        while (true)
        {
            CHECK_END;
            if (*now >= '0' && *now <= '9')
            {
                exponent *= 10;
                exponent += *now - '0';
            }
            else
            {
                break;
            }
        }
    }
    return exp_sign == 1 ?
        num_sign * (integer + (double)decimal / decimal_num) * pow(10, exponent) :
        num_sign * (integer + (double)decimal / decimal_num) / pow(10, exponent);
}
std::string dog_torch::serialize::json::any::to_string(std::string::const_iterator& now, std::string::const_iterator end)
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
dog_torch::serialize::json::array dog_torch::serialize::json::any::to_array(std::string::const_iterator& now, std::string::const_iterator end)
{
    CHECK_END;
    if (*now != '[')
    {
        throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    }
    std::vector<std::any> result;
    now++;
    while (true)
    {
        skip_whitespace(now, end);
        if (*now == ']')
        {
            break;
        }
        else if (*now == 'n')
        {
            result.emplace_back(to_null(now, end));
        }
        else if (*now == 't' || *now == 'f')
        {
            result.emplace_back(to_bool(now, end));
        }
        else if ((*now >= '0' && *now <= '9') || *now == '-')
        {
            result.emplace_back(to_number(now, end));
        }
        else if (*now == '"')
        {
            result.emplace_back(to_string(now, end));
        }
        else if (*now == '[')
        {
            result.emplace_back(to_array(now, end));
        }
        else if (*now == '{')
        {
            result.emplace_back(to_object(now, end));
        }
        else
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        }
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
    return result;
}
dog_torch::serialize::json::object dog_torch::serialize::json::any::to_object(std::string::const_iterator& now, std::string::const_iterator end)
{
    CHECK_END;
    if (*now != '{')
    {
        throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    }
    now++;
    std::string key = "";
    std::unordered_map<std::string, std::any> result;
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
        if (*now == 'n')
        {
            result[key] = (to_null(now, end));
        }
        else if (*now == 't' || *now == 'f')
        {
            result[key] = (to_bool(now, end));
        }
        else if ((*now >= '0' && *now <= '9') || *now == '-')
        {
            result[key] = (to_number(now, end));
        }
        else if (*now == '"')
        {
            result[key] = (to_string(now, end));
        }
        else if (*now == '[')
        {
            result[key] = (to_array(now, end));
        }
        else if (*now == '{')
        {
            result[key] = (to_object(now, end));
        }
        else
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        }
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
    return result;
}

#define CHECK_SEND if (input.eof()) throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_END);
void dog_torch::serialize::json::any::skip_whitespace(std::istream& input)
{
    while (true)
    {
        CHECK_SEND;
        if (input.peek() == ' ' || input.peek() == '\n' || input.peek() == '\t' || input.peek() == '\r')
        {
            input.get();
        }
        else
        {
            break;
        }
    }
}
std::nullptr_t dog_torch::serialize::json::any::to_null(std::istream& input)
{
    CHECK_SEND;
    if (input.peek() != 'n') throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    input.get();

    CHECK_SEND;
    if (input.peek() != 'u') throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    input.get();

    CHECK_SEND;
    if (input.peek() != 'l') throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    input.get();

    CHECK_SEND;
    if (input.peek() != 'l') throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    input.get();

    return nullptr;

}
bool dog_torch::serialize::json::any::to_bool(std::istream& input)
{
    CHECK_SEND;
    if (input.peek() == 't')
    {
        CHECK_SEND;
        if (input.peek() != 'r') throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        input.get();

        CHECK_SEND;
        if (input.peek() != 'u') throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        input.get();

        CHECK_SEND;
        if (input.peek() != 'e') throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        input.get();

        return true;
    }
    else if (input.peek() == 'f')
    {
        CHECK_SEND;
        if (input.peek() != 'a') throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        input.get();

        CHECK_SEND;
        if (input.peek() != 'l') throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        input.get();

        CHECK_SEND;
        if (input.peek() != 's') throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        input.get();

        CHECK_SEND;
        if (input.peek() != 'e') throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        input.get();

        return false;
    }
    else
    {
        throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    }
}
double dog_torch::serialize::json::any::to_number(std::istream& input)
{
    CHECK_SEND;
    if ((input.peek() < '0' || input.peek() > '9') && (input.peek() != '-'))
    {
        throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    }
    double num_sign = 1;
    uint64_t integer = 0;
    uint64_t decimal = 0;
    uint64_t decimal_num = 1;
    double exp_sign = 1;
    uint64_t exponent = 0;
    if (input.peek() == '-')
    {
        num_sign = -1;
        input.get();
    }
    if (input.peek() == '0')
    {
        input.get();
    }
    else
    {
        while (true)
        {
            CHECK_SEND;
            if (input.peek() >= '0' && input.peek() <= '9')
            {
                integer *= 10;
                integer += input.peek() - '0';
            }
            else
            {
                break;
            }
            input.get();
        }
    }
    if (input.peek() == '.')
    {
        input.get();
        while (true)
        {
            CHECK_SEND;
            if (input.peek() >= '0' && input.peek() <= '9')
            {
                decimal *= 10;
                decimal += input.peek() - '0';
                decimal_num *= 10;
            }
            else
            {
                break;
            }
            input.get();
        }
    }
    if (input.peek() == 'e' || input.peek() == 'E')
    {
        input.get();
        if (input.peek() == '-')
        {
            exp_sign = -1;
            input.get();
        }
        else if (input.peek() == '+')
        {
            exp_sign = 1;
            input.get();
        }
        while (true)
        {
            CHECK_SEND;
            if (input.peek() >= '0' && input.peek() <= '9')
            {
                exponent *= 10;
                exponent += input.peek() - '0';
            }
            else
            {
                break;
            }
        }
    }
    return exp_sign == 1 ?
        num_sign * (integer + (double)decimal / decimal_num) * pow(10, exponent) :
        num_sign * (integer + (double)decimal / decimal_num) / pow(10, exponent);
}
std::string dog_torch::serialize::json::any::to_string(std::istream& input)
{
    CHECK_SEND;
    if (input.get() != '"')
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
            if (input.get() == '"')
            {
                status = -1;
            }
            else if (input.get() == '\\')
            {
                status = 1;
            }
            else
            {
                result += input.get();
            }
            break;
        }
        case 1:
        {
            if (input.get() == 'u')
            {
                status = 2;
                continue;
            }
            else
            {
                switch (input.get())
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
                if (input.get() >= '0' && input.get() <= '9')
                {
                    unicode <<= 4;
                    unicode |= input.get() - '0';
                }
                else if (input.get() >= 'a' && input.get() <= 'f')
                {
                    unicode <<= 4;
                    unicode |= input.get() - 'a' + 10;
                }
                else if (input.get() >= 'A' && input.get() <= 'F')
                {
                    unicode <<= 4;
                    unicode |= input.get() - 'A' + 10;
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
dog_torch::serialize::json::array dog_torch::serialize::json::any::to_array(std::istream& input)
{
    CHECK_SEND;
    if (input.peek() != '[')
    {
        throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    }
    std::vector<std::any> result;
    input.get();
    while (true)
    {
        skip_whitespace(input);
        if (input.peek() == ']')
        {
            break;
        }
        else if (input.peek() == 'n')
        {
            result.emplace_back(to_null(input));
        }
        else if (input.peek() == 't' || input.peek() == 'f')
        {
            result.emplace_back(to_bool(input));
        }
        else if ((input.peek() >= '0' && input.peek() <= '9') || input.peek() == '-')
        {
            result.emplace_back(to_number(input));
        }
        else if (input.peek() == '"')
        {
            result.emplace_back(to_string(input));
        }
        else if (input.peek() == '[')
        {
            result.emplace_back(to_array(input));
        }
        else if (input.peek() == '{')
        {
            result.emplace_back(to_object(input));
        }
        else
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        }
        skip_whitespace(input);
        if (input.peek() == ']')
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
    return result;
}
dog_torch::serialize::json::object dog_torch::serialize::json::any::to_object(std::istream& input)
{
    CHECK_SEND;
    if (input.peek() != '{')
    {
        throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    }
    input.get();
    std::string key = "";
    std::unordered_map<std::string, std::any> result;
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
        if (input.peek() == 'n')
        {
            result[key] = (to_null(input));
        }
        else if (input.peek() == 't' || input.peek() == 'f')
        {
            result[key] = (to_bool(input));
        }
        else if ((input.peek() >= '0' && input.peek() <= '9') || input.peek() == '-')
        {
            result[key] = (to_number(input));
        }
        else if (input.peek() == '"')
        {
            result[key] = (to_string(input));
        }
        else if (input.peek() == '[')
        {
            result[key] = (to_array(input));
        }
        else if (input.peek() == '{')
        {
            result[key] = (to_object(input));
        }
        else
        {
            throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
        }
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
    return result;
}

std::string dog_torch::serialize::json::to_string(Type type)
{
    switch (type)
    {
    case Type::undefined:return "undefined";
    case Type::null: return "null";
    case Type::boolean:return "boolean";
    case Type::number: return "number";
    case Type::string:return "string";
    case Type::array:return "array";
    case Type::object:return "object";
    }
}

dog_torch::serialize::json::Value::Value()
{
    this->value_ = nullptr;
}
dog_torch::serialize::json::Value::Value(std::nullptr_t value)
{
    this->value_ = value;
}
dog_torch::serialize::json::Value::Value(bool value)
{
    this->value_ = value;
}
dog_torch::serialize::json::Value::Value(double value)
{
    this->value_ = value;
}
dog_torch::serialize::json::Value::Value(std::string value)
{
    this->value_ = value;
}
dog_torch::serialize::json::Value::Value(std::string::const_iterator& now, std::string::const_iterator end)
{
    if (*now == 'n')
    {
        *this = Value(dog_torch::serialize::json::any::to_null(now, end));
    }
    else if (*now == 't' || *now == 'f')
    {
        *this = Value(dog_torch::serialize::json::any::to_bool(now, end));
    }
    else if ((*now >= '0' && *now <= '9') || *now == '-')
    {
        *this = Value(dog_torch::serialize::json::any::to_number(now, end));
    }
    else if (*now == '"')
    {
        *this = Value(dog_torch::serialize::json::any::to_string(now, end));
    }
    else if (*now == '[')
    {
        *this = Value(Array(now, end));
    }
    else if (*now == '{')
    {
        *this = Value(Object(now, end));
    }
    else
    {
        throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    }
}
dog_torch::serialize::json::Value::Value(std::istream& input)
{
    if (input.peek() == 'n')
    {
        *this = Value(dog_torch::serialize::json::any::to_null(input));
    }
    else if (input.peek() == 't' || input.peek() == 'f')
    {
        *this = Value(dog_torch::serialize::json::any::to_bool(input));
    }
    else if ((input.peek() >= '0' && input.peek() <= '9') || input.peek() == '-')
    {
        *this = Value(dog_torch::serialize::json::any::to_number(input));
    }
    else if (input.peek() == '"')
    {
        *this = Value(dog_torch::serialize::json::any::to_string(input));
    }
    else if (input.peek() == '[')
    {
        *this = Value(Array(input));
    }
    else if (input.peek() == '{')
    {
        *this = Value(Object(input));
    }
    else
    {
        throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    }
}
dog_torch::serialize::json::Value::Value(std::vector<Value> value)
{
    this->value_ = value;
}
dog_torch::serialize::json::Value::Value(Array value)
{
    this->value_ = value.to_std_vector();
}
dog_torch::serialize::json::Value::Value(std::unordered_map<std::string, Value> value)
{
    this->value_ = value;
}
dog_torch::serialize::json::Value::Value(Object value)
{
    this->value_ = value.to_std_map();
}
dog_torch::serialize::json::Type dog_torch::serialize::json::Value::get_type() const
{
    struct Visitor
    {
        dog_torch::serialize::json::Type operator()(std::nullptr_t val) { return Type::null; }
        dog_torch::serialize::json::Type operator()(bool val) { return Type::boolean; }
        dog_torch::serialize::json::Type operator()(double val) { return Type::number; }
        dog_torch::serialize::json::Type operator()(std::string val) { return Type::string; }
        dog_torch::serialize::json::Type operator()(std::vector<Value> val) { return Type::array; }
        dog_torch::serialize::json::Type operator()(std::unordered_map<std::string, Value>) { return Type::object; }
    };

    return std::visit(Visitor(), this->value_);
}
#define VALUE_RETURN(jsonT,stdT) if (this->get_type() != Type::jsonT)\
throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);\
return std::get<stdT>(this->value_);
std::nullptr_t dog_torch::serialize::json::Value::to_null() const
{
    VALUE_RETURN(null, std::nullptr_t);
}
bool dog_torch::serialize::json::Value::to_bool() const
{
    VALUE_RETURN(boolean, bool);
}
double dog_torch::serialize::json::Value::to_number() const
{
    VALUE_RETURN(number, double);
}
std::string dog_torch::serialize::json::Value::to_string() const
{
    VALUE_RETURN(string, std::string);
}
std::vector<dog_torch::serialize::json::Value> dog_torch::serialize::json::Value::to_std_vector() const
{
    VALUE_RETURN(array, std::vector<dog_torch::serialize::json::Value>);
}
dog_torch::serialize::json::Array dog_torch::serialize::json::Value::to_array() const
{
    return dog_torch::serialize::json::Array(this->to_std_vector());
}
std::unordered_map<std::string, dog_torch::serialize::json::Value> dog_torch::serialize::json::Value::to_std_map() const
{
    if (this->get_type() != Type::object)
        throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    return std::get<std::unordered_map<std::string, dog_torch::serialize::json::Value>>(this->value_);
}
dog_torch::serialize::json::Object dog_torch::serialize::json::Value::to_object() const
{
    return dog_torch::serialize::json::Object(this->to_std_map());
}
std::string dog_torch::serialize::json::Value::to_json_str(bool is_fmt, uint64_t depth) const
{
    switch (this->get_type())
    {
    case Type::null: return "null";
    case Type::boolean: return dog_torch::serialize::json::any::to_json_str(this->to_bool());
    case Type::number: return dog_torch::serialize::json::any::to_json_str(this->to_number());
    case Type::string: return dog_torch::serialize::json::any::to_json_str(this->to_string());
    case Type::array: return this->to_array().to_json_str(is_fmt, depth);
    case Type::object: return this->to_object().to_json_str(is_fmt, depth);
    }
}

dog_torch::serialize::json::Object::Object()
{
}
dog_torch::serialize::json::Object::Object(object value)
{
    this->value_ = value;
}
dog_torch::serialize::json::Object::Object(std::string::const_iterator& now, std::string::const_iterator end)
{
    CHECK_END;
    if (*now != '{')
    {
        throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    }
    using namespace dog_torch::serialize::json::any;
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
dog_torch::serialize::json::Object::Object(std::string str)
{
    auto now = str.cbegin();
    *this = Object(now, str.cend());
}
dog_torch::serialize::json::Object::Object(std::istream& input)
{
    CHECK_SEND;
    if (input.peek() != '{')
    {
        throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    }
    input.get();
    using namespace dog_torch::serialize::json::any;
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
std::unordered_map<std::string, dog_torch::serialize::json::Value> dog_torch::serialize::json::Object::to_std_map()
{
    return this->value_;
}
std::string dog_torch::serialize::json::Object::to_json_str(bool is_fmt, uint64_t depth)
{
    return std::string();
}
size_t dog_torch::serialize::json::Object::size() const
{
    return this->value_.size();
}
size_t dog_torch::serialize::json::Object::max_size() const
{
    return this->value_.max_size();
}
bool dog_torch::serialize::json::Object::empty() const
{
    return this->value_.empty();
}
dog_torch::serialize::json::Object::it dog_torch::serialize::json::Object::begin()
{
    return this->value_.begin();
}
dog_torch::serialize::json::Object::it dog_torch::serialize::json::Object::end()
{
    return this->value_.end();
}
dog_torch::serialize::json::Object::cit dog_torch::serialize::json::Object::cbegin() const
{
    return this->value_.cbegin();
}
dog_torch::serialize::json::Object::cit dog_torch::serialize::json::Object::cend() const
{
    return cit();
}
dog_torch::serialize::json::Value& dog_torch::serialize::json::Object::at(const std::string& key)
{
    return this->value_.at(key);
}
const dog_torch::serialize::json::Value& dog_torch::serialize::json::Object::at(const std::string& key) const
{
    return this->value_.at(key);
}
dog_torch::serialize::json::Value& dog_torch::serialize::json::Object::operator[](const std::string& key)
{
    return this->value_[key];
}
const dog_torch::serialize::json::Value& dog_torch::serialize::json::Object::operator[](const std::string& key) const
{
    return this->value_.at(key);
}
std::unordered_map<std::string,dog_torch::serialize::json::Value>::size_type dog_torch::serialize::json::Object::count(const std::string& key) const
{
    return this->value_.count(key);
}
dog_torch::serialize::json::Object::it dog_torch::serialize::json::Object::find(const std::string& key)
{
    return this->value_.find(key);
}
dog_torch::serialize::json::Object::cit dog_torch::serialize::json::Object::find(const std::string& key) const
{
    return this->value_.find(key);
}
bool dog_torch::serialize::json::Object::contains(const std::string& key) const
{
    return this->value_.contains(key);
}
std::pair<dog_torch::serialize::json::Object::it, dog_torch::serialize::json::Object::it> dog_torch::serialize::json::Object::equal_range(const std::string& key)
{
    return this->value_.equal_range(key);
}
std::pair<dog_torch::serialize::json::Object::cit, dog_torch::serialize::json::Object::cit> dog_torch::serialize::json::Object::equal_range(const std::string& key) const
{
    return std::pair<cit, cit>();
}
void dog_torch::serialize::json::Object::clear()
{
    this->value_.clear();
}
std::pair<dog_torch::serialize::json::Object::it, bool> dog_torch::serialize::json::Object::insert(const std::pair<std::string, Value>& value)
{
    return this->value_.insert(value);
}
std::pair<dog_torch::serialize::json::Object::it, bool> dog_torch::serialize::json::Object::insert(std::pair<std::string, Value>&& value)
{
    return this->value_.insert(std::move(value));
}
dog_torch::serialize::json::Object::it dog_torch::serialize::json::Object::erase(cit pos)
{
    return this->value_.erase(pos);
}
dog_torch::serialize::json::Object::it dog_torch::serialize::json::Object::erase(cit first, cit last)
{
    return this->value_.erase(first, last);
}

dog_torch::serialize::json::Array::Array()
{
}
dog_torch::serialize::json::Array::Array(array value)
{
    this->value_ = value;
}
dog_torch::serialize::json::Array::Array(std::string::const_iterator& now, std::string::const_iterator end)
{
    CHECK_END;
    if (*now != '[')
    {
        throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    }
    using namespace dog_torch::serialize::json::any;
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
dog_torch::serialize::json::Array::Array(std::string str)
{
    auto now = str.cbegin();
    *this = Array(now, str.cend());
}
dog_torch::serialize::json::Array::Array(std::istream& input)
{
    CHECK_SEND;
    if (input.peek() != '[')
    {
        throw DOG_EXCEPTION(DOG_ERROR_UNEXCEPT_CHAR);
    }
    using namespace dog_torch::serialize::json::any;
    auto& result = this->value_;
    input.get();
    while (true)
    {
        skip_whitespace(input);
        result.emplace_back(Value(input));
        skip_whitespace(input);
        if (input.peek() == ']')
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
std::vector<dog_torch::serialize::json::Value> dog_torch::serialize::json::Array::to_std_vector()
{
    return this->value_;
}
std::string dog_torch::serialize::json::Array::to_json_str(bool is_fmt, uint64_t depth)
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
dog_torch::serialize::json::Value& dog_torch::serialize::json::Array::at(size_t pos)
{
    return this->value_.at(pos);
}
const dog_torch::serialize::json::Value& dog_torch::serialize::json::Array::at(size_t pos) const
{
    return this->value_.at(pos);
}
dog_torch::serialize::json::Value& dog_torch::serialize::json::Array::operator[](size_t pos)
{
    return this->value_[pos];
}
const dog_torch::serialize::json::Value& dog_torch::serialize::json::Array::operator[](size_t pos) const
{
    return this->value_.at(pos);
}
dog_torch::serialize::json::Value& dog_torch::serialize::json::Array::front()
{
    return this->value_.front();
}
const dog_torch::serialize::json::Value& dog_torch::serialize::json::Array::front() const
{
    return this->value_.front();
}
dog_torch::serialize::json::Value& dog_torch::serialize::json::Array::back()
{
    return this->value_.back();
}
const dog_torch::serialize::json::Value& dog_torch::serialize::json::Array::back() const
{
    return this->value_.back();
}
dog_torch::serialize::json::Value* dog_torch::serialize::json::Array::data()
{
    return this->value_.data();
}
const dog_torch::serialize::json::Value* dog_torch::serialize::json::Array::data() const
{
    return this->value_.data();
}
size_t dog_torch::serialize::json::Array::size() const
{
    return this->value_.size();
}
size_t dog_torch::serialize::json::Array::max_size() const
{
    return this->value_.max_size();
}
bool dog_torch::serialize::json::Array::empty() const
{
    return this->value_.empty();
}
void dog_torch::serialize::json::Array::reserve(size_t new_cap)
{
    this->value_.reserve(new_cap);
}
std::vector<dog_torch::serialize::json::Value>::size_type dog_torch::serialize::json::Array::capacity() const
{
    return this->value_.capacity();
}
void dog_torch::serialize::json::Array::shrink_to_fit()
{
    this->value_.shrink_to_fit();
}
dog_torch::serialize::json::Array::it dog_torch::serialize::json::Array::begin()
{
    return this->value_.begin();
}
dog_torch::serialize::json::Array::cit dog_torch::serialize::json::Array::cbegin() const
{
    return this->value_.cbegin();
}
dog_torch::serialize::json::Array::it dog_torch::serialize::json::Array::end()
{
    return this->value_.end();
}
dog_torch::serialize::json::Array::cit dog_torch::serialize::json::Array::cend() const
{
    return this->value_.cend();
}
dog_torch::serialize::json::Array::rit dog_torch::serialize::json::Array::rbegin()
{
    return this->value_.rbegin();
}
dog_torch::serialize::json::Array::crit dog_torch::serialize::json::Array::crbegin() const
{
    return this->value_.crbegin();
}
dog_torch::serialize::json::Array::rit dog_torch::serialize::json::Array::rend()
{
    return this->value_.rend();
}
dog_torch::serialize::json::Array::crit dog_torch::serialize::json::Array::crend() const
{
    return this->value_.crend();
}
void dog_torch::serialize::json::Array::clear()
{
    this->value_.clear();
}
dog_torch::serialize::json::Array::it dog_torch::serialize::json::Array::insert(cit pos, const Value& value)
{
    return this->value_.insert(pos, value);
}
dog_torch::serialize::json::Array::it dog_torch::serialize::json::Array::insert(cit pos, Value&& value)
{
    return this->value_.insert(pos, value);
}
void dog_torch::serialize::json::Array::push_back(const Value& value)
{
    this->value_.push_back(value);
}
void dog_torch::serialize::json::Array::push_back(Value&& value)
{
    this->value_.push_back(value);
}
void dog_torch::serialize::json::Array::emplace(cit pos, Value&& value)
{
    this->value_.emplace(pos, value);
}
void dog_torch::serialize::json::Array::emplace_back(const Value& value)
{
    this->value_.emplace_back(value);
}
void dog_torch::serialize::json::Array::emplace_back(Value&& value)
{
    this->value_.emplace_back(value);
}
void dog_torch::serialize::json::Array::pop_back()
{
    this->value_.pop_back();
}
dog_torch::serialize::json::Array::it dog_torch::serialize::json::Array::erase(cit pos)
{
    return this->value_.erase(pos);
}
dog_torch::serialize::json::Array::it dog_torch::serialize::json::Array::erase(cit first, cit last)
{
    return this->value_.erase(first, last);
}
void dog_torch::serialize::json::Array::resize(size_t count)
{
    this->value_.resize(count);
}
void dog_torch::serialize::json::Array::resize(size_t count, const Value& value)
{
    this->value_.resize(count, value);
}

#undef CHECK_END
#undef CHECK_SEND
#undef VALUE_RETURN

#undef DOG_ERROR_UNEXCEPT_END
#undef DOG_ERROR_UNEXCEPT_CHAR