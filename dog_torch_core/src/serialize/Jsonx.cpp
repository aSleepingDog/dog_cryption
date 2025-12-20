#include "serialize/Jsonx.h"

std::string dog_torch::serialize::jsonx::any::to_json_str(std::nullptr_t value)
{
    return "null";
}
std::string dog_torch::serialize::jsonx::any::to_json_str(bool value)
{
    return value ? "true" : "false";
}
std::string dog_torch::serialize::jsonx::any::to_json_str(int64_t number)
{
    return 'i' + std::to_string(number);
}
std::string dog_torch::serialize::jsonx::any::to_json_str(uint64_t number)
{
    return "ui" + std::to_string(number);
}
std::string dog_torch::serialize::jsonx::any::to_json_str(double number)
{
    return std::to_string(number);
}
std::string dog_torch::serialize::jsonx::any::to_json_str(const char* param)
{
    return to_json_str(std::string(param));
}
std::string dog_torch::serialize::jsonx::any::to_json_str(std::string param)
{
    std::string res = "\"";
    for (auto c : param)
    {
        if (c == '"' || c == '\\' || c == '/' || c == '\b' || c == '\f' || c == '\n' || c == '\r' || c == '\t')
        {
            res += '\\';
            switch (c)
            {
            case '\b':
            {
                res += 'b';
                break;
            }
            case '\f':
            {
                res += 'f';
                break;
            }
            case '\n':
            {
                res += 'n';
                break;
            }
            case '\r':
            {
                res += 'r';
                break;
            }
            case '\t':
            {
                res += 't';
                break;
            }
            default:
            {
                res += c;
            }
            };
        }
        else
        {
            res += c;
        }
    }
    return res + "\"";
}
std::string dog_torch::serialize::jsonx::any::to_json_str(dog_torch::serialize::jsonx::array list, bool is_fmt, uint64_t depth)
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
        else if (item.type() == typeid(dog_torch::serialize::jsonx::array))
        {
            value_str = to_json_str(std::any_cast<dog_torch::serialize::jsonx::array>(item), is_fmt, depth + 1);
        }
        else if (item.type() == typeid(dog_torch::serialize::jsonx::object))
        {
            value_str = to_json_str(std::any_cast<dog_torch::serialize::jsonx::object>(item), is_fmt, depth + 1);
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
std::string dog_torch::serialize::jsonx::any::to_json_str(dog_torch::serialize::jsonx::array list, bool is_fmt)
{
    return to_json_str(list, is_fmt, 0);
}
std::string dog_torch::serialize::jsonx::any::to_json_str(dog_torch::serialize::jsonx::object object, bool is_fmt, uint64_t depth)
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
        else if (value.type() == typeid(dog_torch::serialize::jsonx::array))
        {
            value_str = to_json_str(std::any_cast<dog_torch::serialize::jsonx::array>(value), is_fmt, depth + 1);
        }
        else if (value.type() == typeid(dog_torch::serialize::jsonx::object))
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
std::string dog_torch::serialize::jsonx::any::to_json_str(dog_torch::serialize::jsonx::object object, bool is_fmt)
{
    return to_json_str(object, is_fmt, 0);
}

#define CHECK_END if (now == end) throw DOG_EXCEPTION("Error:unexpected end of jsonx string\n错误：jsonx字符串意外结束");
void dog_torch::serialize::jsonx::any::skip_whitespace(std::string::const_iterator& now, std::string::const_iterator end)
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
            case '/': status = 1;
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
                throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
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
std::nullptr_t dog_torch::serialize::jsonx::any::to_null(std::string::const_iterator& now, std::string::const_iterator end)
{
    CHECK_END;
    if (now + 4 > end)
    {
        throw DOG_EXCEPTION("Json parse error: unexpected end");
    }
    if (*now != 'n' || *(now + 1) != 'u' || *(now + 2) != 'l' || *(now + 3) != 'l')
    {
        throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
    }
    return nullptr;
}
bool dog_torch::serialize::jsonx::any::to_bool(std::string::const_iterator& now, std::string::const_iterator end)
{
    CHECK_END;
    if (*now == 't')
    {
        if (now + 4 > end)
        {
            throw DOG_EXCEPTION("Json parse error: unexpected end");
        }
        if (*now != 't' || *(now + 1) != 'r' || *(now + 2) != 'u' || *(now + 3) != 'e')
        {
            throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
        }
        now += 4;
        return true;
    }
    else if (*now == 'f')
    {
        if (now + 5 > end)
        {
            throw DOG_EXCEPTION("Json parse error: unexpected end");
        }
        if (*now != 'f' || *(now + 1) != 'a' || *(now + 2) != 'l' || *(now + 3) != 's' || *(now + 4) != 'e')
        {
            throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
        }
        now += 5;
        return false;
    }
    else
    {
        throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
    }
}
int64_t dog_torch::serialize::jsonx::any::to_int64(std::string::const_iterator& now, std::string::const_iterator end)
{
    CHECK_END;
    if (*now != 'i')
    {
        throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
    }
    now++;
    CHECK_END;
    int64_t sign = 1;
    int64_t num = 0;
    if (*now == '-')
    {
        sign = -1;
        now++;
        CHECK_END;
    }
    while (true)
    {
        if (*now >= '0' && *now <= '9')
        {
            num *= 10;
            num += *now - '0';
        }
        else
        {
            break;
        }
        now++;
    }
    return sign * num;
}
uint64_t dog_torch::serialize::jsonx::any::to_uint64(std::string::const_iterator& now, std::string::const_iterator end)
{
    CHECK_END;
    if (*now != 'u')
    {
        throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
    }
    now++;
    CHECK_END;
    if (*now != 'i')
    {
        throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
    }
    now++;
    CHECK_END;
    uint64_t num = 0;
    while (true)
    {
        if (*now >= '0' && *now <= '9')
        {
            num *= 10;
            num += *now - '0';
        }
        else
        {
            break;
        }
        now++;
    }
    return num;
}
double dog_torch::serialize::jsonx::any::to_float64(std::string::const_iterator& now, std::string::const_iterator end)
{
    CHECK_END;
    if ((*now < '0' || *now > '9') && (*now != '-'))
    {
        throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
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
std::string dog_torch::serialize::jsonx::any::to_string(std::string::const_iterator& now, std::string::const_iterator end)
{
    CHECK_END;
    if (*now != '"')
    {
        throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
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
                    throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
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
                    throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
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
dog_torch::serialize::jsonx::array dog_torch::serialize::jsonx::any::to_array(std::string::const_iterator& now, std::string::const_iterator end)
{
    CHECK_END;
    if (*now != '[')
    {
        throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
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
            result.emplace_back(to_float64(now, end));
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
            throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
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
            throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
        }
    }
    now++;
    return result;
}
dog_torch::serialize::jsonx::object dog_torch::serialize::jsonx::any::to_object(std::string::const_iterator& now, std::string::const_iterator end)
{
    CHECK_END;
    if (*now != '{')
    {
        throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
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
            throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
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
            result[key] = (to_float64(now, end));
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
            throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
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
            throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
        }

    }
    now++;
    return result;
}

#define CHECK_SEND if (input.eof()) throw DOG_EXCEPTION("Error: unexpected end of jsonx file\n错误：jsonx文件意外结束");
void dog_torch::serialize::jsonx::any::skip_whitespace(std::istream& input)
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
std::nullptr_t dog_torch::serialize::jsonx::any::to_null(std::istream& input)
{
    CHECK_SEND;
    if (input.peek() != 'n') throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
    input.get();

    CHECK_SEND;
    if (input.peek() != 'u') throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
    input.get();

    CHECK_SEND;
    if (input.peek() != 'l') throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
    input.get();

    CHECK_SEND;
    if (input.peek() != 'l') throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
    input.get();

    return nullptr;

}
bool dog_torch::serialize::jsonx::any::to_bool(std::istream& input)
{
    CHECK_SEND;
    if (input.peek() == 't')
    {
        CHECK_SEND;
        if (input.peek() != 'r') throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
        input.get();

        CHECK_SEND;
        if (input.peek() != 'u') throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
        input.get();

        CHECK_SEND;
        if (input.peek() != 'e') throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
        input.get();

        return true;
    }
    else if (input.peek() == 'f')
    {
        CHECK_SEND;
        if (input.peek() != 'a') throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
        input.get();

        CHECK_SEND;
        if (input.peek() != 'l') throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
        input.get();

        CHECK_SEND;
        if (input.peek() != 's') throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
        input.get();

        CHECK_SEND;
        if (input.peek() != 'e') throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
        input.get();

        return false;
    }
    else
    {
        throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
    }
}
double dog_torch::serialize::jsonx::any::to_number(std::istream& input)
{
    CHECK_SEND;
    if ((input.peek() < '0' || input.peek() > '9') && (input.peek() != '-'))
    {
        throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
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
std::string dog_torch::serialize::jsonx::any::to_string(std::istream& input)
{
    CHECK_SEND;
    if (input.get() != '"')
    {
        throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
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
                    throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
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
                    throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
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
dog_torch::serialize::jsonx::array dog_torch::serialize::jsonx::any::to_array(std::istream& input)
{
    CHECK_SEND;
    if (input.peek() != '[')
    {
        throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
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
            throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
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
            throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
        }
    }
    input.get();
    return result;
}
dog_torch::serialize::jsonx::object dog_torch::serialize::jsonx::any::to_object(std::istream& input)
{
    CHECK_SEND;
    if (input.peek() != '{')
    {
        throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
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
            throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
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
            throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
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
            throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
        }

    }
    input.get();
    return result;
}

std::string dog_torch::serialize::jsonx::to_string(Type type)
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

dog_torch::serialize::jsonx::Value::Value()
{
    this->value_ = nullptr;
}
dog_torch::serialize::jsonx::Value::Value(std::nullptr_t value)
{
    this->value_ = value;
}
dog_torch::serialize::jsonx::Value::Value(bool value)
{
    this->value_ = value;
}
dog_torch::serialize::jsonx::Value::Value(int64_t value)
{
    this->value_ = value;
}
dog_torch::serialize::jsonx::Value::Value(uint64_t value)
{
    this->value_ = value;
}
dog_torch::serialize::jsonx::Value::Value(double value)
{
    this->value_ = value;
}
dog_torch::serialize::jsonx::Value::Value(std::string value)
{
    this->value_ = value;
}
dog_torch::serialize::jsonx::Value::Value(std::string::const_iterator& now, std::string::const_iterator end)
{
    if (*now == 'n')
    {
        *this = Value(dog_torch::serialize::jsonx::any::to_null(now, end));
    }
    else if (*now == 't' || *now == 'f')
    {
        *this = Value(dog_torch::serialize::jsonx::any::to_bool(now, end));
    }
    else if (*now == 'i')
    {
        *this = Value(dog_torch::serialize::jsonx::any::to_int64(now, end));
    }
    else if (*now == 'u')
    {
        *this = Value(dog_torch::serialize::jsonx::any::to_uint64(now, end));
    }
    else if ((*now >= '0' && *now <= '9') || *now == '-')
    {
        *this = Value(dog_torch::serialize::jsonx::any::to_float64(now, end));
    }
    else if (*now == '"')
    {
        *this = Value(dog_torch::serialize::jsonx::any::to_string(now, end));
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
        throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
    }
}
dog_torch::serialize::jsonx::Value::Value(std::istream& input)
{
    if (input.peek() == 'n')
    {
        *this = Value(dog_torch::serialize::jsonx::any::to_null(input));
    }
    else if (input.peek() == 't' || input.peek() == 'f')
    {
        *this = Value(dog_torch::serialize::jsonx::any::to_bool(input));
    }
    else if ((input.peek() >= '0' && input.peek() <= '9') || input.peek() == '-')
    {
        *this = Value(dog_torch::serialize::jsonx::any::to_number(input));
    }
    else if (input.peek() == '"')
    {
        *this = Value(dog_torch::serialize::jsonx::any::to_string(input));
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
        throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
    }
}
dog_torch::serialize::jsonx::Value::Value(std::vector<Value> value)
{
    this->value_ = value;
}
dog_torch::serialize::jsonx::Value::Value(Array value)
{
    this->value_ = value.to_std_vector();
}
dog_torch::serialize::jsonx::Value::Value(std::unordered_map<std::string, Value> value)
{
    this->value_ = value;
}
dog_torch::serialize::jsonx::Value::Value(Object value)
{
    this->value_ = value.to_std_map();
}
dog_torch::serialize::jsonx::Type dog_torch::serialize::jsonx::Value::get_type() const
{
    struct Visitor
    {
        dog_torch::serialize::jsonx::Type operator()(std::nullptr_t val) { return Type::null; }
        dog_torch::serialize::jsonx::Type operator()(bool val) { return Type::boolean; }
        dog_torch::serialize::jsonx::Type operator()(int64_t val) { return Type::int64; }
        dog_torch::serialize::jsonx::Type operator()(uint64_t val) { return Type::uint64; }
        dog_torch::serialize::jsonx::Type operator()(double val) { return Type::float64; }
        dog_torch::serialize::jsonx::Type operator()(std::string val) { return Type::string; }
        dog_torch::serialize::jsonx::Type operator()(std::vector<Value> val) { return Type::array; }
        dog_torch::serialize::jsonx::Type operator()(std::unordered_map<std::string, Value>) { return Type::object; }
    };

    return std::visit(Visitor(), this->value_);
}
#define VALUE_RETURN(jsonT,stdT) if (this->get_type() != Type::jsonT)\
throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");\
return std::get<stdT>(this->value_);
std::nullptr_t dog_torch::serialize::jsonx::Value::to_null() const
{
    VALUE_RETURN(null, std::nullptr_t);
}
bool dog_torch::serialize::jsonx::Value::to_bool() const
{
    VALUE_RETURN(boolean, bool);
}
int64_t dog_torch::serialize::jsonx::Value::to_int64() const
{
    VALUE_RETURN(int64, int64_t);
}
uint64_t dog_torch::serialize::jsonx::Value::to_uint64() const
{
    VALUE_RETURN(uint64, uint64_t);
}
double dog_torch::serialize::jsonx::Value::to_float64() const
{
    VALUE_RETURN(float64, double);
}
std::string dog_torch::serialize::jsonx::Value::to_string() const
{
    VALUE_RETURN(string, std::string);
}
std::vector<dog_torch::serialize::jsonx::Value> dog_torch::serialize::jsonx::Value::to_std_vector() const
{
    VALUE_RETURN(array, std::vector<dog_torch::serialize::jsonx::Value>);
}
dog_torch::serialize::jsonx::Array dog_torch::serialize::jsonx::Value::to_array() const
{
    return dog_torch::serialize::jsonx::Array(this->to_std_vector());
}
std::unordered_map<std::string, dog_torch::serialize::jsonx::Value> dog_torch::serialize::jsonx::Value::to_std_map() const
{
    if (this->get_type() != Type::object)
        throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
    return std::get<std::unordered_map<std::string, dog_torch::serialize::jsonx::Value>>(this->value_);
}
dog_torch::serialize::jsonx::Object dog_torch::serialize::jsonx::Value::to_object() const
{
    return dog_torch::serialize::jsonx::Object(this->to_std_map());
}
std::string dog_torch::serialize::jsonx::Value::to_json_str(bool is_fmt, uint64_t depth) const
{
    switch (this->get_type())
    {
    case Type::null: return "null";
    case Type::boolean: return dog_torch::serialize::jsonx::any::to_json_str(this->to_bool());
    case Type::int64: return dog_torch::serialize::jsonx::any::to_json_str(this->to_int64());
    case Type::uint64: return dog_torch::serialize::jsonx::any::to_json_str(this->to_uint64());
    case Type::float64: return dog_torch::serialize::jsonx::any::to_json_str(this->to_float64());
    case Type::string: return dog_torch::serialize::jsonx::any::to_json_str(this->to_string());
    case Type::array: return this->to_array().to_json_str(is_fmt, depth);
    case Type::object: return this->to_object().to_json_str(is_fmt, depth);
    }
}

dog_torch::serialize::jsonx::Object::Object()
{
}
dog_torch::serialize::jsonx::Object::Object(std::unordered_map<std::string, Value> value)
{
    this->value_ = value;
}
dog_torch::serialize::jsonx::Object::Object(std::string::const_iterator& now, std::string::const_iterator end)
{
    CHECK_END;
    if (*now != '{')
    {
        throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
    }
    using namespace dog_torch::serialize::jsonx::any;
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
            throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
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
            throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
        }

    }
    now++;
}
dog_torch::serialize::jsonx::Object::Object(std::istream& input)
{
    CHECK_SEND;
    if (input.peek() != '{')
    {
        throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
    }
    input.get();
    using namespace dog_torch::serialize::jsonx::any;
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
            throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
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
            throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
        }

    }
    input.get();
}
std::unordered_map<std::string, dog_torch::serialize::jsonx::Value> dog_torch::serialize::jsonx::Object::to_std_map()
{
    return this->value_;
}
std::string dog_torch::serialize::jsonx::Object::to_json_str(bool is_fmt, uint64_t depth)
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
size_t dog_torch::serialize::jsonx::Object::size() const
{
    return this->value_.size();
}
size_t dog_torch::serialize::jsonx::Object::max_size() const
{
    return this->value_.max_size();
}
bool dog_torch::serialize::jsonx::Object::empty() const
{
    return this->value_.empty();
}
dog_torch::serialize::jsonx::Object::it dog_torch::serialize::jsonx::Object::begin()
{
    return this->value_.begin();
}
dog_torch::serialize::jsonx::Object::it dog_torch::serialize::jsonx::Object::end()
{
    return this->value_.end();
}
dog_torch::serialize::jsonx::Object::cit dog_torch::serialize::jsonx::Object::cbegin() const
{
    return this->value_.cbegin();
}
dog_torch::serialize::jsonx::Object::cit dog_torch::serialize::jsonx::Object::cend() const
{
    return this->value_.cend();
}
dog_torch::serialize::jsonx::Value& dog_torch::serialize::jsonx::Object::at(const std::string& key)
{
    return this->value_.at(key);
}
const dog_torch::serialize::jsonx::Value& dog_torch::serialize::jsonx::Object::at(const std::string& key) const
{
    return this->value_.at(key);
}
dog_torch::serialize::jsonx::Value& dog_torch::serialize::jsonx::Object::operator[](const std::string& key)
{
    return this->value_[key];
}
const dog_torch::serialize::jsonx::Value& dog_torch::serialize::jsonx::Object::operator[](const std::string& key) const
{
    return this->value_.at(key);
}
std::unordered_map<std::string, dog_torch::serialize::jsonx::Value>::size_type dog_torch::serialize::jsonx::Object::count(const std::string& key) const
{
    return this->value_.count(key);
}
dog_torch::serialize::jsonx::Object::it dog_torch::serialize::jsonx::Object::find(const std::string& key)
{
    return this->value_.find(key);
}
dog_torch::serialize::jsonx::Object::cit dog_torch::serialize::jsonx::Object::find(const std::string& key) const
{
    return this->value_.find(key);
}
bool dog_torch::serialize::jsonx::Object::contains(const std::string& key) const
{
    return this->value_.contains(key);
}
std::pair<dog_torch::serialize::jsonx::Object::it, dog_torch::serialize::jsonx::Object::it> dog_torch::serialize::jsonx::Object::equal_range(const std::string& key)
{
    return this->value_.equal_range(key);
}
std::pair<dog_torch::serialize::jsonx::Object::cit, dog_torch::serialize::jsonx::Object::cit> dog_torch::serialize::jsonx::Object::equal_range(const std::string& key) const
{
    return std::pair<cit, cit>();
}
void dog_torch::serialize::jsonx::Object::clear()
{
    this->value_.clear();
}
std::pair<dog_torch::serialize::jsonx::Object::it, bool> dog_torch::serialize::jsonx::Object::insert(const std::pair<std::string, Value>& value)
{
    return this->value_.insert(value);
}
std::pair<dog_torch::serialize::jsonx::Object::it, bool> dog_torch::serialize::jsonx::Object::insert(std::pair<std::string, Value>&& value)
{
    return this->value_.insert(std::move(value));
}
dog_torch::serialize::jsonx::Object::it dog_torch::serialize::jsonx::Object::erase(cit pos)
{
    return this->value_.erase(pos);
}
dog_torch::serialize::jsonx::Object::it dog_torch::serialize::jsonx::Object::erase(cit first, cit last)
{
    return this->value_.erase(first, last);
}

dog_torch::serialize::jsonx::Array::Array()
{
}
dog_torch::serialize::jsonx::Array::Array(std::vector<Value> value)
{
    this->value_ = value;
}
dog_torch::serialize::jsonx::Array::Array(std::string::const_iterator& now, std::string::const_iterator end)
{
    CHECK_END;
    if (*now != '[')
    {
        throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
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
            throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
        }
    }
    now++;
}
dog_torch::serialize::jsonx::Array::Array(std::istream& input)
{
    CHECK_SEND;
    if (input.peek() != '[')
    {
        throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
    }
    using namespace dog_torch::serialize::jsonx::any;
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
            throw DOG_EXCEPTION("Error: unexpected character of jsonx string\n错误：jsonx字符串中出现了意外的字符");
        }
    }
    input.get();
}
std::vector<dog_torch::serialize::jsonx::Value> dog_torch::serialize::jsonx::Array::to_std_vector()
{
    return this->value_;
}
std::string dog_torch::serialize::jsonx::Array::to_json_str(bool is_fmt, uint64_t depth)
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
dog_torch::serialize::jsonx::Value& dog_torch::serialize::jsonx::Array::at(size_t pos)
{
    return this->value_.at(pos);
}
const dog_torch::serialize::jsonx::Value& dog_torch::serialize::jsonx::Array::at(size_t pos) const
{
    return this->value_.at(pos);
}
dog_torch::serialize::jsonx::Value& dog_torch::serialize::jsonx::Array::operator[](size_t pos)
{
    return this->value_[pos];
}
const dog_torch::serialize::jsonx::Value& dog_torch::serialize::jsonx::Array::operator[](size_t pos) const
{
    return this->value_.at(pos);
}
dog_torch::serialize::jsonx::Value& dog_torch::serialize::jsonx::Array::front()
{
    return this->value_.front();
}
const dog_torch::serialize::jsonx::Value& dog_torch::serialize::jsonx::Array::front() const
{
    return this->value_.front();
}
dog_torch::serialize::jsonx::Value& dog_torch::serialize::jsonx::Array::back()
{
    return this->value_.back();
}
const dog_torch::serialize::jsonx::Value& dog_torch::serialize::jsonx::Array::back() const
{
    return this->value_.back();
}
dog_torch::serialize::jsonx::Value* dog_torch::serialize::jsonx::Array::data()
{
    return this->value_.data();
}
const dog_torch::serialize::jsonx::Value* dog_torch::serialize::jsonx::Array::data() const
{
    return this->value_.data();
}
size_t dog_torch::serialize::jsonx::Array::size() const
{
    return this->value_.size();
}
size_t dog_torch::serialize::jsonx::Array::max_size() const
{
    return this->value_.max_size();
}
bool dog_torch::serialize::jsonx::Array::empty() const
{
    return this->value_.empty();
}
void dog_torch::serialize::jsonx::Array::reserve(size_t new_cap)
{
    this->value_.reserve(new_cap);
}
std::vector<dog_torch::serialize::jsonx::Value>::size_type dog_torch::serialize::jsonx::Array::capacity() const
{
    return this->value_.capacity();
}
void dog_torch::serialize::jsonx::Array::shrink_to_fit()
{
    this->value_.shrink_to_fit();
}
dog_torch::serialize::jsonx::Array::it dog_torch::serialize::jsonx::Array::begin()
{
    return this->value_.begin();
}
dog_torch::serialize::jsonx::Array::cit dog_torch::serialize::jsonx::Array::cbegin() const
{
    return this->value_.cbegin();
}
dog_torch::serialize::jsonx::Array::it dog_torch::serialize::jsonx::Array::end()
{
    return this->value_.end();
}
dog_torch::serialize::jsonx::Array::cit dog_torch::serialize::jsonx::Array::cend() const
{
    return this->value_.cend();
}
dog_torch::serialize::jsonx::Array::rit dog_torch::serialize::jsonx::Array::rbegin()
{
    return this->value_.rbegin();
}
dog_torch::serialize::jsonx::Array::crit dog_torch::serialize::jsonx::Array::crbegin() const
{
    return this->value_.crbegin();
}
dog_torch::serialize::jsonx::Array::rit dog_torch::serialize::jsonx::Array::rend()
{
    return this->value_.rend();
}
dog_torch::serialize::jsonx::Array::crit dog_torch::serialize::jsonx::Array::crend() const
{
    return this->value_.crend();
}
void dog_torch::serialize::jsonx::Array::clear()
{
    this->value_.clear();
}
dog_torch::serialize::jsonx::Array::it dog_torch::serialize::jsonx::Array::insert(cit pos, const Value& value)
{
    return this->value_.insert(pos, value);
}
dog_torch::serialize::jsonx::Array::it dog_torch::serialize::jsonx::Array::insert(cit pos, Value&& value)
{
    return this->value_.insert(pos, value);
}
void dog_torch::serialize::jsonx::Array::push_back(const Value& value)
{
    this->value_.push_back(value);
}
void dog_torch::serialize::jsonx::Array::push_back(Value&& value)
{
    this->value_.push_back(value);
}
void dog_torch::serialize::jsonx::Array::emplace(cit pos, Value&& value)
{
    this->value_.emplace(pos, value);
}
void dog_torch::serialize::jsonx::Array::emplace_back(const Value& value)
{
    this->value_.emplace_back(value);
}
void dog_torch::serialize::jsonx::Array::emplace_back(Value&& value)
{
    this->value_.emplace_back(value);
}
void dog_torch::serialize::jsonx::Array::pop_back()
{
    this->value_.pop_back();
}
dog_torch::serialize::jsonx::Array::it dog_torch::serialize::jsonx::Array::erase(cit pos)
{
    return this->value_.erase(pos);
}
dog_torch::serialize::jsonx::Array::it dog_torch::serialize::jsonx::Array::erase(cit first, cit last)
{
    return this->value_.erase(first, last);
}
void dog_torch::serialize::jsonx::Array::resize(size_t count)
{
    this->value_.resize(count);
}
void dog_torch::serialize::jsonx::Array::resize(size_t count, const Value& value)
{
    this->value_.resize(count, value);
}
#undef CHECK_END
#undef CHECK_SEND
#undef VALUE_RETURN

