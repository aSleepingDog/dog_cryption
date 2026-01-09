#include "serialize/tlv.h"

/*/
void dog_data::print::block(dog_torch::serialize::BinaryData data, uint64_t column)
{
    printf("XX");
    for (uint64_t i = 0; i < column; ++i)
    {
        printf(" %02X", i);
        if ((i % column) % 4 == 3)
        {
            printf("|");
        }
    }
    uint64_t row = 0;
    for (uint64_t i=0;i<data.size();++i)
    {
        if (i % column == 0) 
        {
            printf("\n%02X", row++);
        }
        printf(" %02X", data[i]);
        if ((i % column) % 4 == 3)
        {
            printf("|");
        }
    }
    printf("\n");
}
void dog_data::print::block(const char* data, uint64_t size, uint64_t column)
{
    printf("XX");
    for (uint64_t i = 0; i < column; ++i)
    {
        printf(" %02X", i);
        if ((i % column) % 4 == 3)
        {
            printf("|");
        }
    }
    uint64_t row = 0;
    for (uint64_t i = 0; i < size; ++i)
    {
        if (i % column == 0)
        {
            printf("\n%02X", row++);
        }
        printf(" %02X", data[i] & 0xff);
        if ((i % column) % 4 == 3)
        {
            printf("|");
        }
    }
    printf("\n");
}
void dog_data::print::space(dog_torch::serialize::BinaryData data, uint64_t column)
{
    if (data.size() == 0) { printf("\n"); return; }
    printf("%02X ", data[0] & 0xff);
    for (uint64_t i = 1; i < data.size(); ++i)
    {
        if (i % column == 0)
        {
            printf("\n");
        }
        printf("%02X ", data[i] & 0xff);
        if ((i % column) % 4 == 3)
        {
            printf("|");
        }
    }
    printf("\n");
}
void dog_data::print::space(const char* data, uint64_t size, uint64_t column)
{
    printf("%02X ", data[0] & 0xff);
    for (uint64_t i = 1; i < size; ++i)
    {
        if (i % column == 0)
        {
            printf("\n");
        }
        printf("%02X ", data[i] & 0xff);
        if ((i % column) % 4 == 3)
        {
            printf("|");
        }
    }
    printf("\n");
}
uint64_t dog_data::buffer::get_buffer_size(uint64_t file_size)
{
    if (file_size < (1ull << 10))//1KB
    {
        return 1ull << 10;//1KB
    }
    else if (file_size < (1ull << 20))//1MB
    {
        return 5ull << 10;//5KB
    }
    else if (file_size < (1ull << 30))
    {
        return 10ull << 10;//10KB
    }
    else if (file_size < (1ull << 40))//1TB
    {
        return 1ull << 20;//1MB
    }
    else
    {
        return 1ull << 30;//1GB
    }
}
*/
dog_torch::serialize::BinaryData dog_torch::serialize::tlv::boolean(bool b)
{
    dog_torch::serialize::BinaryData res(1);
    //bool  -> 0010 (0000/1111=false/true)
    if (b)
    {
        res[0] = 0x2F;
    }
    else
    {
        res[0] = 0x20;
    }
    return res;

}
dog_torch::serialize::BinaryData dog_torch::serialize::tlv::integer_num(uint64_t num)
{
    //int   -> 100 (0/1=+/-) 0001-1000(0-8):length
    dog_torch::serialize::BinaryData res(1);
    uint8_t az = dog_torch::math::integer::available_size(num);
    uint8_t sign = 0x80 | az;
    res[0] = sign;
    for (uint8_t i = 0; i < az; ++i)
    {
        res.push_back(dog_torch::math::integer::pick_byte(num, az - i));
    }
    return res;
}
dog_torch::serialize::BinaryData dog_torch::serialize::tlv::integer_num(int64_t num)
{
    //int   -> 100 (0/1=+/-) 0001-1000(0-8):length
    if (num >= 0)
    {
        return dog_torch::serialize::tlv::integer_num((uint64_t)num);
    }
    dog_torch::serialize::BinaryData res(1);
    uint64_t num_ = (uint64_t)(-num);
    uint8_t az = dog_torch::math::integer::available_size(num_);
    uint8_t sign = 0x90 | az;
    res[0] = sign;
    for (uint8_t i = 0; i < az; ++i)
    {
        res.push_back(dog_torch::math::integer::pick_byte(num_, az - i));
    }
    return res;
}
dog_torch::serialize::BinaryData dog_torch::serialize::tlv::float_num(float num)
{
    //float  -> 101X (4/8=float/double)
    dog_torch::serialize::BinaryData res(5);
    res[0] = 0b10100100;
    memcpy(res.data() + 1, &num, sizeof(float));
    return res;
}
dog_torch::serialize::BinaryData dog_torch::serialize::tlv::float_num(double num)
{
    //float  -> 101X (4/8=float/double)
    dog_torch::serialize::BinaryData res(9);
    res[0] = 0b10101000;
    memcpy(res.data() + 1, &num, sizeof(double));
    return res;
}
dog_torch::serialize::BinaryData dog_torch::serialize::tlv::bytes(const std::vector<uint8_t>& bytes)
{
    dog_torch::serialize::BinaryData res(1);
    uint64_t len = bytes.size();
    uint8_t az = dog_torch::math::integer::available_size(len);
    uint8_t sign = 0x40 | az;
    for (uint8_t i = 0; i < az; ++i)
    {
        res.push_back(dog_torch::math::integer::pick_byte(len, az - i));
    }
    for (uint64_t i = 0; i < len; ++i)
    {
        res.push_back(bytes[i]);
    }
    return res;
}
dog_torch::serialize::BinaryData dog_torch::serialize::tlv::bytes(const uint8_t* bytes, uint64_t size)
{
    dog_torch::serialize::BinaryData res(1);
    uint64_t len = size;
    uint8_t az = dog_torch::math::integer::available_size(len);
    uint8_t sign = 0x40 | az;
    for (uint8_t i = 0; i < az; ++i)
    {
        res.push_back(dog_torch::math::integer::pick_byte(len, az - i));
    }
    for (uint64_t i = 0; i < len; ++i)
    {
        res.push_back(bytes[i]);
    }
    return res;
}
dog_torch::serialize::BinaryData dog_torch::serialize::tlv::bytes(std::istream& stream)
{
    dog_torch::serialize::BinaryData res(1);
    stream.seekg(0, std::ios::end);
    uint64_t len = stream.tellg();
    stream.seekg(0, std::ios::beg);
    uint8_t az = dog_torch::math::integer::available_size(len);
    uint8_t sign = 0x40 | az;
    for (uint8_t i = 0; i < az; ++i)
    {
        res.push_back(dog_torch::math::integer::pick_byte(len, az - i));
    }
    for (uint64_t i = 0; i < len; ++i)
    {
        res.push_back(stream.get());
    }
    return res;
}
dog_torch::serialize::BinaryData dog_torch::serialize::tlv::string(const char* str)
{
    //string  -> 01XX 0000-1000(0-8):length length + int(length) + bytes(utf8)
    dog_torch::serialize::BinaryData res(1);
    uint64_t len = strlen(str);
    uint8_t az = dog_torch::math::integer::available_size(len);
    uint8_t sign = 0x60 | az;
    res[0] = sign;
    for (uint8_t i = 0; i < az; ++i)
    {
        res.push_back(dog_torch::math::integer::pick_byte(len, az - i));
    }
    for (uint64_t i = 0; i < len; ++i)
    {
        res.push_back(str[i]);
    }
    return res;
}
dog_torch::serialize::BinaryData dog_torch::serialize::tlv::string(std::string str)
{
    //string  -> 01XX 0000-1000(0-8):length length + int(length) + bytes(utf8)
    dog_torch::serialize::BinaryData res(1);
    uint64_t len = str.length();
    uint8_t az = dog_torch::math::integer::available_size(len);
    uint8_t sign = 0x60 | az;
    res[0] = sign;
    for (uint8_t i = 0; i < az; ++i)
    {
        res.push_back(dog_torch::math::integer::pick_byte(len, az - i));
    }
    for (uint64_t i = 0; i < len; ++i)
    {
        res.push_back(str[i]);
    }
    return res;
}
dog_torch::serialize::BinaryData dog_torch::serialize::tlv::array(const std::vector<std::any>& arr)
{
    //array  -> 110X 0000-1000(0-8):length length + int(length) + other
    dog_torch::serialize::BinaryData res(1);
    uint64_t len = arr.size();
    uint8_t az = dog_torch::math::integer::available_size(len);
    uint8_t sign = 0xC0 | az;
    res[0] = sign;
    for (uint8_t i = 0; i < az; ++i)
    {
        res.push_back(dog_torch::math::integer::pick_byte(len, az - i));
    }
    for (auto& item : arr)
    {
        dog_torch::serialize::BinaryData single;
        if (item.type() == typeid(bool))
        {
            single = dog_torch::serialize::tlv::boolean(std::any_cast<bool>(item));
        }
        else if (item.type() == typeid(uint64_t))
        {
            single = dog_torch::serialize::tlv::integer_num(std::any_cast<uint64_t>(item));
        }
        else if (item.type() == typeid(uint32_t))
        {
            single = dog_torch::serialize::tlv::integer_num((uint64_t)(std::any_cast<uint32_t>(item)));
        }
        else if (item.type() == typeid(uint16_t))
        {
            single = dog_torch::serialize::tlv::integer_num((uint64_t)(std::any_cast<uint16_t>(item)));
        }
        else if (item.type() == typeid(uint8_t))
        {
            single = dog_torch::serialize::tlv::integer_num((uint64_t)(std::any_cast<uint8_t>(item)));
        }
        else if (item.type() == typeid(int64_t))
        {
            single = dog_torch::serialize::tlv::integer_num((std::any_cast<int64_t>(item)));
        }
        else if (item.type() == typeid(int32_t))
        {
            single = dog_torch::serialize::tlv::integer_num((int64_t)(std::any_cast<int32_t>(item)));
        }
        else if (item.type() == typeid(int16_t))
        {
            single = dog_torch::serialize::tlv::integer_num((int64_t)(std::any_cast<int16_t>(item)));
        }
        else if (item.type() == typeid(int8_t))
        {
            single = dog_torch::serialize::tlv::integer_num((int64_t)(std::any_cast<int8_t>(item)));
        }
        else if (item.type() == typeid(float))
        {
            single = dog_torch::serialize::tlv::float_num(std::any_cast<float>(item));
        }
        else if (item.type() == typeid(double))
        {
            single = dog_torch::serialize::tlv::float_num(std::any_cast<double>(item));
        }
        else if (item.type() == typeid(std::string))
        {
            single = dog_torch::serialize::tlv::string(std::any_cast<std::string>(item));
        }
        else if (item.type() == typeid(const char*))
        {
            single = dog_torch::serialize::tlv::string(std::any_cast<const char*>(item));
        }
        else if (item.type() == typeid(std::vector<std::any>))
        {
            single = dog_torch::serialize::tlv::array(std::any_cast<std::vector<std::any>>(item));
        }
        else if (item.type() == typeid(std::unordered_map<std::string, std::any>))
        {
            single = dog_torch::serialize::tlv::object(std::any_cast<std::unordered_map<std::string, std::any>>(item));
        }
        else if (item.type() == typeid(std::map<std::string, std::any>))
        {
            single = dog_torch::serialize::tlv::object(std::any_cast<std::map<std::string, std::any>>(item));
        }
        res += single;
    }
    return res;
}
dog_torch::serialize::BinaryData dog_torch::serialize::tlv::object(const std::unordered_map<std::string, std::any>& obj)
{
    dog_torch::serialize::BinaryData res(1);
    uint64_t len = obj.size();
    uint8_t az = dog_torch::math::integer::available_size(len);
    uint8_t sign = 0xE0 | az;
    res[0] = sign;
    for (uint8_t i = 0; i < az; ++i)
    {
        res.push_back(dog_torch::math::integer::pick_byte(len, az - i));
    }
    for (auto& item_value : obj)
    {
        dog_torch::serialize::BinaryData single;
        std::string key = item_value.first;
        single = dog_torch::serialize::tlv::string(std::any_cast<std::string>(key));
        res += single;
        std::any item = item_value.second;
        if (item.type() == typeid(bool))
        {
            single = dog_torch::serialize::tlv::boolean(std::any_cast<bool>(item));
        }
        else if (item.type() == typeid(uint64_t))
        {
            single = dog_torch::serialize::tlv::integer_num(std::any_cast<uint64_t>(item));
        }
        else if (item.type() == typeid(uint32_t))
        {
            single = dog_torch::serialize::tlv::integer_num((uint64_t)(std::any_cast<uint32_t>(item)));
        }
        else if (item.type() == typeid(uint16_t))
        {
            single = dog_torch::serialize::tlv::integer_num((uint64_t)(std::any_cast<uint16_t>(item)));
        }
        else if (item.type() == typeid(uint8_t))
        {
            single = dog_torch::serialize::tlv::integer_num((uint64_t)(std::any_cast<uint8_t>(item)));
        }
        else if (item.type() == typeid(int64_t))
        {
            single = dog_torch::serialize::tlv::integer_num((std::any_cast<int64_t>(item)));
        }
        else if (item.type() == typeid(int32_t))
        {
            single = dog_torch::serialize::tlv::integer_num((int64_t)(std::any_cast<int32_t>(item)));
        }
        else if (item.type() == typeid(int16_t))
        {
            single = dog_torch::serialize::tlv::integer_num((int64_t)(std::any_cast<int16_t>(item)));
        }
        else if (item.type() == typeid(int8_t))
        {
            single = dog_torch::serialize::tlv::integer_num((int64_t)(std::any_cast<int8_t>(item)));
        }
        else if (item.type() == typeid(float))
        {
            single = dog_torch::serialize::tlv::float_num(std::any_cast<float>(item));
        }
        else if (item.type() == typeid(double))
        {
            single = dog_torch::serialize::tlv::float_num(std::any_cast<double>(item));
        }
        else if (item.type() == typeid(std::string))
        {
            single = dog_torch::serialize::tlv::string(std::any_cast<std::string>(item));
        }
        else if (item.type() == typeid(const char*))
        {
            single = dog_torch::serialize::tlv::string(std::any_cast<const char*>(item));
        }
        else if (item.type() == typeid(std::vector<std::any>))
        {
            single = dog_torch::serialize::tlv::array(std::any_cast<std::vector<std::any>>(item));
        }
        else if (item.type() == typeid(std::unordered_map<std::string, std::any>))
        {
            single = dog_torch::serialize::tlv::object(std::any_cast<std::unordered_map<std::string, std::any>>(item));
        }
        else if (item.type() == typeid(std::map<std::string, std::any>))
        {
            single = dog_torch::serialize::tlv::object(std::any_cast<std::map<std::string, std::any>>(item));
        }
        res += single;
    }
    return res;
}
dog_torch::serialize::BinaryData dog_torch::serialize::tlv::object(const std::map<std::string, std::any>& obj)
{
    dog_torch::serialize::BinaryData res(1);
    uint64_t len = obj.size();
    uint8_t az = dog_torch::math::integer::available_size(len);
    uint8_t sign = 0xE0 | az;
    res[0] = sign;
    for (uint8_t i = 0; i < az; ++i)
    {
        res.push_back(dog_torch::math::integer::pick_byte(len, az - i));
    }
    for (auto& item_value : obj)
    {
        dog_torch::serialize::BinaryData single;
        std::string key = item_value.first;
        single = dog_torch::serialize::tlv::string(std::any_cast<std::string>(key));
        res += single;
        std::any item = item_value.second;
        if (item.type() == typeid(bool))
        {
            single = dog_torch::serialize::tlv::boolean(std::any_cast<bool>(item));
        }
        else if (item.type() == typeid(uint64_t))
        {
            single = dog_torch::serialize::tlv::integer_num(std::any_cast<uint64_t>(item));
        }
        else if (item.type() == typeid(uint32_t))
        {
            single = dog_torch::serialize::tlv::integer_num((uint64_t)(std::any_cast<uint32_t>(item)));
        }
        else if (item.type() == typeid(uint16_t))
        {
            single = dog_torch::serialize::tlv::integer_num((uint64_t)(std::any_cast<uint16_t>(item)));
        }
        else if (item.type() == typeid(uint8_t))
        {
            single = dog_torch::serialize::tlv::integer_num((uint64_t)(std::any_cast<uint8_t>(item)));
        }
        else if (item.type() == typeid(int64_t))
        {
            single = dog_torch::serialize::tlv::integer_num((std::any_cast<int64_t>(item)));
        }
        else if (item.type() == typeid(int32_t))
        {
            single = dog_torch::serialize::tlv::integer_num((int64_t)(std::any_cast<int32_t>(item)));
        }
        else if (item.type() == typeid(int16_t))
        {
            single = dog_torch::serialize::tlv::integer_num((int64_t)(std::any_cast<int16_t>(item)));
        }
        else if (item.type() == typeid(int8_t))
        {
            single = dog_torch::serialize::tlv::integer_num((int64_t)(std::any_cast<int8_t>(item)));
        }
        else if (item.type() == typeid(float))
        {
            single = dog_torch::serialize::tlv::float_num(std::any_cast<float>(item));
        }
        else if (item.type() == typeid(double))
        {
            single = dog_torch::serialize::tlv::float_num(std::any_cast<double>(item));
        }
        else if (item.type() == typeid(std::string))
        {
            single = dog_torch::serialize::tlv::string(std::any_cast<std::string>(item));
        }
        else if (item.type() == typeid(const char*))
        {
            single = dog_torch::serialize::tlv::string(std::any_cast<const char*>(item));
        }
        else if (item.type() == typeid(std::vector<std::any>))
        {
            single = dog_torch::serialize::tlv::array(std::any_cast<std::vector<std::any>>(item));
        }
        else if (item.type() == typeid(std::unordered_map<std::string, std::any>))
        {
            single = dog_torch::serialize::tlv::object(std::any_cast<std::unordered_map<std::string, std::any>>(item));
        }
        else if (item.type() == typeid(std::map<std::string, std::any>))
        {
            single = dog_torch::serialize::tlv::object(std::any_cast<std::map<std::string, std::any>>(item));
        }
        res += single;
    }
    return res;
}

std::any dog_torch::serialize::tlv::read_any(dog_torch::serialize::BinaryData data)
{
    dog_torch::serialize::DataStream stream(data);
    return read_any(stream);
}
std::any dog_torch::serialize::tlv::read_any(std::istream& data)
{
    uint8_t as = data.get();
    if ((as & 0xE0) == 0x00)
    {
        return nullptr;
    }
    else if ((as & 0xE0) == 0x20)
    {
        if ((as & 0x0F) == 0x00)
        {
            return false;
        }
        else if ((as & 0x0F) == 0x0F)
        {
            return true;
        }
    }
    else if ((as & 0xE0) == 0x80)
    {
        uint8_t length = (as & 0x0F);
        if ((as & 0x10) == 0x00)
        {
            uint64_t value = 0;
            //memcpy(&value, &data[start], length);
            uint8_t* p = (uint8_t*)&value + length - 1;
            for (uint8_t i = 0; i < length; i++)
            {
                *p = data.get();
                p--;
            }
            return value;
        }
        else if ((as & 0x10) == 0x10)
        {
            uint64_t value = 0;
            uint8_t* p = (uint8_t*)&value + length - 1;
            for (uint8_t i = 0; i < length; i++)
            {
                *p = data.get();
                p--;
            }
            int64_t res = -value;
            return res;
        }
    }
    else if ((as & 0xE0) == 0xA0)
    {
        if ((as & 0x0F) == 0x04)
        {
            uint32_t value = 0;
            uint8_t* p = (uint8_t*)&value + 4 - 1;
            for (uint8_t i = 0; i < 4; i++)
            {
                *p = data.get();
                p--;
            }
            for (int i = 0; i < 4; i++) { data.get(); }
            float f_v = 0;
            memcpy(&f_v, &value, 4);
            return value;
        }
        else if ((as & 0x0F) == 0x08)
        {
            uint64_t value = 0;
            uint8_t* p = (uint8_t*)&value + 8 - 1;
            for (uint8_t i = 0; i < 8; i++)
            {
                *p = data.get();
                p--;
            }
            for (int i = 0; i < 8; i++) { data.get(); }
            float f_v = 0;
            memcpy(&f_v, &value, 8);
            return value;
        }
    }
    else if ((as & 0xE0) == 0x40)
    {
        uint8_t length_length = (as & 0x0F);
        uint64_t length = 0;
        uint8_t* p = (uint8_t*)&length + length_length - 1;
        for (uint8_t i = 0; i < length_length; i++)
        {
            *p = data.get();
            p--;
        }
        std::vector<uint8_t> value(length);
        for (uint64_t i = 0; i < length; i++)
        {
            value[i] = data.get();
        }
        return value;
    }
    else if ((as & 0xE0) == 0x60)
    {
        uint8_t length_length = (as & 0x0F);
        uint64_t length = 0;
        uint8_t* p = (uint8_t*)&length + length_length - 1;
        for (uint8_t i = 0; i < length_length; i++)
        {
            *p = data.get();
            p--;
        }
        std::string value;
        for (uint64_t i = 0; i < length; i++)
        {
            value += data.get();
        }
        return value;
    }
    else if ((as & 0xE0) == 0xC0)
    {
        uint8_t length_length = (as & 0x0F);
        uint64_t length = 0;
        uint8_t* p = (uint8_t*)&length + length_length - 1;
        for (uint8_t i = 0; i < length_length; i++)
        {
            *p = data.get();
            p--;
        }
        std::vector<std::any> value;
        for (uint64_t i = 0; i < length; i++)
        {
            value.push_back(read_any(data));
        }
        return value;
    }
    else if ((as & 0xE0) == 0xE0)
    {
        uint8_t length_length = (as & 0x0F);
        uint64_t length = 0;
        uint8_t* p = (uint8_t*)&length + length_length - 1;
        for (uint8_t i = 0; i < length_length; i++)
        {
            *p = data.get();
            p--;
        }
        std::unordered_map<std::string, std::any> res;
        for (uint64_t i = 0; i < length; i++)
        {
            std::any key = read_any(data);
            std::any value = read_any(data);
            std::string key_str = std::any_cast<std::string>(key);
            res[key_str] = value;
        }
        return res;
    }
}
std::any dog_torch::serialize::tlv::read_any(dog_torch::serialize::DataStream& data)
{
    /*
		   null  -> 0000 0000
		  start  -> 0000 0001
		   end   -> 0000 0010
		   bool  -> 0010 (0000/1111=false/true)
		   int   -> 100 (0/1=+/-) 0001-1000(0-8):length
		  float  -> 101X (4/8=float/double)
		  bytes  -> 010X 0000-1000(0-8):length length + int(length) + bytes
		 string  -> 011X 0000-1000(0-8):length length + int(length) + bytes(utf8)
		  array  -> 110X 0000-1000(0-8):length length + int(length) + other
		 object(hash table)  -> 111X 0000-1000(0-8):length length + int(length) + string:other
	*/
    uint8_t as = data.get();
    if ((as & 0xE0) == 0x00)
    {
        return nullptr;
    }
    else if ((as & 0xE0) == 0x20)
    {
        if ((as & 0x0F) == 0x00)
        {
            return false;
        }
        else if ((as & 0x0F) == 0x0F)
        {
            return true;
        }
    }
    else if ((as & 0xE0) == 0x80)
    {
        uint8_t length = (as & 0x0F);
        if ((as & 0x10) == 0x00)
        {
            uint64_t value = 0;
            //memcpy(&value, &data[start], length);
            uint8_t* p = (uint8_t*)&value + length - 1;
            for (uint8_t i = 0; i < length; i++)
            {
                *p = data.get();
                p--;
            }
            return value;
        }
        else if ((as & 0x10) == 0x10)
        {
            uint64_t value = 0;
            uint8_t* p = (uint8_t*)&value + length - 1;
            for (uint8_t i = 0; i < length; i++)
            {
                *p = data.get();
                p--;
            }
            int64_t res = -value;
            return res;
        }
    }
    else if ((as & 0xE0) == 0xA0)
    {
        if ((as & 0x0F) == 0x04)
        {
            float value = 0;
            memcpy(&value, data.data(), 4);
            for (int i = 0; i < 4; i++) { data.get(); }
            return value;
        }
        else if ((as & 0x0F) == 0x08)
        {
            double value = 0;
            memcpy(&value, data.data(), 8);
            for (int i = 0; i < 8; i++) { data.get(); }
            return value;
        }
    }
    else if ((as & 0xE0) == 0x40)
    {
        uint8_t length_length = (as & 0x0F);
        uint64_t length = 0;
        uint8_t* p = (uint8_t*)&length + length_length - 1;
        for (uint8_t i = 0; i < length_length; i++)
        {
            *p = data.get();
            p--;
        }
        std::vector<uint8_t> value(length);
        for (uint64_t i = 0; i < length; i++)
        {
            value[i] = data.get();
        }
        return value;
    }
    else if ((as & 0xE0) == 0x60)
    {
        uint8_t length_length = (as & 0x0F);
        uint64_t length = 0;
        uint8_t* p = (uint8_t*)&length + length_length - 1;
        for (uint8_t i = 0; i < length_length; i++)
        {
            *p = data.get();
            p--;
        }
        std::string value;
        for (uint64_t i = 0; i < length; i++)
        {
            value += data.get();
        }
        return value;
    }
    else if ((as & 0xE0) == 0xC0)
    {
        uint8_t length_length = (as & 0x0F);
        uint64_t length = 0;
        uint8_t* p = (uint8_t*)&length + length_length - 1;
        for (uint8_t i = 0; i < length_length; i++)
        {
            *p = data.get();
            p--;
        }
        std::vector<std::any> value;
        for (uint64_t i = 0; i < length; i++)
        {
            value.push_back(read_any(data));
        }
        return value;
    }
    else if ((as & 0xE0) == 0xE0)
    {
        uint8_t length_length = (as & 0x0F);
        uint64_t length = 0;
        uint8_t* p = (uint8_t*)&length + length_length - 1;
        for (uint8_t i = 0; i < length_length; i++)
        {
            *p = data.get();
            p--;
        }
        std::unordered_map<std::string, std::any> res;
        for (uint64_t i = 0; i < length; i++)
        {
            std::any key = read_any(data);
            std::any value = read_any(data);
            std::string key_str = std::any_cast<std::string>(key);
            res[key_str] = value;
        }
        return res;
    }
    else
    {
        throw dog_torch::utils::Exception(DOG_EXCEPTION_MSG_OPINION("Error:Invalid TLV type\n错误：无效的TLV类型"));
    }
}

