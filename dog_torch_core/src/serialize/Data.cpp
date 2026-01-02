#include "serialize/Data.h"

dog_torch::serialize::Data::Data(std::string str, const int type)
{
    if (type == 0)//常规字符串
    {
        this->inside_data.resize(str.size());
        for (int i = 0; i < str.size(); i++)
        {
            this->inside_data[i] = str[i];
        }
    }
    else if (type == 1)//Base64
    {
        uint64_t m = str.size() * 3 / 4;
        this->inside_data.reserve(m);
        for (int i = 0; i < str.size(); i += 4)
        {
            uint8_t b[4] = { 0,0,0,0 };
            for (int i0 = 0; i0 < 4; i0++)
            {
                if (str[i + i0] >= (uint8_t)'A' && str[i + i0] <= (uint8_t)'Z')
                {
                    b[i0] = str[i + i0] - (uint8_t)'A';
                }
                else if (str[i + i0] >= (uint8_t)'a' && str[i + i0] <= (uint8_t)'z')
                {
                    b[i0] = str[i + i0] - (uint8_t)'a' + (uint8_t)26;
                }
                else if (str[i + i0] >= (uint8_t)'0' && str[i + i0] <= (uint8_t)'9')
                {
                    b[i0] = str[i + i0] - (uint8_t)'0' + (uint8_t)52;
                }
                else if (str[i + i0] == (uint8_t)'+')
                {
                    b[i0] = (uint8_t)62;
                }
                else if (str[i + i0] == (uint8_t)'/')
                {
                    b[i0] = (uint8_t)63;
                }
                else if (str[i + i0] == (uint8_t)'=')
                {
                    b[i0] = (uint8_t)64;
                }
            }
            this->inside_data.push_back((uint8_t)((b[0] << 2) | (b[1] >> 4)));
            if (b[2] == (uint8_t)64) { continue;/*b[2] = (uint8_t)0;*/ /* break; */ }
            this->inside_data.push_back((uint8_t)((b[1] << 4) | (b[2] >> 2)));
            if (b[3] == (uint8_t)64) { continue;/*b[3] == (uint8_t)0; */ /* break; */ }
            this->inside_data.push_back((uint8_t)((b[2] << 6) | b[3]));
        }
    }
    else if (type == 2)//16进制
    {
        this->inside_data.reserve(str.size() / 2);
        for (int i = 0; i < str.size(); i += 2)
        {
            uint8_t b0 = 0;
            if (str[i] >= (uint8_t)'A' && str[i] <= (uint8_t)'F')
            {
                b0 = str[i] - (uint8_t)'A' + (uint8_t)10;
            }
            else if (str[i] >= (uint8_t)'a' && str[i] <= (uint8_t)'f')
            {
                b0 = str[i] - (uint8_t)'a' + (uint8_t)10;
            }
            else if (str[i] >= '0' && str[i] <= '9')
            {
                b0 = str[i] - (uint8_t)'0';
            }
            uint8_t b1 = 0;
            if (str[i + 1] >= (uint8_t)'A' && str[i + 1] <= (uint8_t)'F')
            {
                b1 = str[i + 1] - (uint8_t)'A' + (uint8_t)10;
            }
            else if (str[i + 1] >= (uint8_t)'a' && str[i + 1] <= (uint8_t)'f')
            {
                b1 = str[i + 1] - (uint8_t)'a' + (uint8_t)10;
            }
            else if (str[i + 1] >= '0' && str[i + 1] <= '9')
            {
                b1 = str[i + 1] - (uint8_t)'0';
            }
            this->inside_data.push_back((uint8_t)(b0 * 16 + b1));
        }
    }
}
dog_torch::serialize::Data::Data(uint64_t size)
{
    this->inside_data.resize(size);
}
dog_torch::serialize::Data::Data(const Data& other)
{
    this->inside_data = other.inside_data;
    //printf("copy data %lld=>%lld\n", (uint64_t)&other, (uint64_t)this);
}
void dog_torch::serialize::Data::operator=(const Data& other)
{
    this->inside_data = other.inside_data;
    //printf("copy data %lld=>%lld\n", (uint64_t)&other, (uint64_t)this);
}
dog_torch::serialize::Data::Data(Data&& other) noexcept
{
    this->inside_data = std::move(other.inside_data);
    //printf("move data %lld->%lld\n", (uint64_t)&other, (uint64_t)this);
}
dog_torch::serialize::Data::~Data()
{
    //printf("delete data %lld\n", (uint64_t)this);
}
uint8_t& dog_torch::serialize::Data::at(uint64_t i)
{
    return this->inside_data.at(i);
}
uint8_t dog_torch::serialize::Data::at(uint64_t i) const
{
    return this->inside_data.at(i);
}
uint8_t& dog_torch::serialize::Data::operator[](uint64_t i)
{
    return this->inside_data[i];
}
uint8_t dog_torch::serialize::Data::operator[](uint64_t i) const
{
    return this->inside_data[i];
}
uint8_t& dog_torch::serialize::Data::front()
{
    return this->inside_data.front();
}
uint8_t& dog_torch::serialize::Data::back()
{
    return this->inside_data.back();
}
uint8_t* dog_torch::serialize::Data::data()
{
    return this->inside_data.data();
}
const uint8_t* dog_torch::serialize::Data::data() const
{
    return this->inside_data.data();
}
std::vector<uint8_t>::iterator dog_torch::serialize::Data::begin()
{
    return this->inside_data.begin();
}
std::vector<uint8_t>::iterator dog_torch::serialize::Data::end()
{
    return this->inside_data.end();
}
std::vector<uint8_t>::const_iterator dog_torch::serialize::Data::cbegin() const
{
    return this->inside_data.cbegin();
}
std::vector<uint8_t>::const_iterator dog_torch::serialize::Data::cend() const
{
    return this->inside_data.cend();
}
std::reverse_iterator<std::vector<uint8_t>::iterator> dog_torch::serialize::Data::rbegin()
{
    return this->inside_data.rbegin();
}
std::reverse_iterator<std::vector<uint8_t>::iterator> dog_torch::serialize::Data::rend()
{
    return this->inside_data.rend();
}
std::reverse_iterator<std::vector<uint8_t>::const_iterator> dog_torch::serialize::Data::crbegin() const
{
    return this->inside_data.crbegin();
}
std::reverse_iterator<std::vector<uint8_t>::const_iterator> dog_torch::serialize::Data::crend() const
{
    return this->inside_data.crend();
}
std::vector<uint8_t> dog_torch::serialize::Data::to_byte_vector() const
{
    return this->inside_data;
}
std::vector<char> dog_torch::serialize::Data::to_utf8_vector() const
{
    std::vector<char> res(this->inside_data.size());
    for (int i = 0; i < this->inside_data.size(); i++)
    {
        res[i] = this->inside_data[i];
    }
    return res;
}
std::vector<char> dog_torch::serialize::Data::to_base64_vector() const
{
    return this->to_base64_vector('+', '/', '=');
}
std::vector<char> dog_torch::serialize::Data::to_base64_vector(char a, char b) const
{
    return this->to_base64_vector(a, b, '=');
}
std::vector<char> dog_torch::serialize::Data::to_base64_vector(char a, char b, char c) const
{
    char tempList[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    tempList[62] = a; tempList[63] = b;
    std::vector<char> res;
    int bit[4] = { 0,0,0,0 };
    uint64_t TDfull = this->inside_data.size() - this->inside_data.size() % 3;
    for (uint64_t i = 0; i < TDfull; i += 3)
    {
        bit[0] = (this->inside_data[i] >> 2) & 0x3f;
        bit[1] = ((this->inside_data[i] << 6 >> 2) + (this->inside_data[i + 1] >> 4)) & 0x3f;
        bit[2] = ((this->inside_data[i + 1] << 4 >> 2) + (this->inside_data[i + 2] >> 6)) & 0x3f;
        bit[3] = (this->inside_data[i + 2] << 2 >> 2) & 0x3f;
        res.push_back(tempList[bit[0]]);
        res.push_back(tempList[bit[1]]);
        res.push_back(tempList[bit[2]]);
        res.push_back(tempList[bit[3]]);
    }
    if (this->inside_data.size() % 3 == 1)
    {
        bit[0] = (this->inside_data[TDfull] >> 2) & 0x3f;
        bit[1] = (this->inside_data[TDfull] << 6 >> 2) & 0x3f;
        res.push_back(tempList[bit[0]]);
        res.push_back(tempList[bit[1]]);
        res.push_back(c);
        res.push_back(c);
    }
    else if (this->inside_data.size() % 3 == 2)
    {
        bit[0] = (this->inside_data[TDfull] >> 2) & 0x3f;
        bit[1] = ((this->inside_data[TDfull] << 6 >> 2) + (this->inside_data[TDfull + 1] >> 4)) & 0x3f;
        bit[2] = (this->inside_data[TDfull + 1] << 4 >> 2) & 0x3f;
        res.push_back(tempList[bit[0]]);
        res.push_back(tempList[bit[1]]);
        res.push_back(tempList[bit[2]]);
        res.push_back(c);
    }
    return res;
}
std::vector<char> dog_torch::serialize::Data::to_hex_vector(bool is_upper) const
{
    std::vector<char> res;
    std::string HexList;
    if (is_upper)
    {
        HexList = "0123456789ABCDEF";
    }
    else
    {
        HexList = "0123456789abcdef";
    }
    res.reserve(this->inside_data.size() * 2);
    for (int i = 0; i < this->inside_data.size(); i++)
    {
        res.push_back(HexList[(uint8_t)this->inside_data[i] >> 4]);
        res.push_back(HexList[(uint8_t)this->inside_data[i] & 0x0f]);
    }
    return res;
}
std::string dog_torch::serialize::Data::to_utf8_string() const
{
    std::vector<char> res = this->to_utf8_vector();
    return std::string(res.begin(), res.end());
}
std::string dog_torch::serialize::Data::to_base64_string() const
{
    std::vector<char> res = this->to_base64_vector();
    return std::string(res.begin(), res.end());
}
std::string dog_torch::serialize::Data::to_base64_string(char a, char b) const
{
    std::vector<char> res = this->to_base64_vector(a, b);
    return std::string(res.begin(), res.end());
}
std::string dog_torch::serialize::Data::to_base64_string(char a, char b, char c) const
{
    std::vector<char> res = this->to_base64_vector(a, b, c);
    return std::string(res.begin(), res.end());
}
std::string dog_torch::serialize::Data::to_hex_string(bool is_upper) const
{
    std::vector<char> res = this->to_hex_vector(is_upper);
    return std::string(res.begin(), res.end());
}
dog_torch::serialize::Data dog_torch::serialize::Data::sub_by_pos(uint64_t start, uint64_t end) const
{
    uint64_t size = end - start;
    uint64_t max_size = this->inside_data.size();
    dog_torch::serialize::Data res; res.reserve(size);
    for (uint64_t i = start; i < end && i < max_size; i++)
    {
        res.push_back(this->inside_data[i]);
    }
    return res;
}
dog_torch::serialize::Data dog_torch::serialize::Data::sub_by_len(uint64_t start, uint64_t len) const
{
    uint64_t end = start + len;
    uint64_t max_size = this->inside_data.size();
    dog_torch::serialize::Data res; res.reserve(len);
    for (uint64_t i = start; i < end && i < max_size; i++)
    {
        res.push_back(this->inside_data[i]);
    }
    return res;
}
dog_torch::serialize::Data dog_torch::serialize::Data::sub_by_pos(std::vector<uint8_t>::iterator start, std::vector<uint8_t>::iterator end) const
{
    uint64_t size = end - start;
    dog_torch::serialize::Data res; res.reserve(size);
    for (std::vector<uint8_t>::iterator i = start; i != end; i++)
    {
        res.push_back(*i);
    }
    return res;
}
dog_torch::serialize::Data dog_torch::serialize::Data::sub_by_len(std::vector<uint8_t>::iterator start, uint64_t len) const
{
    std::vector<uint8_t>::iterator end = start + len;
    dog_torch::serialize::Data res; res.reserve(len);
    for (std::vector<uint8_t>::iterator i = start; i != end; i++)
    {
        res.push_back(*i);
    }
    return res;
}
bool dog_torch::serialize::Data::empty() const
{
    return this->inside_data.empty();
}
uint64_t dog_torch::serialize::Data::size() const
{
    return this->inside_data.size();
}
uint64_t dog_torch::serialize::Data::max_size() const
{
    return this->inside_data.max_size();
}
void dog_torch::serialize::Data::reserve(uint64_t n)
{
    return this->inside_data.reserve(n);
}
void dog_torch::serialize::Data::insert(const uint64_t i, uint8_t b)
{
    this->inside_data.insert(this->inside_data.begin() + i, b);
}
void dog_torch::serialize::Data::insert(const std::vector<uint8_t>::iterator pos, uint8_t b)
{
    this->inside_data.insert(pos, b);
}
void dog_torch::serialize::Data::erase(const uint64_t i)
{
    this->inside_data.erase(this->inside_data.begin() + i);
}
void dog_torch::serialize::Data::erase(const std::vector<uint8_t>::iterator pos)
{
    this->inside_data.erase(pos);
}
void dog_torch::serialize::Data::rm_pos()
{
    this->inside_data.clear();
}
void dog_torch::serialize::Data::set_zero()
{
    for (auto it = this->inside_data.begin(); it != this->inside_data.end(); it++)
    {
        *it = '\0';
    }
}
void dog_torch::serialize::Data::push_back(uint8_t b)
{
    this->inside_data.push_back(b);
}
void dog_torch::serialize::Data::pop_back()
{
    this->inside_data.pop_back();
}
void dog_torch::serialize::Data::reverse()
{
    for (uint64_t i = 0; i < this->size() / 2; i++)
    {
        std::swap(this->inside_data[i], this->inside_data[this->size() - i - 1]);
    }
}
void dog_torch::serialize::Data::swap(Data& d)
{
    this->inside_data.swap(d.inside_data);
}
void dog_torch::serialize::Data::swap(Data d)
{
    this->inside_data.swap(d.inside_data);
}
dog_torch::serialize::Data dog_torch::serialize::Data::bit_left_move_norise(uint64_t shift)
{
    dog_torch::serialize::Data res; res.reserve(this->size());
    dog_torch::serialize::Data mid;
    uint64_t byte_shift = shift / 8;
    uint64_t bit_shift = shift % 8;
    uint8_t last = 0;
    if (byte_shift > this->size())
    {
        for (uint64_t i = 0; i < this->size(); i++)
        {
            res.push_back(0x00);
        }
        return res;
    }
    else if (byte_shift != 0)
    {
        mid = this->sub_by_len(byte_shift, this->size() - byte_shift);
        for (uint64_t i = 0; i < byte_shift; i++)
        {
            mid.push_back(0x00);
        }
    }
    else
    {
        mid = *this;
    }
    for (auto rit = mid.crbegin(); rit != mid.crend(); rit++)
    {
        res.insert(res.begin(), *rit << bit_shift | last);
        last = *rit >> (8 - bit_shift);
    }
    return res;
}
void dog_torch::serialize::Data::bit_left_move_norise_self(uint64_t shift)
{
    dog_torch::serialize::Data mid;
    uint64_t byte_shift = shift / 8;
    uint64_t bit_shift = shift % 8;
    uint8_t last = 0;
    if (byte_shift > this->size())
    {
        this->set_zero();
    }
    else if (byte_shift != 0)
    {
        mid = this->sub_by_len(byte_shift, this->size() - byte_shift);
        for (uint64_t i = 0; i < byte_shift; i++)
        {
            mid.push_back(0x00);
        }
    }
    else
    {
        mid = *this;
    }
    this->rm_pos();
    for (auto rit = mid.crbegin(); rit != mid.crend(); rit++)
    {
        this->insert(this->begin(), *rit << bit_shift | last);
        last = *rit >> (8 - bit_shift);
    }
}
dog_torch::serialize::Data dog_torch::serialize::Data::bit_left_move_rise(uint64_t shift)
{
    dog_torch::serialize::Data res; res.reserve(this->size());
    uint64_t byte_shift = shift / 8;
    uint64_t bit_shift = shift % 8;
    uint8_t last = 0;
    for (auto rit = this->crbegin(); rit != this->crend(); rit++)
    {
        res.insert(res.begin(), *rit << bit_shift | last);
        last = *rit >> (8 - bit_shift);
    }
    if (last != 0x00)
    {
        res.insert(res.begin(), last);
    }
    for (uint64_t i = 0; i < byte_shift; i++)
    {
        res.push_back(0x00);
    }
    return res;
}
void dog_torch::serialize::Data::bit_left_move_rise_self(uint64_t shift)
{
    uint64_t byte_shift = shift / 8;
    uint64_t bit_shift = shift % 8;
    uint8_t last = 0;
    for (auto rit = this->rbegin(); rit != this->rend(); rit++)
    {
        uint8_t tmp = (*rit << bit_shift | last);
        last = *rit >> (8 - bit_shift);
        *rit = tmp;
    }
    if (last != 0x00)
    {
        this->insert(this->begin(), last);
    }
    for (uint64_t i = 0; i < byte_shift; i++)
    {
        this->push_back(0x00);
    }
}
dog_torch::serialize::Data dog_torch::serialize::Data::bit_right_move_norise(uint64_t shift)
{
    dog_torch::serialize::Data res; res.reserve(this->size());
    dog_torch::serialize::Data mid;
    uint64_t byte_shift = shift / 8;
    uint64_t bit_shift = shift % 8;
    uint8_t last = 0;
    if (byte_shift > this->size())
    {
        for (uint64_t i = 0; i < this->size(); i++)
        {
            res.push_back(0x00);
        }
        return res;
    }
    else if (byte_shift != 0)
    {
        mid = this->sub_by_len(0, this->size() - byte_shift);
        for (uint64_t i = 0; i < byte_shift; i++)
        {
            mid.insert(mid.begin(), 0x00);
        }
    }
    else
    {
        mid = *this;
    }
    for (auto it = mid.cbegin(); it != mid.cend(); it++)
    {
        res.push_back(*it >> bit_shift | last);
        last = *it << (8 - bit_shift);
    }
    return res;
}
void dog_torch::serialize::Data::bit_right_move_norise_self(uint64_t shift)
{
    dog_torch::serialize::Data mid;
    uint64_t byte_shift = shift / 8;
    uint64_t bit_shift = shift % 8;
    uint8_t last = 0;
    if (byte_shift > this->size())
    {
        this->set_zero();
    }
    else if (byte_shift != 0)
    {
        mid = this->sub_by_len(0, this->size() - byte_shift);
        for (uint64_t i = 0; i < byte_shift; i++)
        {
            mid.insert(mid.begin(), 0x00);
        }
    }
    else
    {
        mid = *this;
    }
    this->rm_pos();
    for (auto it = mid.cbegin(); it != mid.cend(); it++)
    {
        this->push_back(*it >> bit_shift | last);
        last = *it << (8 - bit_shift);
    }
}
dog_torch::serialize::Data dog_torch::serialize::Data::bit_right_move_rise(uint64_t shift)
{
    dog_torch::serialize::Data res; res.reserve(this->size());
    uint64_t byte_shift = shift / 8;
    uint64_t bit_shift = shift % 8;
    uint8_t last = 0;
    for (auto rit = this->cbegin(); rit != this->cend(); rit++)
    {
        res.push_back(*rit >> bit_shift | last);
        last = *rit << (8 - bit_shift);
    }
    if (last != 0x00)
    {
        res.push_back(last);
    }
    for (uint64_t i = 0; i < byte_shift; i++)
    {
        res.insert(res.begin(), 0x00);
    }
    return res;
}
void dog_torch::serialize::Data::bit_right_move_rise_self(uint64_t shift)
{
    uint64_t byte_shift = shift / 8;
    uint64_t bit_shift = shift % 8;
    uint8_t last = 0;
    for (auto rit = this->begin(); rit != this->end(); rit++)
    {
        uint8_t tmp = (*rit >> bit_shift | last);
        last = *rit << (8 - bit_shift);
        *rit = tmp;
    }
    if (last != 0x00)
    {
        this->push_back(last);
    }
    for (uint64_t i = 0; i < byte_shift; i++)
    {
        this->insert(this->begin(), 0x00);
    }
}
dog_torch::serialize::Data dog_torch::serialize::Data::bit_circle_left_move(uint64_t shift)
{
    return this->bit_left_move_norise(shift) | this->bit_right_move_norise(this->size() * 8 - shift);
}
dog_torch::serialize::Data dog_torch::serialize::Data::bit_circle_right_move(uint64_t shift)
{
    return this->bit_right_move_norise(shift) | this->bit_left_move_norise(this->size() * 8 - shift);
}
dog_torch::serialize::Data dog_torch::serialize::Data::operator~()
{
    dog_torch::serialize::Data res;
    for (auto it = this->cbegin(); it != this->cend(); it++)
    {
        res.push_back(~(*it));
    }
    return res;
}
bool dog_torch::serialize::Data::is_equal(const Data& d2) const
{
    return *this == d2;
}
dog_torch::serialize::Data dog_torch::serialize::Data::concat(const Data& b) const
{
    return *this + b;
}
/*
bool DogData::operator==(const Data& d1, const Data& d2)
{
    if (d1.inside_data.size() != d2.inside_data.size())
    {
        return false;
    }
    else
    {
        auto it1 = d1.inside_data.begin();
        auto it2 = d2.inside_data.begin();
        while (true)
        {
            if (*it1 != *it2)
            {
                return false;
            }
            else
            {
                it1++;
                it2++;
            }
        }
        return true;
    }
}
bool DogData::operator==(const Data d1, const Data& d2)
{
    if (d1.inside_data.size() != d2.inside_data.size())
    {
        return false;
    }
    else
    {
        auto it1 = d1.inside_data.begin();
        auto it2 = d2.inside_data.begin();
        while (true)
        {
            if (*it1 != *it2)
            {
                return false;
            }
            else
            {
                it1++;
                it2++;
            }
        }
        return true;
    }
}
bool DogData::operator==(const Data& d1, const Data d2)
{
    if (d1.inside_data.size() != d2.inside_data.size())
    {
        return false;
    }
    else
    {
        auto it1 = d1.inside_data.begin();
        auto it2 = d2.inside_data.begin();
        while (true)
        {
            if (*it1 != *it2)
            {
                return false;
            }
            else
            {
                it1++;
                it2++;
            }
        }
        return true;
    }
}
*/
dog_torch::serialize::Data dog_torch::serialize::operator&(const Data d1, const Data d2)
{
    if (d1.size() != d2.size())
    {
        throw dog_torch::utils::Exception(DOG_EXCEPTION_MSG_OPINION("Error:the size of two Datas must be equal when ther AND each other\n错误：按位与操作的Data长度必须相等"));
    }
    dog_torch::serialize::Data res; res.reserve(d1.size());
    for (uint64_t i = 0; i < d1.size(); i++)
    {
        res.push_back(d1[i] & d2[i]);
    }
    return res;

}
dog_torch::serialize::Data dog_torch::serialize::operator|(const Data d1, const Data d2)
{
    if (d1.size() != d2.size())
    {
        throw dog_torch::utils::Exception(DOG_EXCEPTION_MSG_OPINION("Error:the size of two Datas must be equal when ther OR each other\n错误：按位与操作的Data长度必须相等"));
    }
    dog_torch::serialize::Data res; res.reserve(d1.size());
    for (uint64_t i = 0; i < d1.size(); i++)
    {
        res.push_back(d1[i] | d2[i]);
    }
    return res;

}
dog_torch::serialize::Data dog_torch::serialize::operator^(const Data d1, const Data d2)
{
    if (d1.size() != d2.size())
    {
        throw dog_torch::utils::Exception(DOG_EXCEPTION_MSG_OPINION("Error:the size of two Datas must be equal when ther XOR each other\n错误：按位与操作的Data长度必须相等"));
    }
    dog_torch::serialize::Data res; res.reserve(d1.size());
    for (uint64_t i = 0; i < d1.size(); i++)
    {
        res.push_back(d1[i] ^ d2[i]);
    }
    return res;
}
bool dog_torch::serialize::operator==(const Data d1, const Data d2)
{
    if (d1.inside_data.size() != d2.inside_data.size())
    {
        return false;
    }
    else
    {
        auto it1 = d1.cbegin();
        auto it2 = d2.cbegin();
        while (true)
        {
            if(it1 == d1.cend() || it2 == d2.cend())
            {
                break;
            }
            else if (*it1 != *it2)
            {
                return false;
            }
            else
            {
                it1++;
                it2++;
            }
        }
        return true;
    }
}
/*
bool DogData::operator!=(const Data& d1, const Data& d2)
{
    if (d1.inside_data.size() != d2.inside_data.size())
    {
        return true;
    }
    else
    {
        auto it1 = d1.inside_data.begin();
        auto it2 = d2.inside_data.begin();
        while (true)
        {
            if (*it1 != *it2)
            {
                return true;
            }
            else
            {
                it1++;
                it2++;
            }
        }
        return false;
    }
}
bool DogData::operator!=(const Data d1, const Data& d2)
{
    if (d1.inside_data.size() != d2.inside_data.size())
    {
        return true;
    }
    else
    {
        auto it1 = d1.inside_data.begin();
        auto it2 = d2.inside_data.begin();
        while (true)
        {
            if (*it1 != *it2)
            {
                return true;
            }
            else
            {
                it1++;
                it2++;
            }
        }
        return false;
    }
}
bool DogData::operator!=(const Data& d1, const Data d2)
{
    if (d1.inside_data.size() != d2.inside_data.size())
    {
        return true;
    }
    else
    {
        auto it1 = d1.inside_data.begin();
        auto it2 = d2.inside_data.begin();
        while (true)
        {
            if (*it1 != *it2)
            {
                return true;
            }
            else
            {
                it1++;
                it2++;
            }
        }
        return false;
    }
}
*/
bool dog_torch::serialize::operator!=(const Data d1, const Data d2)
{
    if (d1.inside_data.size() != d2.inside_data.size())
    {
        return true;
    }
    else
    {
        auto it1 = d1.inside_data.begin();
        auto it2 = d2.inside_data.begin();
        while (true)
        {
            if (it1 == d1.cend() || it2 == d2.cend())
            {
                break;
            }
            if (*it1 != *it2)
            {
                return true;
            }
            else
            {
                it1++;
                it2++;
            }
        }
        return false;
    }
}
void dog_torch::serialize::operator+=(Data& d1, const Data& d2)
{
    for (uint8_t i : d2.inside_data)
    {
        d1.inside_data.push_back(i);
    }
}
dog_torch::serialize::Data dog_torch::serialize::operator+(const Data& a, const Data b)
{
    dog_torch::serialize::Data res; res.reserve(a.size() + b.size());
    for (auto it = a.cbegin(); it != a.cend(); ++it)
    {
        res.push_back(*it);
    }
    for (auto it = b.cbegin(); it != b.cend(); ++it)
    {
        res.push_back(*it);
    }
    return res;
}

dog_torch::serialize::Data dog_torch::serialize::operator""_DogHexData(const char* str, size_t len)
{
    return Data(str, 2);
}

dog_torch::serialize::DataStream::DataStream(dog_torch::serialize::Data& data)
{
    this->data_ = data;
}
uint8_t* dog_torch::serialize::DataStream::data()
{
    return (uint8_t*)this->data_.data();
}
uint8_t dog_torch::serialize::DataStream::get()
{
    uint8_t res = data_[pos_];
    pos_++;
    return res;
}
uint8_t dog_torch::serialize::DataStream::peek()
{
    return data_[pos_];
}
void dog_torch::serialize::DataStream::unget()
{
    pos_--;
}
uint64_t dog_torch::serialize::DataStream::tellg() const
{
    return this->pos_;
}

std::string dog_torch::serialize::utf8::to_utf8(uint64_t code)
{
    std::string result = "";
    if (code <= 0x7F)
    {
        result += (char)code;
    }
    else if (code <= 0x7FF)
    {
        result += (char)(0b11000000 | ((code >> 06) & 0x1F));
        result += (char)(0b10000000 | ((code >> 00) & 0x3F));
    }
    else if (code <= 0xFFFF)
    {
        result += (char)(0b11100000 | ((code >> 12) & 0x0F));
        result += (char)(0b10000000 | ((code >> 06) & 0x3F));
        result += (char)(0b10000000 | ((code >> 00) & 0x3F));
    }
    else if (code <= 0x1FFFFF)
    {
        result += (char)(0b11110000 | ((code >> 18) & 0x07));
        result += (char)(0b10000000 | ((code >> 12) & 0x3F));
        result += (char)(0b10000000 | ((code >> 06) & 0x3F));
        result += (char)(0b10000000 | ((code >> 00) & 0x3F));
    }
    else if (code <= 0x3FFFFFF)
    {
        result += (char)(0b11111000 | ((code >> 24) & 0x03));
        result += (char)(0b10000000 | ((code >> 18) & 0x3F));
        result += (char)(0b10000000 | ((code >> 12) & 0x3F));
        result += (char)(0b10000000 | ((code >> 06) & 0x3F));
        result += (char)(0b10000000 | ((code >> 00) & 0x3F));
    }
    else if (code <= 0x7FFFFFFF)
    {
        result += (char)(0b11111100 | ((code >> 30) & 0x01));
        result += (char)(0b10000000 | ((code >> 24) & 0x3F));
        result += (char)(0b10000000 | ((code >> 18) & 0x3F));
        result += (char)(0b10000000 | ((code >> 12) & 0x3F));
        result += (char)(0b10000000 | ((code >> 06) & 0x3F));
        result += (char)(0b10000000 | ((code >> 00) & 0x3F));
    }
    return result;
}
uint64_t dog_torch::serialize::utf8::utf8_size(std::string str)
{
    uint64_t size = 0;
    for (auto it = str.begin(); it != str.end();)
    {
        if ((uint64_t)*it < 0x80)
        {
            size += 1;
            it++;
        }
        else
        {
            uint8_t sign = *it;
            while ((sign & 0x80) == 0x80)
            {
                it++;
                sign <<= 1;
            }
            size++;
        }
    }
    return size;
}
uint64_t dog_torch::serialize::utf8::utf8_size(const char* str)
{
    return dog_torch::serialize::utf8::utf8_size(std::string(str));
}
std::string dog_torch::serialize::utf8::get_utf8_char(std::string str, uint64_t offset)
{
    uint64_t size = 0;
    std::string value = "";
    for (auto it = str.begin(); it != str.end();)
    {
        if (size != offset)
        {
            if ((uint64_t)*it < 0x80)
            {
                size += 1;
                it++;
            }
            else
            {
                uint8_t sign = *it;
                while ((sign & 0x80) == 0x80)
                {
                    it++;
                    sign <<= 1;
                }
                size++;
            }
        }
        else
        {
            if ((uint64_t)*it < 0x80)
            {
                value += *it;
                return value;
            }
            else
            {
                uint8_t sign = *it;
                while ((sign & 0x80) == 0x80)
                {
                    value += *it;
                    it++;
                    sign <<= 1;
                }
                return value;
            }
        }
    }
    throw DOG_EXCEPTION("Error:out of offset\n错误：偏移量超出范围");
}
std::string dog_torch::serialize::utf8::get_utf8_char(const char* str, uint64_t offset)
{
    return dog_torch::serialize::utf8::get_utf8_char(std::string(str), offset);
}