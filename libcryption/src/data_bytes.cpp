#include "../include/cryption/data_bytes.h"

DogException::DogException(const char* msg, const char* file, const char* function, uint64_t line)
{
    this->msg = std::format("{}:{}\n at {}({}:{})", typeid(*this).name(), msg, function, file, line);
}
const char* DogException::what() const throw()
{
    return this->msg.c_str();
}

dog_data::Data::Data(std::string str, const int type)
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
dog_data::Data::Data(uint64_t size)
{
    this->inside_data.resize(size);
}
dog_data::Data::Data(const Data& other)
{
    this->inside_data = other.inside_data;
    //printf("copy data %lld=>%lld\n", (uint64_t)&other, (uint64_t)this);
}
void dog_data::Data::operator=(const Data& other)
{
    this->inside_data = other.inside_data;
    //printf("copy data %lld=>%lld\n", (uint64_t)&other, (uint64_t)this);
}
dog_data::Data::Data(Data&& other) noexcept
{
    this->inside_data = std::move(other.inside_data);
    //printf("move data %lld->%lld\n", (uint64_t)&other, (uint64_t)this);
}
dog_data::Data::~Data()
{
    //printf("delete data %lld\n", (uint64_t)this);
}
uint8_t& dog_data::Data::at(uint64_t i)
{
    return this->inside_data.at(i);
}
uint8_t dog_data::Data::at(uint64_t i) const
{
    return this->inside_data.at(i);
}
uint8_t& dog_data::Data::operator[](uint64_t i)
{
    return this->inside_data[i];
}
uint8_t dog_data::Data::operator[](uint64_t i) const
{
    return this->inside_data[i];
}
uint8_t& dog_data::Data::front()
{
    return this->inside_data.front();
}
uint8_t& dog_data::Data::back()
{
    return this->inside_data.back();
}
uint8_t* dog_data::Data::data()
{
    return this->inside_data.data();
}
const uint8_t* dog_data::Data::data() const
{
    return this->inside_data.data();
}
std::vector<uint8_t>::iterator dog_data::Data::begin()
{
    return this->inside_data.begin();
}
std::vector<uint8_t>::iterator dog_data::Data::end()
{
    return this->inside_data.end();
}
std::vector<uint8_t>::const_iterator dog_data::Data::cbegin() const
{
    return this->inside_data.cbegin();
}
std::vector<uint8_t>::const_iterator dog_data::Data::cend() const
{
    return this->inside_data.cend();
}
std::reverse_iterator<std::vector<uint8_t>::iterator> dog_data::Data::rbegin()
{
    return this->inside_data.rbegin();
}
std::reverse_iterator<std::vector<uint8_t>::iterator> dog_data::Data::rend()
{
    return this->inside_data.rend();
}
std::reverse_iterator<std::vector<uint8_t>::const_iterator> dog_data::Data::crbegin() const
{
    return this->inside_data.crbegin();
}
std::reverse_iterator<std::vector<uint8_t>::const_iterator> dog_data::Data::crend() const
{
    return this->inside_data.crend();
}
std::vector<char> dog_data::Data::getUTF8Vector()
{
    std::vector<char> res(this->inside_data.size());
    for (int i = 0; i < this->inside_data.size(); i++)
    {
        res[i] = this->inside_data[i];
    }
    return res;
}
std::vector<char> dog_data::Data::getBase64Vector()
{
    return this->getBase64Vector('+', '/', '=');
}
std::vector<char> dog_data::Data::getBase64Vector(char a, char b)
{
    return this->getBase64Vector(a, b, '=');
}
std::vector<char> dog_data::Data::getBase64Vector(char a, char b, char c)
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
std::vector<char> dog_data::Data::getHexVector(bool is_upper)
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
std::string dog_data::Data::getUTF8String()
{
    std::vector<char> res = this->getUTF8Vector();
    return std::string(res.begin(), res.end());
}
std::string dog_data::Data::getBase64String()
{
    std::vector<char> res = this->getBase64Vector();
    return std::string(res.begin(), res.end());
}
std::string dog_data::Data::getBase64String(char a, char b)
{
    std::vector<char> res = this->getBase64Vector(a, b);
    return std::string(res.begin(), res.end());
}
std::string dog_data::Data::getBase64String(char a, char b, char c)
{
    std::vector<char> res = this->getBase64Vector(a, b, c);
    return std::string(res.begin(), res.end());
}
std::string dog_data::Data::getHexString(bool is_upper)
{
    std::vector<char> res = this->getHexVector(is_upper);
    return std::string(res.begin(), res.end());
}
dog_data::Data dog_data::Data::sub_by_pos(uint64_t start, uint64_t end) const
{
    uint64_t size = end - start;
    uint64_t max_size = this->inside_data.size();
    dog_data::Data res; res.reserve(size);
    for (uint64_t i = start; i < end && i < max_size; i++)
    {
        res.push_back(this->inside_data[i]);
    }
    return res;
}
dog_data::Data dog_data::Data::sub_by_len(uint64_t start, uint64_t len) const
{
    uint64_t end = start + len;
    uint64_t max_size = this->inside_data.size();
    dog_data::Data res; res.reserve(len);
    for (uint64_t i = start; i < end && i < max_size; i++)
    {
        res.push_back(this->inside_data[i]);
    }
    return res;
}
dog_data::Data dog_data::Data::sub_by_pos(std::vector<uint8_t>::iterator start, std::vector<uint8_t>::iterator end) const
{
    uint64_t size = end - start;
    dog_data::Data res; res.reserve(size);
    for (std::vector<uint8_t>::iterator i = start; i != end; i++)
    {
        res.push_back(*i);
    }
    return res;
}
dog_data::Data dog_data::Data::sub_by_len(std::vector<uint8_t>::iterator start, uint64_t len) const
{
    std::vector<uint8_t>::iterator end = start + len;
    dog_data::Data res; res.reserve(len);
    for (std::vector<uint8_t>::iterator i = start; i != end; i++)
    {
        res.push_back(*i);
    }
    return res;
}
bool dog_data::Data::empty() const
{
    return this->inside_data.empty();
}
uint64_t dog_data::Data::size() const
{
    return this->inside_data.size();
}
uint64_t dog_data::Data::max_size() const
{
    return this->inside_data.max_size();
}
void dog_data::Data::reserve(uint64_t n)
{
    return this->inside_data.reserve(n);
}
void dog_data::Data::insert(const uint64_t i, uint8_t b)
{
    this->inside_data.insert(this->inside_data.begin() + i, b);
}
void dog_data::Data::insert(const std::vector<uint8_t>::iterator pos, uint8_t b)
{
    this->inside_data.insert(pos, b);
}
void dog_data::Data::erase(const uint64_t i)
{
    this->inside_data.erase(this->inside_data.begin() + i);
}
void dog_data::Data::erase(const std::vector<uint8_t>::iterator pos)
{
    this->inside_data.erase(pos);
}
void dog_data::Data::clear_leave_pos()
{
    this->inside_data.clear();
}
void dog_data::Data::clear_set_zero()
{
    for (auto it = this->inside_data.begin(); it != this->inside_data.end(); it++)
    {
        *it = '\0';
    }
}
void dog_data::Data::push_back(uint8_t b)
{
    this->inside_data.push_back(b);
}
void dog_data::Data::pop_back()
{
    this->inside_data.pop_back();
}
void dog_data::Data::reverse()
{
    for (uint64_t i = 0; i < this->size() / 2; i++)
    {
        std::swap(this->inside_data[i], this->inside_data[this->size() - i - 1]);
    }
}
void dog_data::Data::swap(Data& d)
{
    this->inside_data.swap(d.inside_data);
}
void dog_data::Data::swap(Data d)
{
    this->inside_data.swap(d.inside_data);
}
dog_data::Data dog_data::Data::bit_left_move_norise(uint64_t shift)
{
    dog_data::Data res; res.reserve(this->size());
    dog_data::Data mid;
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
void dog_data::Data::bit_left_move_norise_self(uint64_t shift)
{
    dog_data::Data mid;
    uint64_t byte_shift = shift / 8;
    uint64_t bit_shift = shift % 8;
    uint8_t last = 0;
    if (byte_shift > this->size())
    {
        this->clear_set_zero();
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
    this->clear_leave_pos();
    for (auto rit = mid.crbegin(); rit != mid.crend(); rit++)
    {
        this->insert(this->begin(), *rit << bit_shift | last);
        last = *rit >> (8 - bit_shift);
    }
}
dog_data::Data dog_data::Data::bit_left_move_rise(uint64_t shift)
{
    dog_data::Data res; res.reserve(this->size());
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
void dog_data::Data::bit_left_move_rise_self(uint64_t shift)
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
dog_data::Data dog_data::Data::bit_right_move_norise(uint64_t shift)
{
    dog_data::Data res; res.reserve(this->size());
    dog_data::Data mid;
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
void dog_data::Data::bit_right_move_norise_self(uint64_t shift)
{
    dog_data::Data mid;
    uint64_t byte_shift = shift / 8;
    uint64_t bit_shift = shift % 8;
    uint8_t last = 0;
    if (byte_shift > this->size())
    {
        this->clear_set_zero();
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
    this->clear_leave_pos();
    for (auto it = mid.cbegin(); it != mid.cend(); it++)
    {
        this->push_back(*it >> bit_shift | last);
        last = *it << (8 - bit_shift);
    }
}
dog_data::Data dog_data::Data::bit_right_move_rise(uint64_t shift)
{
    dog_data::Data res; res.reserve(this->size());
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
void dog_data::Data::bit_right_move_rise_self(uint64_t shift)
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
dog_data::Data dog_data::Data::bit_circle_left_move(uint64_t shift)
{
    return this->bit_left_move_norise(shift) | this->bit_right_move_norise(this->size() * 8 - shift);
}
dog_data::Data dog_data::Data::bit_circle_right_move(uint64_t shift)
{
    return this->bit_right_move_norise(shift) | this->bit_left_move_norise(this->size() * 8 - shift);
}
dog_data::Data dog_data::Data::operator~()
{
    dog_data::Data res;
    for (auto it = this->cbegin(); it != this->cend(); it++)
    {
        res.push_back(~(*it));
    }
    return res;
}
bool dog_data::Data::is_equal(const Data& d2) const
{
    return *this == d2;
}
dog_data::Data dog_data::Data::concat(const Data& b) const
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
dog_data::Data dog_data::operator&(const Data d1, const Data d2)
{
    if (d1.size() != d2.size())
    {
        throw DogException("the size must be equal when AND", __FILE__, __FUNCTION__, __LINE__);
    }
    dog_data::Data res; res.reserve(d1.size());
    for (uint64_t i = 0; i < d1.size(); i++)
    {
        res.push_back(d1[i] & d2[i]);
    }
    return res;

}
dog_data::Data dog_data::operator|(const Data d1, const Data d2)
{
    if (d1.size() != d2.size())
    {
        throw DogException("the size must be equal when OR", __FILE__, __FUNCTION__, __LINE__);
    }
    dog_data::Data res; res.reserve(d1.size());
    for (uint64_t i = 0; i < d1.size(); i++)
    {
        res.push_back(d1[i] | d2[i]);
    }
    return res;

}
dog_data::Data dog_data::operator^(const Data d1, const Data d2)
{
    if (d1.size() != d2.size())
    {
        throw DogException("the size must be equal when OR", __FILE__, __FUNCTION__, __LINE__);
    }
    dog_data::Data res; res.reserve(d1.size());
    for (uint64_t i = 0; i < d1.size(); i++)
    {
        res.push_back(d1[i] ^ d2[i]);
    }
    return res;
}
bool dog_data::operator==(const Data d1, const Data d2)
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
bool dog_data::operator!=(const Data d1, const Data d2)
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
void dog_data::operator+=(Data& d1, const Data& d2)
{
    for (uint8_t i : d2.inside_data)
    {
        d1.inside_data.push_back(i);
    }
}
dog_data::Data dog_data::operator+(const Data& a, const Data b)
{
    dog_data::Data res; res.reserve(a.size() + b.size());
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
void dog_data::print::block(dog_data::Data data, uint64_t column)
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
void dog_data::print::space(dog_data::Data data, uint64_t column)
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

dog_data::DataStream::DataStream(dog_data::Data& data)
{
    this->data_ = data;
}
uint8_t* dog_data::DataStream::data()
{
    return (uint8_t*)this->data_.data();
}
uint8_t dog_data::DataStream::get()
{
    uint8_t res = data_[pos_];
    pos_++;
    return res;
}
uint8_t dog_data::DataStream::peek()
{
    return data_[pos_];
}
void dog_data::DataStream::unget()
{
    pos_--;
}
uint64_t dog_data::DataStream::tellg() const
{
    return this->pos_;
}

dog_data::Data dog_data::serialize::boolean(bool b)
{
    dog_data::Data res(1);
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
dog_data::Data dog_data::serialize::integer_num(uint64_t num)
{
    //int   -> 100 (0/1=+/-) 0001-1000(0-8):length
    dog_data::Data res(1);
    uint8_t az = dog_number::integer::available_size(num);
    uint8_t sign = 0x80 | az;
    res[0] = sign;
    for (uint8_t i = 0; i < az; ++i)
    {
        res.push_back(dog_number::integer::pick_byte(num, az - i));
    }
    return res;
}
dog_data::Data dog_data::serialize::integer_num(int64_t num)
{
    //int   -> 100 (0/1=+/-) 0001-1000(0-8):length
    if (num >= 0)
    {
        return dog_data::serialize::integer_num((uint64_t)num);
    }
    dog_data::Data res(1);
    uint64_t num_ = (uint64_t)(-num);
    uint8_t az = dog_number::integer::available_size(num_);
    uint8_t sign = 0x90 | az;
    res[0] = sign;
    for (uint8_t i = 0; i < az; ++i)
    {
        res.push_back(dog_number::integer::pick_byte(num_, az - i));
    }
    return res;
}
dog_data::Data dog_data::serialize::float_num(float num)
{
    //float  -> 101X (4/8=float/double)
    dog_data::Data res(5);
    res[0] = 0b10100100;
    memcpy(res.data() + 1, &num, sizeof(float));
    return res;
}
dog_data::Data dog_data::serialize::float_num(double num)
{
    //float  -> 101X (4/8=float/double)
    dog_data::Data res(9);
    res[0] = 0b10101000;
    memcpy(res.data() + 1, &num, sizeof(double));
    return res;
}
dog_data::Data dog_data::serialize::bytes(const std::vector<uint8_t>& bytes)
{
    dog_data::Data res(1);
    uint64_t len = bytes.size();
    uint8_t az = dog_number::integer::available_size(len);
    uint8_t sign = 0x40 | az;
    for (uint8_t i = 0; i < az; ++i)
    {
        res.push_back(dog_number::integer::pick_byte(len, az - i));
    }
    for (uint64_t i = 0; i < len; ++i)
    {
        res.push_back(bytes[i]);
    }
    return res;
}
dog_data::Data dog_data::serialize::bytes(const uint8_t* bytes, uint64_t size)
{
    dog_data::Data res(1);
    uint64_t len = size;
    uint8_t az = dog_number::integer::available_size(len);
    uint8_t sign = 0x40 | az;
    for (uint8_t i = 0; i < az; ++i)
    {
        res.push_back(dog_number::integer::pick_byte(len, az - i));
    }
    for (uint64_t i = 0; i < len; ++i)
    {
        res.push_back(bytes[i]);
    }
    return res;
}
dog_data::Data dog_data::serialize::bytes(std::istream& stream)
{
    dog_data::Data res(1);
    stream.seekg(0, std::ios::end);
    uint64_t len = stream.tellg();
    stream.seekg(0, std::ios::beg);
    uint8_t az = dog_number::integer::available_size(len);
    uint8_t sign = 0x40 | az;
    for (uint8_t i = 0; i < az; ++i)
    {
        res.push_back(dog_number::integer::pick_byte(len, az - i));
    }
    for (uint64_t i = 0; i < len; ++i)
    {
        res.push_back(stream.get());
    }
    return res;
}
dog_data::Data dog_data::serialize::string(const char* str)
{
    //string  -> 01XX 0000-1000(0-8):length length + int(length) + bytes(utf8)
    dog_data::Data res(1);
    uint64_t len = strlen(str);
    uint8_t az = dog_number::integer::available_size(len);
    uint8_t sign = 0x60 | az;
    res[0] = sign;
    for (uint8_t i = 0; i < az; ++i)
    {
        res.push_back(dog_number::integer::pick_byte(len, az - i));
    }
    for (uint64_t i = 0; i < len; ++i)
    {
        res.push_back(str[i]);
    }
    return res;
}
dog_data::Data dog_data::serialize::string(std::string str)
{
    //string  -> 01XX 0000-1000(0-8):length length + int(length) + bytes(utf8)
    dog_data::Data res(1);
    uint64_t len = str.length();
    uint8_t az = dog_number::integer::available_size(len);
    uint8_t sign = 0x60 | az;
    res[0] = sign;
    for (uint8_t i = 0; i < az; ++i)
    {
        res.push_back(dog_number::integer::pick_byte(len, az - i));
    }
    for (uint64_t i = 0; i < len; ++i)
    {
        res.push_back(str[i]);
    }
    return res;
}
dog_data::Data dog_data::serialize::array(const std::vector<std::any>& arr)
{
    //array  -> 110X 0000-1000(0-8):length length + int(length) + other
    dog_data::Data res(1);
    uint64_t len = arr.size();
    uint8_t az = dog_number::integer::available_size(len);
    uint8_t sign = 0xC0 | az;
    res[0] = sign;
    for (uint8_t i = 0; i < az; ++i)
    {
        res.push_back(dog_number::integer::pick_byte(len, az - i));
    }
    for (auto& item : arr)
    {
        dog_data::Data single;
        if (item.type() == typeid(bool))
        {
            single = dog_data::serialize::boolean(std::any_cast<bool>(item));
        }
        else if (item.type() == typeid(uint64_t))
        {
            single = dog_data::serialize::integer_num(std::any_cast<uint64_t>(item));
        }
        else if (item.type() == typeid(uint32_t))
        {
            single = dog_data::serialize::integer_num((uint64_t)(std::any_cast<uint32_t>(item)));
        }
        else if (item.type() == typeid(uint16_t))
        {
            single = dog_data::serialize::integer_num((uint64_t)(std::any_cast<uint16_t>(item)));
        }
        else if (item.type() == typeid(uint8_t))
        {
            single = dog_data::serialize::integer_num((uint64_t)(std::any_cast<uint8_t>(item)));
        }
        else if (item.type() == typeid(int64_t))
        {
            single = dog_data::serialize::integer_num((std::any_cast<int64_t>(item)));
        }
        else if (item.type() == typeid(int32_t))
        {
            single = dog_data::serialize::integer_num((int64_t)(std::any_cast<int32_t>(item)));
        }
        else if (item.type() == typeid(int16_t))
        {
            single = dog_data::serialize::integer_num((int64_t)(std::any_cast<int16_t>(item)));
        }
        else if (item.type() == typeid(int8_t))
        {
            single = dog_data::serialize::integer_num((int64_t)(std::any_cast<int8_t>(item)));
        }
        else if (item.type() == typeid(float))
        {
            single = dog_data::serialize::float_num(std::any_cast<float>(item));
        }
        else if (item.type() == typeid(double))
        {
            single = dog_data::serialize::float_num(std::any_cast<double>(item));
        }
        else if (item.type() == typeid(std::string))
        {
            single = dog_data::serialize::string(std::any_cast<std::string>(item));
        }
        else if (item.type() == typeid(const char*))
        {
            single = dog_data::serialize::string(std::any_cast<const char*>(item));
        }
        else if (item.type() == typeid(std::vector<std::any>))
        {
            single = dog_data::serialize::array(std::any_cast<std::vector<std::any>>(item));
        }
        else if (item.type() == typeid(std::unordered_map<std::string, std::any>))
        {
            single = dog_data::serialize::object(std::any_cast<std::unordered_map<std::string, std::any>>(item));
        }
        else if (item.type() == typeid(std::map<std::string, std::any>))
        {
            single = dog_data::serialize::object(std::any_cast<std::map<std::string, std::any>>(item));
        }
        res += single;
    }
    return res;
}
dog_data::Data dog_data::serialize::object(const std::unordered_map<std::string, std::any>& obj)
{
    dog_data::Data res(1);
    uint64_t len = obj.size();
    uint8_t az = dog_number::integer::available_size(len);
    uint8_t sign = 0xE0 | az;
    res[0] = sign;
    for (uint8_t i = 0; i < az; ++i)
    {
        res.push_back(dog_number::integer::pick_byte(len, az - i));
    }
    for (auto& item_value : obj)
    {
        dog_data::Data single;
        std::string key = item_value.first;
        single = dog_data::serialize::string(std::any_cast<std::string>(key));
        res += single;
        std::any item = item_value.second;
        if (item.type() == typeid(bool))
        {
            single = dog_data::serialize::boolean(std::any_cast<bool>(item));
        }
        else if (item.type() == typeid(uint64_t))
        {
            single = dog_data::serialize::integer_num(std::any_cast<uint64_t>(item));
        }
        else if (item.type() == typeid(uint32_t))
        {
            single = dog_data::serialize::integer_num((uint64_t)(std::any_cast<uint32_t>(item)));
        }
        else if (item.type() == typeid(uint16_t))
        {
            single = dog_data::serialize::integer_num((uint64_t)(std::any_cast<uint16_t>(item)));
        }
        else if (item.type() == typeid(uint8_t))
        {
            single = dog_data::serialize::integer_num((uint64_t)(std::any_cast<uint8_t>(item)));
        }
        else if (item.type() == typeid(int64_t))
        {
            single = dog_data::serialize::integer_num((std::any_cast<int64_t>(item)));
        }
        else if (item.type() == typeid(int32_t))
        {
            single = dog_data::serialize::integer_num((int64_t)(std::any_cast<int32_t>(item)));
        }
        else if (item.type() == typeid(int16_t))
        {
            single = dog_data::serialize::integer_num((int64_t)(std::any_cast<int16_t>(item)));
        }
        else if (item.type() == typeid(int8_t))
        {
            single = dog_data::serialize::integer_num((int64_t)(std::any_cast<int8_t>(item)));
        }
        else if (item.type() == typeid(float))
        {
            single = dog_data::serialize::float_num(std::any_cast<float>(item));
        }
        else if (item.type() == typeid(double))
        {
            single = dog_data::serialize::float_num(std::any_cast<double>(item));
        }
        else if (item.type() == typeid(std::string))
        {
            single = dog_data::serialize::string(std::any_cast<std::string>(item));
        }
        else if (item.type() == typeid(const char*))
        {
            single = dog_data::serialize::string(std::any_cast<const char*>(item));
        }
        else if (item.type() == typeid(std::vector<std::any>))
        {
            single = dog_data::serialize::array(std::any_cast<std::vector<std::any>>(item));
        }
        else if (item.type() == typeid(std::unordered_map<std::string, std::any>))
        {
            single = dog_data::serialize::object(std::any_cast<std::unordered_map<std::string, std::any>>(item));
        }
        else if (item.type() == typeid(std::map<std::string, std::any>))
        {
            single = dog_data::serialize::object(std::any_cast<std::map<std::string, std::any>>(item));
        }
        res += single;
    }
    return res;
}
dog_data::Data dog_data::serialize::object(const std::map<std::string, std::any>& obj)
{
    dog_data::Data res(1);
    uint64_t len = obj.size();
    uint8_t az = dog_number::integer::available_size(len);
    uint8_t sign = 0xE0 | az;
    res[0] = sign;
    for (uint8_t i = 0; i < az; ++i)
    {
        res.push_back(dog_number::integer::pick_byte(len, az - i));
    }
    for (auto& item_value : obj)
    {
        dog_data::Data single;
        std::string key = item_value.first;
        single = dog_data::serialize::string(std::any_cast<std::string>(key));
        res += single;
        std::any item = item_value.second;
        if (item.type() == typeid(bool))
        {
            single = dog_data::serialize::boolean(std::any_cast<bool>(item));
        }
        else if (item.type() == typeid(uint64_t))
        {
            single = dog_data::serialize::integer_num(std::any_cast<uint64_t>(item));
        }
        else if (item.type() == typeid(uint32_t))
        {
            single = dog_data::serialize::integer_num((uint64_t)(std::any_cast<uint32_t>(item)));
        }
        else if (item.type() == typeid(uint16_t))
        {
            single = dog_data::serialize::integer_num((uint64_t)(std::any_cast<uint16_t>(item)));
        }
        else if (item.type() == typeid(uint8_t))
        {
            single = dog_data::serialize::integer_num((uint64_t)(std::any_cast<uint8_t>(item)));
        }
        else if (item.type() == typeid(int64_t))
        {
            single = dog_data::serialize::integer_num((std::any_cast<int64_t>(item)));
        }
        else if (item.type() == typeid(int32_t))
        {
            single = dog_data::serialize::integer_num((int64_t)(std::any_cast<int32_t>(item)));
        }
        else if (item.type() == typeid(int16_t))
        {
            single = dog_data::serialize::integer_num((int64_t)(std::any_cast<int16_t>(item)));
        }
        else if (item.type() == typeid(int8_t))
        {
            single = dog_data::serialize::integer_num((int64_t)(std::any_cast<int8_t>(item)));
        }
        else if (item.type() == typeid(float))
        {
            single = dog_data::serialize::float_num(std::any_cast<float>(item));
        }
        else if (item.type() == typeid(double))
        {
            single = dog_data::serialize::float_num(std::any_cast<double>(item));
        }
        else if (item.type() == typeid(std::string))
        {
            single = dog_data::serialize::string(std::any_cast<std::string>(item));
        }
        else if (item.type() == typeid(const char*))
        {
            single = dog_data::serialize::string(std::any_cast<const char*>(item));
        }
        else if (item.type() == typeid(std::vector<std::any>))
        {
            single = dog_data::serialize::array(std::any_cast<std::vector<std::any>>(item));
        }
        else if (item.type() == typeid(std::unordered_map<std::string, std::any>))
        {
            single = dog_data::serialize::object(std::any_cast<std::unordered_map<std::string, std::any>>(item));
        }
        else if (item.type() == typeid(std::map<std::string, std::any>))
        {
            single = dog_data::serialize::object(std::any_cast<std::map<std::string, std::any>>(item));
        }
        res += single;
    }
    return res;
}


std::any dog_data::serialize::read(dog_data::Data data)
{
    dog_data::DataStream stream(data);
    return read(stream);
}
std::any dog_data::serialize::read(std::istream& data)
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
            value.push_back(read(data));
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
            std::any key = read(data);
            std::any value = read(data);
            std::string key_str = std::any_cast<std::string>(key);
            res[key_str] = value;
        }
        return res;
    }
}
std::any dog_data::serialize::read(dog_data::DataStream& data)
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
            value.push_back(read(data));
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
            std::any key = read(data);
            std::any value = read(data);
            std::string key_str = std::any_cast<std::string>(key);
            res[key_str] = value;
        }
        return res;
    }
}



