#include "serialize/BinaryData.h"

#define NSROOT dog_torch::serialize
#define DOG_ERROR_SIZE_NO_EQUAL "Error:BinaryData size not equal"
#define DOG_ERROR_OUT_OF_OFFSET "Error:out of offset"

NSROOT::BinaryData::BinaryData(std::string str, const int type)
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
NSROOT::BinaryData::BinaryData(const std::vector<uint8_t>& data)
{
    this->inside_data.reserve(data.size());
    for (auto& i : data)
    {
        this->inside_data.push_back(i);
    }
}
NSROOT::BinaryData::BinaryData(uint64_t size)
{
    this->inside_data.resize(size);
}
NSROOT::BinaryData::BinaryData(const BinaryData& other)
{
    this->inside_data = other.inside_data;
    //printf("copy data %lld=>%lld\n", (uint64_t)&other, (uint64_t)this);
}
void NSROOT::BinaryData::operator=(const BinaryData& other)
{
    this->inside_data = other.inside_data;
    //printf("copy data %lld=>%lld\n", (uint64_t)&other, (uint64_t)this);
}
NSROOT::BinaryData::BinaryData(BinaryData&& other) noexcept
{
    this->inside_data = std::move(other.inside_data);
    //printf("move data %lld->%lld\n", (uint64_t)&other, (uint64_t)this);
}
NSROOT::BinaryData::~BinaryData()
{
    //printf("delete data %lld\n", (uint64_t)this);
}
uint8_t& NSROOT::BinaryData::at(uint64_t i)
{
    return this->inside_data.at(i);
}
uint8_t NSROOT::BinaryData::at(uint64_t i) const
{
    return this->inside_data.at(i);
}
uint8_t& NSROOT::BinaryData::operator[](uint64_t i)
{
    return this->inside_data[i];
}
uint8_t NSROOT::BinaryData::operator[](uint64_t i) const
{
    return this->inside_data[i];
}
uint8_t& NSROOT::BinaryData::front()
{
    return this->inside_data.front();
}
uint8_t& NSROOT::BinaryData::back()
{
    return this->inside_data.back();
}
uint8_t* NSROOT::BinaryData::data()
{
    return this->inside_data.data();
}
const uint8_t* NSROOT::BinaryData::data() const
{
    return this->inside_data.data();
}
std::vector<uint8_t>::iterator NSROOT::BinaryData::begin()
{
    return this->inside_data.begin();
}
std::vector<uint8_t>::iterator NSROOT::BinaryData::end()
{
    return this->inside_data.end();
}
std::vector<uint8_t>::const_iterator NSROOT::BinaryData::cbegin() const
{
    return this->inside_data.cbegin();
}
std::vector<uint8_t>::const_iterator NSROOT::BinaryData::cend() const
{
    return this->inside_data.cend();
}
std::reverse_iterator<std::vector<uint8_t>::iterator> NSROOT::BinaryData::rbegin()
{
    return this->inside_data.rbegin();
}
std::reverse_iterator<std::vector<uint8_t>::iterator> NSROOT::BinaryData::rend()
{
    return this->inside_data.rend();
}
std::reverse_iterator<std::vector<uint8_t>::const_iterator> NSROOT::BinaryData::crbegin() const
{
    return this->inside_data.crbegin();
}
std::reverse_iterator<std::vector<uint8_t>::const_iterator> NSROOT::BinaryData::crend() const
{
    return this->inside_data.crend();
}
std::vector<uint8_t> NSROOT::BinaryData::to_byte_vector() const
{
    return this->inside_data;
}
std::vector<char> NSROOT::BinaryData::to_utf8_vector() const
{
    std::vector<char> res(this->inside_data.size());
    for (int i = 0; i < this->inside_data.size(); i++)
    {
        res[i] = this->inside_data[i];
    }
    return res;
}
std::vector<char> NSROOT::BinaryData::to_base64_vector() const
{
    return this->to_base64_vector('+', '/', '=');
}
std::vector<char> NSROOT::BinaryData::to_base64_vector(char a, char b) const
{
    return this->to_base64_vector(a, b, '=');
}
std::vector<char> NSROOT::BinaryData::to_base64_vector(char a, char b, char c) const
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
std::vector<char> NSROOT::BinaryData::to_hex_vector(bool is_upper) const
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
std::string NSROOT::BinaryData::to_utf8_string() const
{
    std::vector<char> res = this->to_utf8_vector();
    return std::string(res.begin(), res.end());
}
std::string NSROOT::BinaryData::to_base64_string() const
{
    std::vector<char> res = this->to_base64_vector();
    return std::string(res.begin(), res.end());
}
std::string NSROOT::BinaryData::to_base64_string(char a, char b) const
{
    std::vector<char> res = this->to_base64_vector(a, b);
    return std::string(res.begin(), res.end());
}
std::string NSROOT::BinaryData::to_base64_string(char a, char b, char c) const
{
    std::vector<char> res = this->to_base64_vector(a, b, c);
    return std::string(res.begin(), res.end());
}
std::string NSROOT::BinaryData::to_hex_string(bool is_upper) const
{
    std::vector<char> res = this->to_hex_vector(is_upper);
    return std::string(res.begin(), res.end());
}
std::string NSROOT::BinaryData::to_bin_string() const
{
    std::string res;res.reserve(this->inside_data.size() * 8);
    for (uint8_t i = 0; i < this->inside_data.size(); i++)
    {
		for (uint8_t j = 0;j < 8;j++)
        {
            res.push_back(((this->inside_data[i] >> (7 - j)) & 0x01) ? '1' : '0');
        }
    }
    return res;
}
NSROOT::BinaryData NSROOT::BinaryData::sub_bytes_by_pos(uint64_t start, uint64_t end) const
{
    uint64_t size = end - start;
    uint64_t max_size = this->inside_data.size();
    NSROOT::BinaryData res; res.reserve(size);
    for (uint64_t i = start; i < end && i < max_size; i++)
    {
        res.push_back(this->inside_data[i]);
    }
    return res;
}
NSROOT::BinaryData NSROOT::BinaryData::sub_bytes_by_len(uint64_t start, uint64_t len) const
{
    uint64_t end = start + len;
    uint64_t max_size = this->inside_data.size();
    NSROOT::BinaryData res; res.reserve(len);
    for (uint64_t i = start; i < end && i < max_size; i++)
    {
        res.push_back(this->inside_data[i]);
    }
    return res;
}
NSROOT::BinaryData NSROOT::BinaryData::sub_bytes_by_pos(std::vector<uint8_t>::iterator start, std::vector<uint8_t>::iterator end) const
{
    uint64_t size = end - start;
    NSROOT::BinaryData res; res.reserve(size);
    for (std::vector<uint8_t>::iterator i = start; i != end; i++)
    {
        res.push_back(*i);
    }
    return res;
}
NSROOT::BinaryData NSROOT::BinaryData::sub_bytes_by_len(std::vector<uint8_t>::iterator start, uint64_t len) const
{
    std::vector<uint8_t>::iterator end = start + len;
    NSROOT::BinaryData res; res.reserve(len);
    for (std::vector<uint8_t>::iterator i = start; i != end; i++)
    {
        res.push_back(*i);
    }
    return res;
}
NSROOT::BinaryData NSROOT::BinaryData::sub_bits_by_pos(uint64_t start, uint64_t start_bit_pos, uint64_t end, uint64_t end_bit_pos) const
{
    BinaryData result;
    uint64_t max_size = this->inside_data.size();
    uint8_t fill_byte = 0;
	uint8_t fill_bit_pos = 0;
    for (uint64_t i = start_bit_pos; i < 8; i++)
    {
        fill_byte |= ((this->inside_data[start] >> (7 - i)) & 0x01) << (7 - fill_bit_pos);
        fill_bit_pos++;
    }
    if (fill_bit_pos == 8)
    {
        result.push_back(fill_byte);
        fill_byte = 0;
        fill_bit_pos = 0;
    }
    uint64_t i = start + 1;
    for (; i < end && i < max_size; i++)
    {
        for (uint64_t j = 0; j < 8; j++)
        {
            fill_byte |= ((this->inside_data[i] >> (7 - j)) & 0x01) << (7 - fill_bit_pos);
            fill_bit_pos++;
            if (fill_bit_pos == 8)
            {
                result.push_back(fill_byte);
                fill_byte = 0;
                fill_bit_pos = 0;
            }   
        }
    }
    if (i == end && end != max_size)
    {
        for (uint64_t j = 0; j < end_bit_pos; j++)
        {
            fill_byte |= ((this->inside_data[end] >> (7 - j)) & 0x01) << (7 - fill_bit_pos);
            fill_bit_pos++;
            if (fill_bit_pos == 8)
            {
                result.push_back(fill_byte);
                fill_byte = 0;
                fill_bit_pos = 0;
            }
        }
    }
    if (fill_bit_pos != 0)
    {
        result.push_back(fill_byte);
    }
    return result;
}
NSROOT::BinaryData NSROOT::BinaryData::sub_bits_by_len(uint64_t start, uint64_t start_bit_pos, uint64_t len) const
{
    BinaryData result;
    uint64_t max_size = this->inside_data.size();
    uint8_t fill_byte = 0;
    uint8_t fill_bit_pos = 0;
    uint64_t now_pos = start;
	uint8_t now_bit_pos = start_bit_pos;
    for (uint64_t i = 0; i < len; i++)
    {
        fill_byte |= ((this->inside_data[now_pos] >> (7 - now_bit_pos)) & 0x01) << (7 - fill_bit_pos);
        fill_bit_pos++;
        now_bit_pos++;
        if (fill_bit_pos == 8)
        {
            result.push_back(fill_byte);
            fill_byte = 0;
            fill_bit_pos = 0;
        }
        if (now_bit_pos == 8)
        {
            now_pos++;
            now_bit_pos = 0;
        }
        if (now_pos == max_size)
        {
            break;
		}
    }
    if (fill_bit_pos != 0)
    {
        result.push_back(fill_byte);
    }
    return result;
}
NSROOT::BinaryData NSROOT::BinaryData::sub_bits_by_pos(std::vector<uint8_t>::iterator start, uint64_t start_bit_pos, std::vector<uint8_t>::iterator end, uint64_t end_bit_pos) const
{
    BinaryData result;
    uint64_t max_size = this->inside_data.size();
    uint8_t fill_byte = 0;
    uint8_t fill_bit_pos = 0;
    for (uint64_t i = start_bit_pos; i < 8; i++)
    {
        fill_byte |= ((*start >> (7 - i)) & 0x01) << (7 - fill_bit_pos);
        fill_bit_pos++;
    }
    if (fill_bit_pos == 8)
    {
        result.push_back(fill_byte);
        fill_byte = 0;
        fill_bit_pos = 0;
    }
    start++;
    for (; start < end && start < this->cend(); start++)
    {
        for (uint64_t j = 0; j < 8; j++)
        {
            fill_byte |= ((*start >> (7 - j)) & 0x01) << (7 - fill_bit_pos);
            fill_bit_pos++;
            if (fill_bit_pos == 8)
            {
                result.push_back(fill_byte);
                fill_byte = 0;
                fill_bit_pos = 0;
            }
        }
    }
    if (start == end && end != this->cend())
    {
        for (uint64_t j = 0; j < end_bit_pos; j++)
        {
            fill_byte |= ((*end >> (7 - j)) & 0x01) << (7 - fill_bit_pos);
            fill_bit_pos++;
            if (fill_bit_pos == 8)
            {
                result.push_back(fill_byte);
                fill_byte = 0;
                fill_bit_pos = 0;
            }
        }
    }
    if (fill_bit_pos != 0)
    {
        result.push_back(fill_byte);
    }
    return result;

}
NSROOT::BinaryData NSROOT::BinaryData::sub_bits_by_len(std::vector<uint8_t>::iterator start, uint64_t start_bit_pos, uint64_t len) const
{
    BinaryData result;
    uint64_t max_size = this->inside_data.size();
    uint8_t fill_byte = 0;
    uint8_t fill_bit_pos = 0;
    uint64_t now_pos = start - this->cbegin();
    uint8_t now_bit_pos = start_bit_pos;
    for (uint64_t i = 0; i < len; i++)
    {
        fill_byte |= ((this->inside_data[now_pos] >> (7 - now_bit_pos)) & 0x01) << (7 - fill_bit_pos);
        fill_bit_pos++;
        now_bit_pos++;
        if (fill_bit_pos == 8)
        {
            result.push_back(fill_byte);
            fill_byte = 0;
            fill_bit_pos = 0;
        }
        if (now_bit_pos == 8)
        {
            now_pos++;
            now_bit_pos = 0;
        }
        if (now_pos == max_size)
        {
            break;
        }
    }
    if (fill_bit_pos != 0)
    {
        result.push_back(fill_byte);
    }
    return result;
}
bool NSROOT::BinaryData::empty() const
{
    return this->inside_data.empty();
}
uint64_t NSROOT::BinaryData::size() const
{
    return this->inside_data.size();
}
uint64_t NSROOT::BinaryData::max_size() const
{
    return this->inside_data.max_size();
}
void NSROOT::BinaryData::reserve(uint64_t n)
{
    return this->inside_data.reserve(n);
}
void NSROOT::BinaryData::insert(const uint64_t i, uint8_t b)
{
    this->inside_data.insert(this->inside_data.begin() + i, b);
}
void NSROOT::BinaryData::insert(const std::vector<uint8_t>::iterator pos, uint8_t b)
{
    this->inside_data.insert(pos, b);
}
void NSROOT::BinaryData::erase(const uint64_t i)
{
    this->inside_data.erase(this->inside_data.begin() + i);
}
void NSROOT::BinaryData::erase(const std::vector<uint8_t>::iterator pos)
{
    this->inside_data.erase(pos);
}
void NSROOT::BinaryData::rm_pos()
{
    this->inside_data.clear();
}
void NSROOT::BinaryData::set_zero()
{
    for (auto it = this->inside_data.begin(); it != this->inside_data.end(); it++)
    {
        *it = '\0';
    }
}
void NSROOT::BinaryData::push_back(uint8_t b)
{
    this->inside_data.push_back(b);
}
void NSROOT::BinaryData::pop_back()
{
    this->inside_data.pop_back();
}
void NSROOT::BinaryData::reverse()
{
    for (uint64_t i = 0; i < this->size() / 2; i++)
    {
        std::swap(this->inside_data[i], this->inside_data[this->size() - i - 1]);
    }
}
void NSROOT::BinaryData::swap(BinaryData& d)
{
    this->inside_data.swap(d.inside_data);
}
void NSROOT::BinaryData::swap(BinaryData d)
{
    this->inside_data.swap(d.inside_data);
}
NSROOT::BinaryData NSROOT::BinaryData::bit_left_move_norise(uint64_t shift)
{
    NSROOT::BinaryData res; res.reserve(this->size());
    NSROOT::BinaryData mid;
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
        mid = this->sub_bytes_by_len(byte_shift, this->size() - byte_shift);
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
void NSROOT::BinaryData::bit_left_move_norise_self(uint64_t shift)
{
    NSROOT::BinaryData mid;
    uint64_t byte_shift = shift / 8;
    uint64_t bit_shift = shift % 8;
    uint8_t last = 0;
    if (byte_shift > this->size())
    {
        this->set_zero();
    }
    else if (byte_shift != 0)
    {
        mid = this->sub_bytes_by_len(byte_shift, this->size() - byte_shift);
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
NSROOT::BinaryData NSROOT::BinaryData::bit_left_move_rise(uint64_t shift)
{
    NSROOT::BinaryData res; res.reserve(this->size());
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
void NSROOT::BinaryData::bit_left_move_rise_self(uint64_t shift)
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
NSROOT::BinaryData NSROOT::BinaryData::bit_right_move_norise(uint64_t shift)
{
    NSROOT::BinaryData res; res.reserve(this->size());
    NSROOT::BinaryData mid;
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
        mid = this->sub_bytes_by_len(0, this->size() - byte_shift);
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
void NSROOT::BinaryData::bit_right_move_norise_self(uint64_t shift)
{
    NSROOT::BinaryData mid;
    uint64_t byte_shift = shift / 8;
    uint64_t bit_shift = shift % 8;
    uint8_t last = 0;
    if (byte_shift > this->size())
    {
        this->set_zero();
    }
    else if (byte_shift != 0)
    {
        mid = this->sub_bytes_by_len(0, this->size() - byte_shift);
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
NSROOT::BinaryData NSROOT::BinaryData::bit_right_move_rise(uint64_t shift)
{
    NSROOT::BinaryData res; res.reserve(this->size());
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
void NSROOT::BinaryData::bit_right_move_rise_self(uint64_t shift)
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
NSROOT::BinaryData NSROOT::BinaryData::bit_circle_left_move(uint64_t shift)
{
    return this->bit_left_move_norise(shift) | this->bit_right_move_norise(this->size() * 8 - shift);
}
NSROOT::BinaryData NSROOT::BinaryData::bit_circle_right_move(uint64_t shift)
{
    return this->bit_right_move_norise(shift) | this->bit_left_move_norise(this->size() * 8 - shift);
}
bool NSROOT::BinaryData::is_equal(const BinaryData& d2) const
{
    return *this == d2;
}
NSROOT::BinaryData NSROOT::BinaryData::AND(const BinaryData& d1, const BinaryData& d2, uint64_t size)
{
    BinaryData res; res.reserve(size);
    for (uint64_t i = 0; i < size; i++)
    {
        res.push_back(d1[i] & d2[i]);
    }
    return res;
}
void NSROOT::BinaryData::AND_self(BinaryData& d1, const BinaryData& d2, uint64_t size)
{
    for (uint64_t i = 0; i < size; i++)
    {
        d1[i] &= d2[i];
    }
}
NSROOT::BinaryData NSROOT::BinaryData::OR(const BinaryData& d1, const BinaryData& d2, uint64_t size)
{
    BinaryData res; res.reserve(size);
    for (uint64_t i = 0; i < size; i++)
    {
        res.push_back(d1[i] | d2[i]);
    }
    return res;
}
void NSROOT::BinaryData::OR_self(BinaryData& d1, const BinaryData& d2, uint64_t size)
{
    for (uint64_t i = 0; i < size; i++)
    {
        d1[i] |= d2[i];
    }
}
NSROOT::BinaryData NSROOT::BinaryData::XOR(const BinaryData& d1, const BinaryData& d2, uint64_t size)
{
    BinaryData res; res.reserve(size);
    for (uint64_t i = 0; i < size; i++)
    {
        res.push_back(d1[i] ^ d2[i]);
    }
    return res;
}
void NSROOT::BinaryData::XOR_self(BinaryData& d1, const BinaryData& d2, uint64_t size)
{
    for (uint64_t i = 0; i < size; i++)
    {
        d1[i] ^= d2[i];
    }
}

bool NSROOT::operator==(const BinaryData& d1, const BinaryData& d2)
{
    if (d1.size() != d2.size())
    {
        return false;
    }
    for (uint64_t i = 0; i < d1.size(); i++)
    {
        if (d1[i] != d2[i])
        {
            return false;
        }
    }
    return true;
}
bool NSROOT::operator!=(const BinaryData& d1, const BinaryData& d2)
{
    return !(d1 == d2);
}
NSROOT::BinaryData NSROOT::operator~(const BinaryData& d)
{
    BinaryData res; res.reserve(d.size());
    for (auto it = d.cbegin(); it != d.cend(); it++)
    {
        res.push_back(~(*it));
    }
    return res;
}
NSROOT::BinaryData NSROOT::operator&(const BinaryData& d1, const BinaryData& d2)
{
    if (d1.size() != d2.size())
    {
        throw DOG_EXCEPTION(DOG_ERROR_SIZE_NO_EQUAL);
    }
    BinaryData res; res.reserve(d1.size());
    for (uint64_t i = 0; i < d1.size(); i++)
    {
        res.push_back(d1[i] & d2[i]);
    }
    return res;
}
void NSROOT::operator&=(BinaryData& d1, const BinaryData& d2)
{
    if (d1.size() != d2.size())
    {
        throw DOG_EXCEPTION(DOG_ERROR_SIZE_NO_EQUAL);
    }
    BinaryData res; res.reserve(d1.size());
    for (uint64_t i = 0; i < d1.size(); i++)
    {
        d1[i] &= d2[i];
    }
}
NSROOT::BinaryData NSROOT::operator|(const BinaryData& d1, const BinaryData& d2)
{
    if (d1.size() != d2.size())
    {
        throw DOG_EXCEPTION(DOG_ERROR_SIZE_NO_EQUAL);
    }
    BinaryData res; res.reserve(d1.size());
    for (uint64_t i = 0; i < d1.size(); i++)
    {
        res.push_back(d1[i] | d2[i]);
    }
    return res;
}
void NSROOT::operator|=(BinaryData& d1, const BinaryData& d2)
{
    if (d1.size() != d2.size())
    {
        throw DOG_EXCEPTION(DOG_ERROR_SIZE_NO_EQUAL);
    }
    BinaryData res; res.reserve(d1.size());
    for (uint64_t i = 0; i < d1.size(); i++)
    {
        d1[i] |= d2[i];
    }
}
NSROOT::BinaryData NSROOT::operator^(const BinaryData& d1, const BinaryData& d2)
{
    if (d1.size() != d2.size())
    {
        throw DOG_EXCEPTION(DOG_ERROR_SIZE_NO_EQUAL);
    }
    BinaryData res; res.reserve(d1.size());
    for (uint64_t i = 0; i < d1.size(); i++)
    {
        res.push_back(d1[i] ^ d2[i]);
    }
    return res;
}
void NSROOT::operator^=(BinaryData& d1, const BinaryData& d2)
{
    if (d1.size() != d2.size())
    {
        throw DOG_EXCEPTION(DOG_ERROR_SIZE_NO_EQUAL);
    }
    BinaryData res; res.reserve(d1.size());
    for (uint64_t i = 0; i < d1.size(); i++)
    {
        d1[i] ^= d2[i];
    }
}
NSROOT::BinaryData NSROOT::operator+(const BinaryData& d1, const BinaryData& d2)
{
    BinaryData res = d1;
    for (auto it = d2.cbegin(); it != d2.cend(); it++)
    {
        res.push_back(*it);
    }
    return res;
}
void NSROOT::operator+=(BinaryData& d1, const BinaryData& d2)
{
    for (auto it = d2.cbegin(); it != d2.cend(); it++)
    {
        d1.push_back(*it);
    }
}

NSROOT::BinaryData NSROOT::BinaryData::concat(const BinaryData& d) const
{
    BinaryData res; res.reserve(this->size() + d.size());
    for (auto it = this->cbegin(); it != this->cend(); it++)
    {
        res.push_back(*it);
    }
    return res;
}

NSROOT::BinaryData NSROOT::operator""_DogHexData(const char* str, size_t len)
{
    return BinaryData(str, 2);
}

NSROOT::DataStream::DataStream(NSROOT::BinaryData& data)
{
    this->data_ = data;
}
uint8_t* NSROOT::DataStream::data()
{
    return (uint8_t*)this->data_.data();
}
uint8_t NSROOT::DataStream::get()
{
    uint8_t res = data_[pos_];
    pos_++;
    return res;
}
uint8_t NSROOT::DataStream::peek()
{
    return data_[pos_];
}
void NSROOT::DataStream::unget()
{
    pos_--;
}
uint64_t NSROOT::DataStream::tellg() const
{
    return this->pos_;
}

std::string NSROOT::utf8::to_utf8(uint64_t code)
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
uint64_t NSROOT::utf8::utf8_size(std::string str)
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
uint64_t NSROOT::utf8::utf8_size(const char* str)
{
    return NSROOT::utf8::utf8_size(std::string(str));
}
std::string NSROOT::utf8::get_utf8_char(std::string str, uint64_t offset)
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
    throw DOG_EXCEPTION(DOG_ERROR_OUT_OF_OFFSET);
}
std::string NSROOT::utf8::get_utf8_char(const char* str, uint64_t offset)
{
    return NSROOT::utf8::get_utf8_char(std::string(str), offset);
}

#undef NSROOT
#undef DOG_ERROR_SIZE_NO_EQUAL
#undef DOG_ERROR_OUT_OF_OFFSET