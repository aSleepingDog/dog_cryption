#include "data_bytes.h"
#include "data_bytes.h"

DogData::Data::Data(std::string str, const int type)
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
        Ullong m = str.size() * 3 / 4;
        this->inside_data.reserve(m);
        for (int i = 0; i < str.size(); i += 4)
        {
            Uint b[4] = { 0,0,0,0 };
            for (int i0 = 0; i0 < 4; i0++)
            {
                if (str[i + i0] >= (Uint)'A' && str[i + i0] <= (Uint)'Z')
                {
                    b[i0] = str[i + i0] - (Uint)'A';
                }
                else if (str[i + i0] >= (Uint)'a' && str[i + i0] <= (Uint)'z')
                {
                    b[i0] = str[i + i0] - (Uint)'a' + (Uint)26;
                }
                else if (str[i + i0] >= (Uint)'0' && str[i + i0] <= (Uint)'9')
                {
                    b[i0] = str[i + i0] - (Uint)'0' + (Uint)52;
                }
                else if (str[i + i0] == (Uint)'+')
                {
                    b[i0] = (Uint)62;
                }
                else if (str[i + i0] == (Uint)'/')
                {
                    b[i0] = (Uint)63;
                }
                else if (str[i + i0] == (Uint)'=')
                {
                    b[i0] = (Uint)64;
                }
            }
            this->inside_data.push_back((byte)((b[0] << 2) | (b[1] >> 4)));
            if (b[2] == (Uint)64) { break; }
            this->inside_data.push_back((byte)((b[1] << 4) | (b[2] >> 2)));
            if (b[3] == (Uint)64) { break; }
            this->inside_data.push_back((byte)((b[2] << 6) | b[3]));
        }
    }
    else if (type == 2)//16进制
    {
        this->inside_data.reserve(str.size() / 2);
        for (int i = 0; i < str.size(); i += 2)
        {
            Uint b0 = 0;
            if (str[i] >= (Uint)'A' && str[i] <= (Uint)'F')
            {
                b0 = str[i] - (Uint)'A' + (Uint)10;
            }
            else if (str[i] >= (Uint)'a' && str[i] <= (Uint)'f')
            {
                b0 = str[i] - (Uint)'a' + (Uint)10;
            }
            else if (str[i] >= '0' && str[i] <= '9')
            {
                b0 = str[i] - (Uint)'0';
            }
            Uint b1 = 0;
            if (str[i + 1] >= (Uint)'A' && str[i + 1] <= (Uint)'F')
            {
                b1 = str[i + 1] - (Uint)'A' + (Uint)10;
            }
            else if (str[i + 1] >= (Uint)'a' && str[i + 1] <= (Uint)'f')
            {
                b1 = str[i + 1] - (Uint)'a' + (Uint)10;
            }
            else if (str[i + 1] >= '0' && str[i + 1] <= '9')
            {
                b1 = str[i + 1] - (Uint)'0';
            }
            this->inside_data.push_back((byte)(b0 * 16 + b1));
        }
    }
}

DogData::Data::Data(Ullong size)
{
    this->inside_data.resize(size);
}

DogData::Data::Data(const Data& other)
{
    this->inside_data = other.inside_data;
    //printf("copy data %lld=>%lld\n", (Ullong)&other, (Ullong)this);
}

void DogData::Data::operator=(const Data& other)
{
    this->inside_data = other.inside_data;
    //printf("copy data %lld=>%lld\n", (Ullong)&other, (Ullong)this);
}

DogData::Data::Data(Data&& other)
{
    this->inside_data = std::move(other.inside_data);
    //printf("move data %lld->%lld\n", (Ullong)&other, (Ullong)this);
}

DogData::Data::~Data()
{
    //printf("delete data %lld\n", (Ullong)this);
}

DogData::byte& DogData::Data::at(Ullong i)
{
    return this->inside_data.at(i);
}

DogData::byte DogData::Data::at(Ullong i) const
{
    return this->inside_data.at(i);
}

DogData::byte& DogData::Data::operator[](Ullong i)
{
    return this->inside_data[i];
}

DogData::byte DogData::Data::operator[](Ullong i) const
{
    return this->inside_data[i];
}

DogData::byte& DogData::Data::front()
{
    return this->inside_data.front();
}

DogData::byte& DogData::Data::back()
{
    return this->inside_data.back();
}

DogData::byte* DogData::Data::data()
{
    return this->inside_data.data();
}

std::vector<DogData::byte>::iterator DogData::Data::begin()
{
    return this->inside_data.begin();
}
std::vector<DogData::byte>::iterator DogData::Data::end()
{
    return this->inside_data.end();
}
std::vector<DogData::byte>::const_iterator DogData::Data::cbegin() const
{
    return this->inside_data.cbegin();
}
std::vector<DogData::byte>::const_iterator DogData::Data::cend() const
{
    return this->inside_data.cend();
}
std::reverse_iterator<std::vector<DogData::byte>::iterator> DogData::Data::rbegin()
{
    return this->inside_data.rbegin();
}
std::reverse_iterator<std::vector<DogData::byte>::iterator> DogData::Data::rend()
{
    return this->inside_data.rend();
}
std::reverse_iterator<std::vector<DogData::byte>::const_iterator> DogData::Data::crbegin() const
{
    return this->inside_data.crbegin();
}
std::reverse_iterator<std::vector<DogData::byte>::const_iterator> DogData::Data::crend() const
{
    return this->inside_data.crend();
}

std::vector<char> DogData::Data::getUTF8Vector()
{
    std::vector<char> res(this->inside_data.size());
    for (int i = 0; i < this->inside_data.size(); i++)
    {
        res[i] = this->inside_data[i];
    }
    return res;
}
std::vector<char> DogData::Data::getBase64Vector()
{
    return this->getBase64Vector('+', '/', '=');
}
std::vector<char> DogData::Data::getBase64Vector(char a, char b)
{
    return this->getBase64Vector(a, b, '=');
}
std::vector<char> DogData::Data::getBase64Vector(char a, char b, char c)
{
    char tempList[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    tempList[62] = a; tempList[63] = b;
    std::vector<char> res;
    int bit[4] = { 0,0,0,0 };
    Ullong TDfull = this->inside_data.size() - this->inside_data.size() % 3;
    for (Ullong i = 0; i < TDfull; i += 3)
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
std::vector<char> DogData::Data::getHexVector(bool is_upper)
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
        res.push_back(HexList[(Uint)this->inside_data[i] >> 4]);
        res.push_back(HexList[(Uint)this->inside_data[i] & 0x0f]);
    }
    return res;
}

std::string DogData::Data::getUTF8String()
{
    std::vector<char> res = this->getUTF8Vector();
    return std::string(res.begin(), res.end());
}
std::string DogData::Data::getBase64String()
{
    std::vector<char> res = this->getBase64Vector();
    return std::string(res.begin(), res.end());
}
std::string DogData::Data::getBase64String(char a, char b)
{
    std::vector<char> res = this->getBase64Vector(a, b);
    return std::string(res.begin(), res.end());
}
std::string DogData::Data::getBase64String(char a, char b, char c)
{
    std::vector<char> res = this->getBase64Vector(a, b, c);
    return std::string(res.begin(), res.end());
}
std::string DogData::Data::getHexString(bool is_upper)
{
    std::vector<char> res = this->getHexVector(is_upper);
    return std::string(res.begin(), res.end());
}

DogData::Data DogData::Data::sub_by_pos(Ullong start, Ullong end) const
{
    Ullong size = end - start;
    Ullong max_size = this->inside_data.size();
    DogData::Data res; res.reserve(size);
    for (Ullong i = start; i < end && i < max_size; i++)
    {
        res.push_back(this->inside_data[i]);
    }
    return res;
}

DogData::Data DogData::Data::sub_by_len(Ullong start, Ullong len) const
{
    Ullong end = start + len;
    Ullong max_size = this->inside_data.size();
    DogData::Data res; res.reserve(len);
    for (Ullong i = start; i < end && i < max_size; i++)
    {
        res.push_back(this->inside_data[i]);
    }
    return res;
}

bool DogData::Data::empty() const
{
    return this->inside_data.empty();
}
DogData::Ullong DogData::Data::size() const
{
    return this->inside_data.size();
}
DogData::Ullong DogData::Data::max_size() const
{
    return this->inside_data.max_size();
}
void DogData::Data::reserve(Ullong n)
{
    return this->inside_data.reserve(n);
}
void DogData::Data::insert(const std::vector<byte>::iterator pos, byte b)
{
    this->inside_data.insert(pos, b);
}
void DogData::Data::erase(const std::vector<byte>::iterator pos)
{
    this->inside_data.erase(pos);
}
void DogData::Data::clear_leave_pos()
{
    this->inside_data.clear();
}
void DogData::Data::clear_set_zero()
{
    for (auto it = this->inside_data.begin(); it != this->inside_data.end(); it++)
    {
        *it = '\0';
    }
}
void DogData::Data::push_back(byte b)
{
    this->inside_data.push_back(b);
}
void DogData::Data::pop_back()
{
    this->inside_data.pop_back();
}
void DogData::Data::reverse()
{
    for (Ullong i = 0; i < this->size() / 2; i++)
    {
        std::swap(this->inside_data[i], this->inside_data[this->size() - i - 1]);
    }
}
void DogData::Data::swap(Data& d)
{
    this->inside_data.swap(d.inside_data);
}
void DogData::Data::swap(Data d)
{
    this->inside_data.swap(d.inside_data);
}

DogData::Data DogData::Data::bit_left_move_norise(Ullong shift)
{
    DogData::Data res; res.reserve(this->size());
    DogData::Data mid;
    Ullong byte_shift = shift / 8;
    Ullong bit_shift = shift % 8;
    byte last = 0;
    if (byte_shift > this->size())
    {
        for (Ullong i = 0; i < this->size(); i++)
        {
            res.push_back(0x00);
        }
        return res;
    }
    else if (byte_shift != 0)
    {
        mid = this->sub_by_len(byte_shift, this->size() - byte_shift);
        for (Ullong i = 0; i < byte_shift; i++)
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
void DogData::Data::bit_left_move_norise_self(Ullong shift)
{
    DogData::Data mid;
    Ullong byte_shift = shift / 8;
    Ullong bit_shift = shift % 8;
    byte last = 0;
    if (byte_shift > this->size())
    {
        this->clear_set_zero();
    }
    else if (byte_shift != 0)
    {
        mid = this->sub_by_len(byte_shift, this->size() - byte_shift);
        for (Ullong i = 0; i < byte_shift; i++)
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

DogData::Data DogData::Data::bit_left_move_rise(Ullong shift)
{
    DogData::Data res; res.reserve(this->size());
    Ullong byte_shift = shift / 8;
    Ullong bit_shift = shift % 8;
    byte last = 0;
    for (auto rit = this->crbegin(); rit != this->crend(); rit++)
    {
        res.insert(res.begin(), *rit << bit_shift | last);
        last = *rit >> (8 - bit_shift);
    }
    if (last != 0x00)
    {
        res.insert(res.begin(), last);
    }
    for (Ullong i = 0; i < byte_shift; i++)
    {
        res.push_back(0x00);
    }
    return res;
}
void DogData::Data::bit_left_move_rise_self(Ullong shift)
{
    Ullong byte_shift = shift / 8;
    Ullong bit_shift = shift % 8;
    byte last = 0;
    for (auto rit = this->rbegin(); rit != this->rend(); rit++)
    {
        byte tmp = (*rit << bit_shift | last);
        last = *rit >> (8 - bit_shift);
        *rit = tmp;
    }
    if (last != 0x00)
    {
        this->insert(this->begin(), last);
    }
    for (Ullong i = 0; i < byte_shift; i++)
    {
        this->push_back(0x00);
    }
}

DogData::Data DogData::Data::bit_right_move_norise(Ullong shift)
{
    DogData::Data res; res.reserve(this->size());
    DogData::Data mid;
    Ullong byte_shift = shift / 8;
    Ullong bit_shift = shift % 8;
    byte last = 0;
    if (byte_shift > this->size())
    {
        for (Ullong i = 0; i < this->size(); i++)
        {
            res.push_back(0x00);
        }
        return res;
    }
    else if (byte_shift != 0)
    {
        mid = this->sub_by_len(0, this->size() - byte_shift);
        for (Ullong i = 0; i < byte_shift; i++)
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
void DogData::Data::bit_right_move_norise_self(Ullong shift)
{
    DogData::Data mid;
    Ullong byte_shift = shift / 8;
    Ullong bit_shift = shift % 8;
    byte last = 0;
    if (byte_shift > this->size())
    {
        this->clear_set_zero();
    }
    else if (byte_shift != 0)
    {
        mid = this->sub_by_len(0, this->size() - byte_shift);
        for (Ullong i = 0; i < byte_shift; i++)
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

DogData::Data DogData::Data::bit_right_move_rise(Ullong shift)
{
    DogData::Data res; res.reserve(this->size());
    Ullong byte_shift = shift / 8;
    Ullong bit_shift = shift % 8;
    byte last = 0;
    for (auto rit = this->cbegin(); rit != this->cend(); rit++)
    {
        res.push_back(*rit >> bit_shift | last);
        last = *rit << (8 - bit_shift);
    }
    if (last != 0x00)
    {
        res.push_back(last);
    }
    for (Ullong i = 0; i < byte_shift; i++)
    {
        res.insert(res.begin(), 0x00);
    }
    return res;
}
void DogData::Data::bit_right_move_rise_self(Ullong shift)
{
    Ullong byte_shift = shift / 8;
    Ullong bit_shift = shift % 8;
    byte last = 0;
    for (auto rit = this->begin(); rit != this->end(); rit++)
    {
        byte tmp = (*rit >> bit_shift | last);
        last = *rit << (8 - bit_shift);
        *rit = tmp;
    }
    if (last != 0x00)
    {
        this->push_back(last);
    }
    for (Ullong i = 0; i < byte_shift; i++)
    {
        this->insert(this->begin(), 0x00);
    }
}

DogData::Data DogData::Data::operator~()
{
    DogData::Data res;
    for (auto it = this->cbegin(); it != this->cend(); it++)
    {
        res.push_back(~(*it));
    }
    return res;
}

bool DogData::Data::is_equal(const Data& d2) const
{
    return *this == d2;
}

DogData::Data DogData::Data::concat(const Data& b) const
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
DogData::Data DogData::operator&(const Data d1, const Data d2)
{
    if (d1.size() != d2.size())
    {
        throw dog_exception("the size must be equal when AND", __FILE__, __FUNCTION__, __LINE__);
    }
    DogData::Data res; res.reserve(d1.size());
    for (Ullong i = 0; i < d1.size(); i++)
    {
        res.push_back(d1[i] & d2[i]);
    }
    return res;

}
DogData::Data DogData::operator|(const Data d1, const Data d2)
{
    if (d1.size() != d2.size())
    {
        throw dog_exception("the size must be equal when OR", __FILE__, __FUNCTION__, __LINE__);
    }
    DogData::Data res; res.reserve(d1.size());
    for (Ullong i = 0; i < d1.size(); i++)
    {
        res.push_back(d1[i] | d2[i]);
    }
    return res;

}
DogData::Data DogData::operator^(const Data d1, const Data d2)
{
    if (d1.size() != d2.size())
    {
        throw dog_exception("the size must be equal when OR", __FILE__, __FUNCTION__, __LINE__);
    }
    DogData::Data res; res.reserve(d1.size());
    for (Ullong i = 0; i < d1.size(); i++)
    {
        res.push_back(d1[i] ^ d2[i]);
    }
    return res;
}
bool DogData::operator==(const Data d1, const Data d2)
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
bool DogData::operator!=(const Data d1, const Data d2)
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

void DogData::operator+=(Data& d1, const Data& d2)
{
    for (byte i : d2.inside_data)
    {
        d1.inside_data.push_back(i);
    }
}

DogData::Data DogData::operator+(const Data& a, const Data b)
{
    DogData::Data res; res.reserve(a.size() + b.size());
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

void DogData::print::block(DogData::Data data, Ullong column)
{
    printf("XX");
    for (Ullong i = 0; i < column; ++i)
    {
        printf(" %02X", i);
        if ((i % column) % 4 == 3)
        {
            printf("|");
        }
    }
    Ullong row = 0;
    for (Ullong i=0;i<data.size();++i)
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

void DogData::print::block(const char* data, Ullong size, Ullong column)
{
    printf("XX");
    for (Ullong i = 0; i < column; ++i)
    {
        printf(" %02X", i);
        if ((i % column) % 4 == 3)
        {
            printf("|");
        }
    }
    Ullong row = 0;
    for (Ullong i = 0; i < size; ++i)
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

void DogData::print::space(DogData::Data data, Ullong column)
{
    printf("%02X ", data[0] & 0xff);
    for (Ullong i = 1; i < data.size(); ++i)
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

void DogData::print::space(const char* data, Ullong size, Ullong column)
{
    printf("%02X ", data[0] & 0xff);
    for (Ullong i = 1; i < size; ++i)
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

DogData::Ullong DogData::buffer::get_buffer_size(Ullong file_size)
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

dog_exception::dog_exception(const char* msg, const char* file, const char* function, uint64_t line)
{
    this->msg = std::format("{}:{}\n at {}({}:{})", typeid(*this).name(), msg, function, file, line);
}

const char* dog_exception::what() const throw()
{
    return this->msg.c_str();
}
