#include "big_number.h"

DogNumber::number_exception::number_exception(const char* msg, const char* file, const char* function, uint64_t line)
{
	//std::format("{}:{}\n at {}({}:{})", typeid(*this).name(), msg, function, file, line);
	this->msg = std::format("{}:{}\n at {}({}:{})", typeid(*this).name(), msg, function, file, line);
}
const char* DogNumber::number_exception::what() const throw()
{
	return this->msg.c_str();
}

DogNumber::BigInteger::BigInteger()
{
	this->sign = 0;
	this->num.push_back(0);
}
DogNumber::BigInteger::BigInteger(const char* str, const int radix)
{
	const char* p = str;
	Ullong size = strlen(str);
	if (radix == HEX)
	{
		byte temp = 0x00;
		int num = 0;//取值 0 1 2
		if (*str == '-')
		{
			this->num.reserve((size - 1) >> 1);
			num = ((size & 0x01) == 0x01) ? 0 : 1;
		}
		else
		{
			this->num.reserve(size >> 1);
			num = ((size & 0x01) == 0x00) ? 0 : 1;
		}
		while (*p != '\0')
		{
			if (*p == '-' && p == str)
			{
				this->sign = -1;
			}
			else if (*p == '-' && p != str)
			{
				throw number_exception(
					"Error:minus sign is not at first\n错误：负号不在首位", __FILE__, __FUNCTION__, __LINE__
				);
			}
			else if (*p >= '0' && *p <= '9')
			{
				if (num == 0)
				{
					temp |= (*p - '0') << 4;
					num++;
				}
				else if (num == 1)
				{
					temp |= (*p - '0');
					num++;
				}
			}
			else if (*p >= 'A' && *p <= 'F')
			{
				if (num == 0)
				{
					temp |= (*p - 'A' + 10) << 4;
					num++;
				}
				else if (num == 1)
				{
					temp |= (*p - 'A' + 10);
					num++;
				}
			}
			else if (*p >= 'a' && *p <= 'f')
			{
				if (num == 0)
				{
					temp |= (*p - 'a' + 10) << 4;
					num++;
				}
				else if (num == 1)
				{
					temp |= (*p - 'a' + 10);
					num++;
				}
			}
			else
			{
				throw number_exception(
					"Error:wrong char in hex\ncorrect chars are 0123456789abcdefABCDEF\n错误：出现了16进制中不存在的字符\n正确的字符为0123456789abcdefABCDEF", __FILE__, __FUNCTION__, __LINE__
				);
			}
			if (num == 2)
			{
				this->num.push_back(temp);
				temp = 0x00;
				num = 0;
			}
			p++;
		}
	}
	else if (radix == OCT)
	{
		//--------------______
		Uint temp = 0x00000000;
		//0x00ff0000
		//0x0000ff00
		//0x000000ff
		int num = 0;//取值 0 1 2 3 4 5 6 7 8
		if (*str == '-')
		{
			this->num.reserve((size - 1) * 3 / 8);
			num = (8 - (size - 1) % 8) % 8;
		}
		else
		{
			this->num.reserve(size * 3 / 8);
			num = (8 - (size % 8)) % 8;
		}
		//printf("%d\n", num);
		auto filling = [&temp](byte b, int num)->void
			{
				switch (num)
				{
				case 0:
				{
					temp |= (b & 0x07) << 21;
					break;
				}
				case 1:
				{
					temp |= (b & 0x07) << 18;
					break;
				}
				case 2:
				{
					temp |= (b & 0x07) << 15;
					break;
				}
				case 3:
				{
					temp |= (b & 0x07) << 12;
					break;
				}
				case 4:
				{
					temp |= (b & 0x07) << 9;
					break;
				}
				case 5:
				{
					temp |= (b & 0x07) << 6;
					break;
				}
				case 6:
				{
					temp |= (b & 0x07) << 3;
					break;
				}
				case 7:
				{
					temp |= (b & 0x07);
					break;
				}
				}
			};
		while (*p != '\0')
		{
			if (*p == '-' && p == str)
			{
				this->sign = -1;
			}
			else if (*p == '-' && p != str)
			{
				throw number_exception(
					"Error:minus sign is not at first\n错误：负号不在首位", __FILE__, __FUNCTION__, __LINE__
				);
			}
			else if (*p >= '0' && *p <= '7')
			{
				filling(*p - '0', num);
				num++;
			}
			else
			{
				throw number_exception(
					"Error:wrong char in oct\ncorrect chars are 01234567\n错误：出现了8进制中不存在的字符\n正确的字符为01234567", __FILE__, __FUNCTION__, __LINE__
				);
			}
			if (num == 8)
			{
				this->num.push_back(((temp & 0x00ff0000) >> 16));
				this->num.push_back(((temp & 0x0000ff00) >> 8));
				this->num.push_back((temp & 0x000000ff));
				num = 0;
				temp = 0x00000000;
			}
			p++;
		}
	}
	else if (radix == BIN)
	{
		byte temp = 0x00;
		int num = 0;//取值 0 1 2 3 4 5 6 7 8
		if (*str == '-')
		{
			this->num.reserve(((size - 1) / 8) + 1);
			num = (8 - (size - 1) % 8) % 8;
		}
		else
		{
			this->num.reserve((size / 8) + 1);
			num = (8 - (size % 8)) % 8;
		}
		//printf("%d\n", num);
		auto filling = [&temp](byte b, int num)->void
			{
				switch (num)
				{
				case 0:
				{
					temp |= (b & 0x01) << 7;
					break;
				}
				case 1:
				{
					temp |= (b & 0x01) << 6;
					break;
				}
				case 2:
				{
					temp |= (b & 0x01) << 5;
					break;
				}
				case 3:
				{
					temp |= (b & 0x01) << 4;
					break;
				}
				case 4:
				{
					temp |= (b & 0x01) << 3;
					break;
				}
				case 5:
				{
					temp |= (b & 0x01) << 2;
					break;
				}
				case 6:
				{
					temp |= (b & 0x01) << 1;
					break;
				}
				case 7:
				{
					temp |= (b & 0x01) << 0;
					break;
				}

				}
			};
		while (*p != '\0')
		{
			if (*p == '-' && p == str)
			{
				this->sign = -1;
			}
			else if (*p == '-' && p != str)
			{
				throw number_exception(
					"Error:minus sign is not at first\n错误：负号不在首位", __FILE__, __FUNCTION__, __LINE__
				);
			}
			else if (*p == '0' || *p == '1')
			{
				filling(*p - '0', num);
				num++;
			}
			else
			{
				throw number_exception(
					"Error:wrong char in bin\ncorrect chars are 01\n错误：出现了2进制中不存在的字符\n正确的字符为01", __FILE__, __FUNCTION__, __LINE__
				);
			}
			if (num == 8)
			{
				this->num.push_back(temp);
				temp = 0x00;
				num = 0;
			}
			p++;
		}

	}
	else if (radix == DEC)
	{
		/*
		std::vector<byte> temp_quotient;//商
		Ullong start = 0;
		if (*str != '-')
		{
			temp_quotient.reserve(size);
			for (Ullong i = 0; i < size; i++)
			{
				temp_quotient.push_back(*p - '0');
				p++;
			}
		}
		else
		{
			temp_quotient.reserve(size - 1);
			this->sign = -1;
			p++;
			for (Ullong i = 1; i < size; i++)
			{
				temp_quotient.push_back(*p - '0');
				p++;
			}
		}
		byte highSet = 0;
		auto isZero = [&start](std::vector<byte> tempBs)->bool
			{
				for (Ullong i = start; i < tempBs.size(); i++)
				{
					if (tempBs.at(i) != 0) { return false; }
				}
				return true;
			};
		while (temp_quotient.size() != start && !isZero(temp_quotient))
		{
			byte B = 0;
			for (int j = 0; j < 8; j++)
			{
				B |= (byte)(temp_quotient.at(temp_quotient.size() - 1) % 2) << j;
				for (Ullong i = start; i < temp_quotient.size(); i++)
				{
					byte c = highSet * 10 + temp_quotient.at(i);
					temp_quotient.at(i) = c / 2;
					highSet = c % 2;
					if (temp_quotient.at(start) == 0) { start++; }
				}
				highSet = 0;
			}
			this->num.insert(this->num.begin(), B);
		}
		*/


		/*
			10000000000000000000  8A C7 23 04 89 E8 00 00  8
			1000000000000000000   0D E0 B6 B3 A7 64 00 00  8
			100000000000000000    01 63 45 78 5D 8A 00 00  8
			10000000000000000     23 86 F2 6F C1 00 00     7
			1000000000000000      03 8D 7E A4 C6 80 00     7
			100000000000000       5A F3 10 7A 40 00        6
			10000000000000        09 18 4E 72 A0 00        6
			1000000000000         E8 D4 A5 10 00           5
			100000000000          17 48 76 E8 00           5
			10000000000           02 54 0B E4 00           5
			1000000000            E8 D4 A5 10 00           5
			100000000             05 F5 E1 00              4
			10000000              98 96 80                 3
			1000000               0F 42 40                 3
			100000                01 86 A0                 3
			10000                 27 10                    2
			1000                  03 E8                    2
			100                   64                       1
			10                    0A                       1
			1                     1                        1
		*/

		std::vector<byte> total_quotient;
		if (*str != '-')
		{
			total_quotient.reserve(size);
			for (Ullong i = 0; i < size; i++)
			{
				total_quotient.push_back(*p - '0');
				p++;
			}
		}
		else
		{
			total_quotient.reserve(size - 1);
			this->sign = -1;
			p++;
			for (Ullong i = 1; i < size; i++)
			{
				if (*p - '0' < 0 || *p - '0' > 9)
				{
					throw number_exception("Error:wrong character in dec\n错误：十进制下错误的字符", __FILE__, __FUNCTION__, __LINE__);
				}
				total_quotient.push_back(*p - '0');
				p++;
			}
		}
		while (total_quotient.size() > 2)
		{
			Ullong middle_quotient = total_quotient[0] * 100 + total_quotient[1] * 10 + total_quotient[2];
			Ullong start = 3;
			std::vector<byte> temp_quotient;
			while (true)
			{
				byte temp_singel_quotient = middle_quotient / 256;
				//printf("%d ", temp_singel_quotient);
				if (temp_singel_quotient != 0 || (temp_singel_quotient == 0 && temp_quotient.size() > 0))
				{
					temp_quotient.push_back(temp_singel_quotient);
				}
				middle_quotient = middle_quotient % 256;
				if (start == total_quotient.size()) { break; }
				middle_quotient *= 10;
				middle_quotient += total_quotient[start];
				start++;
			}
			total_quotient = std::move(temp_quotient);
			this->num.insert(this->num.begin(), middle_quotient);
		}
		if (total_quotient.size() == 2)
		{
			this->num.insert(this->num.begin(), total_quotient[0] * 10 + total_quotient[1]);
		}
		else if (total_quotient.size() == 1)
		{
			this->num.insert(this->num.begin(), total_quotient[0]);
		}

	}

	this->trims();
	if (this->sign != -1 && this->num.size() == 1 && this->num.front() == 0)
	{
		this->sign = 0;
	}
	else if (this->sign != -1)
	{
		this->sign = 1;
	}

}
DogNumber::BigInteger::BigInteger(const std::string& str, const int radix)
{
	const char* p = str.c_str();
	const char* str_ = str.c_str();
	Ullong size = str.size();
	if (radix == HEX)
	{
		byte temp = 0x00;
		int num = 0;//取值 0 1 2
		if (*str_ == '-')
		{
			this->num.reserve((size - 1) / 2);
			num = ((size & 0x01) == 0x01) ? 0 : 1;
		}
		else
		{
			this->num.reserve(size / 2);
			num = ((size & 0x01) == 0x00) ? 0 : 1;
		}
		for (Ullong i = 0; i < size; ++i)
		{
			if (*p == '-' && p == str_)
			{
				this->sign = -1;
			}
			else if (*p == '-' && p != str_)
			{
				throw number_exception(
					"Error:minus sign is not at first\n错误：负号不在首位", __FILE__, __FUNCTION__, __LINE__
				);
			}
			else if (*p >= '0' && *p <= '9')
			{
				if (num == 0)
				{
					temp |= (*p - '0') << 4;
					num++;
				}
				else if (num == 1)
				{
					temp |= (*p - '0');
					num++;
				}
			}
			else if (*p >= 'A' && *p <= 'F')
			{
				if (num == 0)
				{
					temp |= (*p - 'A' + 10) << 4;
					num++;
				}
				else if (num == 1)
				{
					temp |= (*p - 'A' + 10);
					num++;
				}
			}
			else if (*p >= 'a' && *p <= 'f')
			{
				if (num == 0)
				{
					temp |= (*p - 'a' + 10) << 4;
					num++;
				}
				else if (num == 1)
				{
					temp |= (*p - 'a' + 10);
					num++;
				}
			}
			else
			{
				throw number_exception(
					"Error:wrong char in hex\ncorrect chars are 0123456789abcdefABCDEF\n错误：出现了16进制中不存在的字符\n正确的字符为0123456789abcdefABCDEF", __FILE__, __FUNCTION__, __LINE__
				);
			}
			if (num == 2)
			{
				this->num.push_back(temp);
				temp = 0x00;
				num = 0;
			}
			p++;
		}
	}
	else if (radix == OCT)
	{
		//--------------______
		Uint temp = 0x00000000;
		//0x00ff0000
		//0x0000ff00
		//0x000000ff
		int num = 0;//取值 0 1 2 3 4 5 6 7 8
		if (*str_ == '-')
		{
			this->num.reserve((size - 1) * 3 / 8);
			num = (8 - (size - 1) % 8) % 8;
		}
		else
		{
			this->num.reserve(size * 3 / 8);
			num = (8 - (size % 8)) % 8;
		}
		//printf("%d\n", num);
		auto filling = [&temp](byte b, int num)->void
			{
				switch (num)
				{
				case 0:
				{
					temp |= (b & 0x07) << 21;
					break;
				}
				case 1:
				{
					temp |= (b & 0x07) << 18;
					break;
				}
				case 2:
				{
					temp |= (b & 0x07) << 15;
					break;
				}
				case 3:
				{
					temp |= (b & 0x07) << 12;
					break;
				}
				case 4:
				{
					temp |= (b & 0x07) << 9;
					break;
				}
				case 5:
				{
					temp |= (b & 0x07) << 6;
					break;
				}
				case 6:
				{
					temp |= (b & 0x07) << 3;
					break;
				}
				case 7:
				{
					temp |= (b & 0x07);
					break;
				}
				}
			};
		for (Ullong i = 0; i < size; ++i)
		{
			if (*p == '-' && p == str_)
			{
				this->sign = -1;
			}
			else if (*p == '-' && p != str_)
			{
				throw number_exception(
					"Error:minus sign is not at first\n错误：负号不在首位", __FILE__, __FUNCTION__, __LINE__
				);
			}
			else if (*p >= '0' && *p <= '7')
			{
				filling(*p - '0', num);
				num++;
			}
			else
			{
				throw number_exception(
					"Error:wrong char in oct\ncorrect chars are 01234567\n错误：出现了8进制中不存在的字符\n正确的字符为01234567", __FILE__, __FUNCTION__, __LINE__
				);
			}
			if (num == 8)
			{
				this->num.push_back(((temp & 0x00ff0000) >> 16));
				this->num.push_back(((temp & 0x0000ff00) >> 8));
				this->num.push_back((temp & 0x000000ff));
				num = 0;
				temp = 0x00000000;
			}
			p++;
		}
	}
	else if (radix == BIN)
	{
		byte temp = 0x00;
		int num = 0;//取值 0 1 2 3 4 5 6 7 8
		if (*str_ == '-')
		{
			this->num.reserve(((size - 1) / 8) + 1);
			num = (8 - (size - 1) % 8) % 8;
		}
		else
		{
			this->num.reserve((size / 8) + 1);
			num = (8 - (size % 8)) % 8;
		}
		//printf("%d\n", num);
		auto filling = [&temp](byte b, int num)->void
			{
				switch (num)
				{
				case 0:
				{
					temp |= (b & 0x01) << 7;
					break;
				}
				case 1:
				{
					temp |= (b & 0x01) << 6;
					break;
				}
				case 2:
				{
					temp |= (b & 0x01) << 5;
					break;
				}
				case 3:
				{
					temp |= (b & 0x01) << 4;
					break;
				}
				case 4:
				{
					temp |= (b & 0x01) << 3;
					break;
				}
				case 5:
				{
					temp |= (b & 0x01) << 2;
					break;
				}
				case 6:
				{
					temp |= (b & 0x01) << 1;
					break;
				}
				case 7:
				{
					temp |= (b & 0x01) << 0;
					break;
				}

				}
			};
		for (Ullong i = 0; i < size; ++i)
		{
			if (*p == '-' && p == str_)
			{
				this->sign = -1;
			}
			else if (*p == '-' && p != str_)
			{
				throw number_exception(
					"Error:minus sign is not at first\n错误：负号不在首位", __FILE__, __FUNCTION__, __LINE__
				);
			}
			else if (*p == '0' || *p == '1')
			{
				filling(*p - '0', num);
				num++;
			}
			else
			{
				throw number_exception(
					"Error:wrong char in bin\ncorrect chars are 01\n错误：出现了2进制中不存在的字符\n正确的字符为01", __FILE__, __FUNCTION__, __LINE__
				);
			}
			if (num == 8)
			{
				this->num.push_back(temp);
				temp = 0x00;
				num = 0;
			}
			p++;
		}

	}
	else if (radix == DEC)
	{
		std::vector<byte> total_quotient;
		if (*str_ != '-')
		{
			total_quotient.reserve(size);
			for (Ullong i = 0; i < size; i++)
			{
				total_quotient.push_back(*p - '0');
				p++;
			}
		}
		else
		{
			total_quotient.reserve(size - 1);
			this->sign = -1;
			p++;
			for (Ullong i = 1; i < size; i++)
			{
				total_quotient.push_back(*p - '0');
				p++;
			}
		}
		while (total_quotient.size() > 2)
		{
			Ullong middle_quotient = total_quotient[0] * 100 + total_quotient[1] * 10 + total_quotient[2];
			Ullong start = 3;
			std::vector<byte> temp_quotient;
			while (true)
			{
				byte temp_singel_quotient = middle_quotient / 256;
				//printf("%d ", temp_singel_quotient);
				if (temp_singel_quotient != 0 || (temp_singel_quotient == 0 && temp_quotient.size() > 0))
				{
					temp_quotient.push_back(temp_singel_quotient);
				}
				middle_quotient = middle_quotient % 256;
				if (start == total_quotient.size()) { break; }
				middle_quotient *= 10;
				middle_quotient += total_quotient[start];
				start++;
			}
			total_quotient = std::move(temp_quotient);
			this->num.insert(this->num.begin(), middle_quotient);
		}
		switch (total_quotient.size())
		{
		case 1:
		{
			this->num.insert(this->num.begin(), total_quotient[0]);
			break;
		}
		case 2:
		{
			this->num.insert(this->num.begin(), total_quotient[0] * 10 + total_quotient[1]);
			break;
		}
		}
	}

	this->trims();
	if (this->sign != -1 && this->num.size() == 1 && this->num.front() == '0')
	{
		this->sign = 0;
	}
	else if (this->sign != -1)
	{
		this->sign = 1;
	}
}
DogNumber::BigInteger::BigInteger(const std::vector<char>& str, const int radix)
{
	const char* p = &str.at(0);
	const char* str_ = &str.at(0);
	Ullong size = str.size();
	if (radix == HEX)
	{
		byte temp = 0x00;
		int num = 0;//取值 0 1 2
		if (*str_ == '-')
		{
			this->num.reserve((size - 1) / 2);
			num = ((size & 0x01) == 0x01) ? 0 : 1;
		}
		else
		{
			this->num.reserve(size / 2);
			num = ((size & 0x01) == 0x00) ? 0 : 1;
		}
		for (Ullong i = 0; i < size; ++i)
		{
			if (*p == '-' && p == str_)
			{
				this->sign = -1;
			}
			else if (*p == '-' && p != str_)
			{
				throw number_exception(
					"Error:minus sign is not at first\n错误：负号不在首位", __FILE__, __FUNCTION__, __LINE__
				);
			}
			else if (*p >= '0' && *p <= '9')
			{
				if (num == 0)
				{
					temp |= (*p - '0') << 4;
					num++;
				}
				else if (num == 1)
				{
					temp |= (*p - '0');
					num++;
				}
			}
			else if (*p >= 'A' && *p <= 'F')
			{
				if (num == 0)
				{
					temp |= (*p - 'A' + 10) << 4;
					num++;
				}
				else if (num == 1)
				{
					temp |= (*p - 'A' + 10);
					num++;
				}
			}
			else if (*p >= 'a' && *p <= 'f')
			{
				if (num == 0)
				{
					temp |= (*p - 'a' + 10) << 4;
					num++;
				}
				else if (num == 1)
				{
					temp |= (*p - 'a' + 10);
					num++;
				}
			}
			else
			{
				throw number_exception(
					"Error:wrong char in hex\ncorrect chars are 0123456789abcdefABCDEF\n错误：出现了16进制中不存在的字符\n正确的字符为0123456789abcdefABCDEF", __FILE__, __FUNCTION__, __LINE__
				);
			}
			if (num == 2)
			{
				this->num.push_back(temp);
				temp = 0x00;
				num = 0;
			}
			p++;
		}
	}
	else if (radix == OCT)
	{
		//--------------______
		Uint temp = 0x00000000;
		//0x00ff0000
		//0x0000ff00
		//0x000000ff
		int num = 0;//取值 0 1 2 3 4 5 6 7 8
		if (*str_ == '-')
		{
			this->num.reserve((size - 1) * 3 / 8);
			num = (8 - (size - 1) % 8) % 8;
		}
		else
		{
			this->num.reserve(size * 3 / 8);
			num = (8 - (size % 8)) % 8;
		}
		//printf("%d\n", num);
		auto filling = [&temp](byte b, int num)->void
			{
				switch (num)
				{
				case 0:
				{
					temp |= (b & 0x07) << 21;
					break;
				}
				case 1:
				{
					temp |= (b & 0x07) << 18;
					break;
				}
				case 2:
				{
					temp |= (b & 0x07) << 15;
					break;
				}
				case 3:
				{
					temp |= (b & 0x07) << 12;
					break;
				}
				case 4:
				{
					temp |= (b & 0x07) << 9;
					break;
				}
				case 5:
				{
					temp |= (b & 0x07) << 6;
					break;
				}
				case 6:
				{
					temp |= (b & 0x07) << 3;
					break;
				}
				case 7:
				{
					temp |= (b & 0x07);
					break;
				}
				}
			};
		for (Ullong i = 0; i < size; ++i)
		{
			if (*p == '-' && p == str_)
			{
				this->sign = -1;
			}
			else if (*p == '-' && p != str_)
			{
				throw number_exception(
					"Error:minus sign is not at first\n错误：负号不在首位", __FILE__, __FUNCTION__, __LINE__
				);
			}
			else if (*p >= '0' && *p <= '7')
			{
				filling(*p - '0', num);
				num++;
			}
			else
			{
				throw number_exception(
					"Error:wrong char in oct\ncorrect chars are 01234567\n错误：出现了8进制中不存在的字符\n正确的字符为01234567", __FILE__, __FUNCTION__, __LINE__
				);
			}
			if (num == 8)
			{
				this->num.push_back(((temp & 0x00ff0000) >> 16));
				this->num.push_back(((temp & 0x0000ff00) >> 8));
				this->num.push_back((temp & 0x000000ff));
				num = 0;
				temp = 0x00000000;
			}
			p++;
		}
	}
	else if (radix == BIN)
	{
		byte temp = 0x00;
		int num = 0;//取值 0 1 2 3 4 5 6 7 8
		if (*str_ == '-')
		{
			this->num.reserve(((size - 1) / 8) + 1);
			num = (8 - (size - 1) % 8) % 8;
		}
		else
		{
			this->num.reserve((size / 8) + 1);
			num = (8 - (size % 8)) % 8;
		}
		//printf("%d\n", num);
		auto filling = [&temp](byte b, int num)->void
			{
				switch (num)
				{
				case 0:
				{
					temp |= (b & 0x01) << 7;
					break;
				}
				case 1:
				{
					temp |= (b & 0x01) << 6;
					break;
				}
				case 2:
				{
					temp |= (b & 0x01) << 5;
					break;
				}
				case 3:
				{
					temp |= (b & 0x01) << 4;
					break;
				}
				case 4:
				{
					temp |= (b & 0x01) << 3;
					break;
				}
				case 5:
				{
					temp |= (b & 0x01) << 2;
					break;
				}
				case 6:
				{
					temp |= (b & 0x01) << 1;
					break;
				}
				case 7:
				{
					temp |= (b & 0x01) << 0;
					break;
				}

				}
			};
		for (Ullong i = 0; i < size; ++i)
		{
			if (*p == '-' && p == str_)
			{
				this->sign = -1;
			}
			else if (*p == '-' && p != str_)
			{
				throw number_exception(
					"Error:minus sign is not at first\n错误：负号不在首位", __FILE__, __FUNCTION__, __LINE__
				);
			}
			else if (*p == '0' || *p == '1')
			{
				filling(*p - '0', num);
				num++;
			}
			else
			{
				throw number_exception(
					"Error:wrong char in bin\ncorrect chars are 01\n错误：出现了2进制中不存在的字符\n正确的字符为01", __FILE__, __FUNCTION__, __LINE__
				);
			}
			if (num == 8)
			{
				this->num.push_back(temp);
				temp = 0x00;
				num = 0;
			}
			p++;
		}

	}
	else if (radix == DEC)
	{
		std::vector<byte> total_quotient;
		if (*str_ != '-')
		{
			total_quotient.reserve(size);
			for (Ullong i = 0; i < size; i++)
			{
				total_quotient.push_back(*p - '0');
				p++;
			}
		}
		else
		{
			total_quotient.reserve(size - 1);
			this->sign = -1;
			p++;
			for (Ullong i = 1; i < size; i++)
			{
				total_quotient.push_back(*p - '0');
				p++;
			}
		}
		while (total_quotient.size() > 2)
		{
			Ullong middle_quotient = total_quotient[0] * 100 + total_quotient[1] * 10 + total_quotient[2];
			Ullong start = 3;
			std::vector<byte> temp_quotient;
			while (true)
			{
				byte temp_singel_quotient = middle_quotient / 256;
				//printf("%d ", temp_singel_quotient);
				if (temp_singel_quotient != 0 || (temp_singel_quotient == 0 && temp_quotient.size() > 0))
				{
					temp_quotient.push_back(temp_singel_quotient);
				}
				middle_quotient = middle_quotient % 256;
				if (start == total_quotient.size()) { break; }
				middle_quotient *= 10;
				middle_quotient += total_quotient[start];
				start++;
			}
			total_quotient = std::move(temp_quotient);
			this->num.insert(this->num.begin(), middle_quotient);
		}
		if (total_quotient.size() == 2)
		{
			this->num.insert(this->num.begin(), total_quotient[0] * 10 + total_quotient[1]);
		}
		else
		{
			this->num.insert(this->num.begin(), total_quotient[0]);
		}
	}

	this->trims();
	if (this->sign != -1 && this->num.size() == 1 && this->num.front() == '0')
	{
		this->sign = 0;
	}
	else if (this->sign != -1)
	{
		this->sign = 1;
	}
}

DogNumber::BigInteger::BigInteger(uint8_t n)
{
	BigInteger::toBigInteger(n).swap(*this);
}
DogNumber::BigInteger::BigInteger(uint16_t n)
{
	BigInteger::toBigInteger(n).swap(*this);
}
DogNumber::BigInteger::BigInteger(uint32_t n)
{
	BigInteger::toBigInteger(n).swap(*this);
}
DogNumber::BigInteger::BigInteger(uint64_t n)
{
	BigInteger::toBigInteger(n).swap(*this);
}
DogNumber::BigInteger::BigInteger(int8_t n)
{
	BigInteger::toBigInteger(n).swap(*this);
}
DogNumber::BigInteger::BigInteger(int16_t n)
{
	BigInteger::toBigInteger(n).swap(*this);
}
DogNumber::BigInteger::BigInteger(int32_t n)
{
	BigInteger::toBigInteger(n).swap(*this);
}
DogNumber::BigInteger::BigInteger(int64_t n)
{
	BigInteger::toBigInteger(n).swap(*this);
}

void DogNumber::BigInteger::swap(BigInteger& b)
{
	std::swap(this->num, b.num);
	std::swap(this->sign, b.sign);
}

void DogNumber::BigInteger::trims()
{
	while (*(this->num.begin()) == 0x00 && this->num.size() > 1)
	{
		this->num.erase(this->num.begin());
	}
	if (this->num.size() == 1 && this->num.front() == 0x00)
	{
		this->sign = 0;
	}
	this->num.shrink_to_fit();
}
std::string DogNumber::BigInteger::getUpHEX()
{
	std::string res;
	if (sign == -1)
	{
		res.reserve(this->num.size() + 1);
		res += '-';
	}
	else
	{
		res.reserve(this->num.size());
	}
	char hexChar[17] = "0123456789ABCDEF";
	for (byte& b : this->num)
	{
		res.push_back(hexChar[(b & 0xF0) >> 4]);
		res.push_back(hexChar[(b & 0x0F)]);
	}
	return res;
}
std::string DogNumber::BigInteger::getLowHEX()
{
	std::string res;
	if (sign == -1)
	{
		res.reserve(this->num.size() + 1);
		res += '-';
	}
	else
	{
		res.reserve(this->num.size());
	}
	char hexChar[17] = "0123456789abcdef";
	for (byte& b : this->num)
	{
		res.push_back(hexChar[(b & 0xF0) >> 4]);
		res.push_back(hexChar[(b & 0x0F)]);
	}
	return res;
}
std::string DogNumber::BigInteger::getDEC()
{
	/*
	BigInteger temp = *this;
	BigInteger res;
	Ushort tB = 0;
	std::string NumStr;
	std::string DecChars;
	bool isFillHigh = false;
	while (temp != 0)
	{
		for (Ullong i = 0; i < temp.size(); i++)
		{
			tB |= temp.at(i);
			if (isFillHigh || tB / 100 != 0)
			{
				res.push_back(tB / 100);
				isFillHigh = true;
			}
			else if (isFillHigh)
			{
				res.push_back(tB / 100);
			}
			tB %= 100;
			tB <<= 8;
		}
		if (res.size() == 0)
		{
			res.push_back(0);
		}
		NumStr = std::to_string((byte)(tB >> 8));
		if (NumStr.size() < 2 && res != 0) { DecChars = "0" + NumStr + DecChars; }
		else { DecChars = NumStr + DecChars; }
		temp = res;
		isFillHigh = false;
		res.clear();
		tB = 0;
	}
	if (this->get_sign() == -1)
	{
		DecChars = "-" + DecChars;
	}
	return DecChars;
	*/
	if (this->size() == 0 && this->num.at(0) == 0)
	{
		return "0";
	}
	std::vector<byte> total_quotient = this->num;
	std::string res;
	while (total_quotient.size() > 7)
	{
		Ullong middle_quotient =
			((Ullong)total_quotient[0] << 48) |
			((Ullong)total_quotient[1] << 40) |
			((Ullong)total_quotient[2] << 32) |
			((Ullong)total_quotient[3] << 24) |
			((Ullong)total_quotient[4] << 16) |
			((Ullong)total_quotient[5] << 8) |
			((Ullong)total_quotient[6] << 0), start = 7;
		std::vector<byte> temp_quotient;
		while (true)
		{
			byte temp_singel_quotient = middle_quotient / 10000000000000000;
			if (temp_singel_quotient != 0 || (temp_singel_quotient == 0 && temp_quotient.size() > 0))
			{
				temp_quotient.push_back(temp_singel_quotient);
			}
			middle_quotient = middle_quotient % 10000000000000000;
			if (start == total_quotient.size()) { break; }
			middle_quotient <<= 8;
			middle_quotient |= total_quotient[start];
			start++;
		}
		total_quotient = std::move(temp_quotient);
		std::string middle_quotient_str = std::to_string(middle_quotient);
		while (middle_quotient_str.size() < 16)
		{
			middle_quotient_str.insert(middle_quotient_str.begin(), 1, '0');
		}
		//printf("%s\n", middle_quotient_str.c_str());
		res = middle_quotient_str + res;
	}
	Ullong last_remainder = 0;
	int offset = 0;
	for (auto one = total_quotient.end() - 1;; one--)
	{
		last_remainder |= ((Ullong)(*one)) << offset;
		offset += 8;
		if (one == total_quotient.begin()) { break; }
	}
	std::string last_remainder_str = std::to_string(last_remainder);
	//printf("%s\n", last_remainder_str.c_str());
	res = last_remainder_str + res;
	if (this->sign == -1)
	{
		res = '-' + res;
	}
	return res;
}
std::string DogNumber::BigInteger::getNum(int radix, bool isUpper)
{
	if (this->get_sign() == 0)
	{
		return "0";
	}
	if (radix > 16 || radix < 2)
	{
		throw number_exception(std::format("Error:radix must be between 2 and 16,now is %d\n错误：进制仅支持2-16，当前为%d", radix, radix).c_str(), __FILE__, __FUNCTION__, __LINE__);
	}
	if (radix == 16 && isUpper)
	{
		return this->getUpHEX();
	}
	else if (radix == 16 && !isUpper)
	{
		return this->getLowHEX();
	}
	Ullong long_radix = radix;
	while (long_radix < (0x0100000000000000 - 1))
	{
		long_radix *= radix;
	}
	long_radix /= radix;
	if (this->size() == 0 && this->num.at(0) == 0)
	{
		return "0";
	}
	std::vector<byte> total_quotient = this->num;
	std::string res;
	auto to_string = [radix, isUpper](Ullong a)->std::string
		{
			std::string res;
			while (a != 0)
			{
				char r = a % radix;
				if (r < 10)
				{
					r += '0';
				}
				else if (r >= 0)
				{
					r += isUpper ? 'A' - 10 : 'a' - 10;
				}
				res.insert(res.begin(), r);
				a /= radix;
			}
			return res;
		};
	while (total_quotient.size() > 7)
	{
		Ullong middle_quotient =
			((Ullong)total_quotient[0] << 48) |
			((Ullong)total_quotient[1] << 40) |
			((Ullong)total_quotient[2] << 32) |
			((Ullong)total_quotient[3] << 24) |
			((Ullong)total_quotient[4] << 16) |
			((Ullong)total_quotient[5] << 8) |
			((Ullong)total_quotient[6] << 0), start = 7;
		std::vector<byte> temp_quotient;
		while (true)
		{
			byte temp_singel_quotient = middle_quotient / long_radix;
			if (temp_singel_quotient != 0 || (temp_singel_quotient == 0 && temp_quotient.size() > 0))
			{
				temp_quotient.push_back(temp_singel_quotient);
			}
			middle_quotient = middle_quotient % long_radix;
			if (start == total_quotient.size()) { break; }
			middle_quotient <<= 8;
			middle_quotient |= total_quotient[start];
			start++;
		}
		total_quotient = std::move(temp_quotient);
		std::string middle_quotient_str = to_string(middle_quotient);
		while (middle_quotient_str.size() < 16)
		{
			middle_quotient_str.insert(middle_quotient_str.begin(), 1, '0');
		}
		//printf("%s\n", middle_quotient_str.c_str());
		res = middle_quotient_str + res;
	}
	Ullong last_remainder = 0;
	int offset = 0;
	for (auto one = total_quotient.end() - 1;; one--)
	{
		last_remainder |= ((Ullong)(*one)) << offset;
		offset += 8;
		if (one == total_quotient.begin()) { break; }
	}
	std::string last_remainder_str = to_string(last_remainder);
	//printf("%s\n", last_remainder_str.c_str());
	res = last_remainder_str + res;
	if (this->sign == -1)
	{
		res = '-' + res;
	}
	return res;
}
std::vector<DogNumber::byte> DogNumber::BigInteger::getBytes()
{
	return this->num;
}
DogNumber::Ullong DogNumber::BigInteger::size()
{
	return this->num.size();
}
void DogNumber::BigInteger::reserve(Ullong n)
{
	this->num.reserve(n);
}
void DogNumber::BigInteger::push_back(byte n)
{
	this->num.push_back(n);
}
void DogNumber::BigInteger::pop_back()
{
	this->num.pop_back();
}
DogNumber::byte& DogNumber::BigInteger::at(Ullong i)
{
	return this->num.at(i);
}
void DogNumber::BigInteger::insert(const std::vector<byte>::iterator pos, byte n)
{
	this->num.insert(pos, n);
}
char DogNumber::BigInteger::get_sign()
{
	return this->sign;
}
void DogNumber::BigInteger::change_sign()
{
	if (this->sign != 0)
	{
		this->sign *= -1;
	}
}
void DogNumber::BigInteger::set_positive()
{
	this->sign = 1;
}
void DogNumber::BigInteger::set_negative()
{
	this->sign = -1;
}
void DogNumber::BigInteger::reverse()
{
	for (int i = 0; i < this->num.size() / 2; i++)
	{
		byte tempB = this->num.at(i);
		this->num.at(i) = this->num.at(this->num.size() - i - 1);
		this->num.at(this->num.size() - i - 1) = tempB;
	}
}
void DogNumber::BigInteger::set2b(Ullong n)
{
	if (n == 0)
	{
		this->sign = 0;
	}
	else
	{
		this->sign = 1;
	}
	this->num.clear();
	this->reserve(n / 8);
	int m = 0;
	byte B = 0;
	for (Ullong i = 0; i < n; i++)
	{
		B |= (byte)(1) << m;
		m++;
		if (m == 8) { this->num.push_back(B); B = 0; m = 0; }
	}
	if (B != 0) { this->num.push_back(B); }
	this->reverse();
}
void DogNumber::BigInteger::set0()
{
	this->num.clear();
	this->num.push_back(0);
	this->sign = 0;
}

std::vector<DogNumber::byte>::iterator DogNumber::BigInteger::begin()
{
	return this->num.begin();
}
std::vector<DogNumber::byte>::iterator DogNumber::BigInteger::end()
{
	return this->num.end();
}

std::vector<DogNumber::byte>::const_iterator DogNumber::BigInteger::cbegin()
{
	return this->num.cbegin();
}
std::vector<DogNumber::byte>::const_iterator DogNumber::BigInteger::cend()
{
	return this->num.cend();
}

std::reverse_iterator<std::vector<DogNumber::byte>::iterator> DogNumber::BigInteger::rbegin()
{
	return this->num.rbegin();
}
std::reverse_iterator<std::vector<DogNumber::byte>::iterator> DogNumber::BigInteger::rend()
{
	return this->num.rend();
}

std::reverse_iterator<std::vector<DogNumber::byte>::const_iterator> DogNumber::BigInteger::crbegin()
{
	return this->num.crbegin();
}
std::reverse_iterator<std::vector<DogNumber::byte>::const_iterator> DogNumber::BigInteger::crend()
{
	return this->num.crend();
}

/*
	2025.2.10 23:19 在颓废了两天，看来无数时间的b站消遣之后，
	总是想起来用py检验正确性，发现90*60=36这种低级错误，然后发现是转换这里遇0就不加，气的写了这个东西
*/
DogNumber::BigInteger DogNumber::BigInteger::toBigInteger(uint8_t n)
{
	BigInteger res;
	if (n == 0)
	{
		return res;
	}
	else
	{
		res.pop_back();
		res.push_back(n);
		res.sign = 1;
	}
	return res;
}
DogNumber::BigInteger DogNumber::BigInteger::toBigInteger(uint16_t n)
{
	BigInteger res;
	if (n == 0)
	{
		return res;
	}
	else
	{
		res.sign = 1;
		res.pop_back();
	}
	res.reserve(2);
	bool high_is_not_zero = false;
	if ((byte)(n >> 8) != 0 || high_is_not_zero)
	{
		res.push_back((byte)(n >> 8));
		high_is_not_zero = true;
	}
	if ((byte)(n & 0xFF) || high_is_not_zero)
	{
		res.push_back((byte)(n & 0xFF));
		high_is_not_zero = true;
	}
	return res;
}
DogNumber::BigInteger DogNumber::BigInteger::toBigInteger(uint32_t n)
{
	BigInteger res;
	if (n == 0)
	{
		return res;
	}
	else
	{
		res.pop_back();
		res.sign = 1;
	}
	res.reserve(4);
	bool high_is_not_zero = false;
	if (((byte)(n >> 24)) || high_is_not_zero)
	{
		res.push_back((byte)(n >> 24));
		high_is_not_zero = true;
	}
	if (((byte)(n >> 16)) || high_is_not_zero)
	{
		res.push_back((byte)(n >> 16));
		high_is_not_zero = true;
	}
	if (((byte)(n >> 8)) || high_is_not_zero)
	{
		res.push_back((byte)(n >> 8));
		high_is_not_zero = true;
	}
	if (((byte)(n & 0xFF)) || high_is_not_zero)
	{
		res.push_back((byte)(n & 0xFF));
		high_is_not_zero = true;
	}
	return res;
}
DogNumber::BigInteger DogNumber::BigInteger::toBigInteger(uint64_t n)
{
	BigInteger res;
	if (n == 0)
	{
		return res;
	}
	else
	{
		res.sign = 1;
		res.pop_back();
	}
	res.reserve(8);
	bool high_is_not_zero = false;
	if (((byte)(n >> 56)) || high_is_not_zero)
	{
		res.push_back((byte)(n >> 56));
		high_is_not_zero = true;
	}
	if (((byte)(n >> 48)) || high_is_not_zero)
	{
		res.push_back((byte)(n >> 48));
		high_is_not_zero = true;
	}
	if (((byte)(n >> 40)) || high_is_not_zero)
	{
		res.push_back((byte)(n >> 40));
		high_is_not_zero = true;
	}
	if (((byte)(n >> 32)) || high_is_not_zero)
	{
		res.push_back((byte)(n >> 32));
		high_is_not_zero = true;
	}
	if (((byte)(n >> 24)) || high_is_not_zero)
	{
		res.push_back((byte)(n >> 24));
		high_is_not_zero = true;
	}
	if (((byte)(n >> 16)) || high_is_not_zero)
	{
		res.push_back((byte)(n >> 16));
		high_is_not_zero = true;
	}
	if (((byte)(n >> 8)) || high_is_not_zero)
	{
		res.push_back((byte)(n >> 8));
		high_is_not_zero = true;
	}
	if (((byte)(n & 0xFF)) || high_is_not_zero)
	{
		res.push_back((byte)(n & 0xFF));
		high_is_not_zero = true;
	}
	return res;
}
DogNumber::BigInteger DogNumber::BigInteger::toBigInteger(int8_t n)
{
	BigInteger res;
	if (n < 0)
	{
		res = toBigInteger((uint8_t)(-n));
		res.sign = -1;
	}
	else
	{
		res = toBigInteger((uint8_t)(n));
	}
	return res;
}
DogNumber::BigInteger DogNumber::BigInteger::toBigInteger(int16_t n)
{
	BigInteger res;
	if (n < 0)
	{
		res = toBigInteger((uint16_t)(-n));
	}
	else
	{
		res = toBigInteger((uint16_t)(n));
	}
	return res;

}
DogNumber::BigInteger DogNumber::BigInteger::toBigInteger(int32_t n)
{
	BigInteger res;
	if (n < 0)
	{
		res = toBigInteger((uint32_t)(-n));
		res.sign = -1;
	}
	else
	{
		res = toBigInteger((uint32_t)(n));
	}
	return res;
}
DogNumber::BigInteger DogNumber::BigInteger::toBigInteger(int64_t n)
{
	BigInteger res;
	if (n < 0)
	{
		res = toBigInteger((uint64_t)(-n));
		res.sign = -1;
	}
	else
	{
		res = toBigInteger((uint64_t)(n));
	}
	return res;
}

DogNumber::byte& DogNumber::BigInteger::operator[](Ullong i)
{
	return this->num[i];
}

DogNumber::BigInteger DogNumber::BigInteger::operator-()
{
	switch (this->get_sign())
	{
	case -1: this->set_positive(); break;
	case 1: this->set_negative(); break;
	}
	return *this;
}

DogNumber::BigInteger DogNumber::BigInteger::abs(BigInteger a)
{
	BigInteger res = a;
	res.sign = 1;
	return res;
}

int DogNumber::BigInteger::abs_compare(BigInteger a, BigInteger b)
{
	if (a.size() != b.size())
	{
		if (a.size() > b.size())
		{
			return 1;
		}
		else//if (a.size() < b.size())
		{
			return -1;
		}
	}
	auto a_it = a.cbegin(), b_it = b.cbegin();
	for (; (a_it != a.cend()) && (b_it != b.cend()); a_it++, b_it++)
	{
		if (*a_it > *b_it)
		{
			return 1;
		}
		else if (*a_it < *b_it)
		{
			return -1;
		}
	}
	return 0;
}

DogNumber::BigInteger DogNumber::BigInteger::add(BigInteger a, BigInteger b)
{
	if (a == 0) { return b; }
	if (b == 0) { return a; }
	BigInteger res;res.pop_back();
	int is_a_big = BigInteger::abs_compare(a, b);
	BigInteger* max = nullptr, * min = nullptr;
	if (is_a_big == 1) { max = &a; min = &b; }
	else { max = &b; min = &a; }
	if (a.sign == b.sign)
	{
		res.sign = a.sign;
		Ushort single_addition = 0;
		auto max_it = max->rbegin(), min_it = min->rbegin();
		for (; min_it != min->rend(); max_it++, min_it++)
		{
			single_addition += ((Ushort)*max_it + (Ushort)*min_it);
			res.insert(res.begin(), (byte)(single_addition & 0x00ff));
			single_addition >>= 8;
		}
		for (; max_it != max->rend(); max_it++)
		{
			single_addition += (Ushort)*max_it;
			res.insert(res.begin(), (byte)(single_addition & 0x00ff));
			single_addition >>= 8;
		}
		if (single_addition != 0)
		{
			res.insert(res.begin(), (byte)(single_addition & 0x00ff));
		}
	}
	else
	{
		res.sign = max->sign;
		short high_borrow = 0;
		auto max_it = max->rbegin(), min_it = min->rbegin();
		for (; min_it != min->rend(); max_it++, min_it++)
		{
			short temp = ((short)*max_it - high_borrow - (short)*min_it);
			if (temp < 0)
			{
				high_borrow = 1;
				temp += 256;
			}
			else
			{
				high_borrow = 0;
			}
			res.insert(res.begin(), (byte)(temp & 0x00ff));
		}
		for (; max_it != max->rend(); max_it++)
		{
			short temp = ((short)*max_it - high_borrow);
			if (temp < 0)
			{
				high_borrow = 1;
				temp += 256;
			}
			else
			{
				high_borrow = 0;
			}
			res.insert(res.begin(), (byte)(temp & 0x00ff));
		}
	}
	res.trims();
	return res;
}
DogNumber::BigInteger DogNumber::operator+(BigInteger a, BigInteger b)
{
	return DogNumber::BigInteger::add(a, b);
}
DogNumber::BigInteger DogNumber::BigInteger::add_other(BigInteger n)
{
	if (n.size() == 1 && n.get_sign() == 0 && n[0] == 0x00)
	{
		return *this;
	}
	if (this->size() == 1 && this->sign == 0 && this->num[0] == 0)
	{
		std::swap(*this, n);
		return *this;
	}
	int sign = BigInteger::abs_compare(*this, n);
	if (sign == 0 && (this->sign != n.get_sign()))
	{
		this->set0();
		return *this;
	}
	while (n.size() > this->size())
	{
		this->insert(this->begin(), 0x00);
	}
	BigInteger* max = nullptr, * min = nullptr;
	if (sign == 1)
	{
		max = this; min = &n;
	}
	else
	{
		max = &n; min = this;
	}
	if (this->sign == n.get_sign())
	{
		Ushort single_addition = 0;
		auto max_it = max->rbegin(), min_it = min->rbegin(), this_it = this->rbegin();
		for (; min_it != min->rend(); max_it++, min_it++, this_it++)
		{
			single_addition += ((Ushort)*max_it + (Ushort)*min_it);
			*this_it = (byte)(single_addition & 0x00ff);
			single_addition >>= 8;
		}
		for (; max_it != max->rend(); max_it++, this_it++)
		{
			single_addition += (Ushort)*max_it;
			*this_it = (byte)(single_addition & 0x00ff);
			single_addition >>= 8;

		}
		if (single_addition != 0)
		{
			this->insert(this->begin(), (byte)(single_addition & 0x00ff));
		}
	}
	else
	{
		short high_borrow = 0;
		auto max_it = max->rbegin(), min_it = min->rbegin(), this_it = this->rbegin();
		for (; min_it != min->rend(); max_it++, min_it++, this_it++)
		{
			short temp = ((short)*max_it - high_borrow - (short)*min_it);
			if (temp < 0)
			{
				high_borrow = 1;
				temp += 256;
			}
			else
			{
				high_borrow = 0;
			}
			*this_it = (byte)(temp & 0x00ff);
		}
		for (; max_it != max->rend(); max_it++, this_it++)
		{
			short temp = ((short)*max_it - high_borrow);
			if (temp < 0)
			{
				high_borrow = 1;
				temp += 256;
			}
			else
			{
				high_borrow = 0;
			}
			*this_it = (byte)(temp & 0x00ff);

		}
	}
	this->sign = max->get_sign();
	this->trims();
	return *this;
}
void DogNumber::operator+=(BigInteger& a, BigInteger b)
{
	a.add_other(b);
}

DogNumber::BigInteger DogNumber::BigInteger::subtract(BigInteger a, BigInteger b)
{
	if (a == 0)
	{
		b.change_sign();
		return b;
	}
	if (b == 0)
	{
		return a;
	}
	b.change_sign();
	return DogNumber::BigInteger::add(a, b);
}
DogNumber::BigInteger DogNumber::operator-(BigInteger a, BigInteger b)
{
	return DogNumber::BigInteger::subtract(a, b);
}
DogNumber::BigInteger DogNumber::BigInteger::subtract_other(BigInteger n)
{
	n.change_sign();
	return this->add_other(n);
}
void DogNumber::operator-=(BigInteger& a, BigInteger b)
{
	a.subtract_other(b);
}

DogNumber::BigInteger DogNumber::BigInteger::multiplysingle(BigInteger a, BigInteger b)
{
	Ushort res_ = (Ushort)a[0] * (Ushort)b[0];
	BigInteger res = BigInteger::toBigInteger(res_);
	res.trims();
	if (a.get_sign() == b.get_sign())
	{
		res.set_positive();
	}
	else
	{
		res.set_negative();
	}
	return res;
}
DogNumber::BigInteger DogNumber::BigInteger::multiplyDistribute(BigInteger a, BigInteger b)
{
	if (a.get_sign() == 0 || b.get_sign() == 0) { return BigInteger(); }
	BigInteger res, middle_addition;
	middle_addition.pop_back();
	middle_addition.set_positive();
	int is_a_big = BigInteger::abs_compare(a, b);
	BigInteger* max = nullptr, * min = nullptr;
	if (is_a_big == 1)
	{
		max = &a; min = &b;
	}
	else
	{
		max = &b; min = &a;
	}
	Ushort single_multiplication = 0;
	Ullong offset = 0;
	for (auto down = min->rbegin(); down != min->rend(); down++)
	{
		for (auto up = max->rbegin(); up != max->rend(); up++)
		{
			single_multiplication += ((Ushort)*down * (Ushort)*up);
			middle_addition.insert(middle_addition.begin(), (byte)(single_multiplication & 0x00ff));
			single_multiplication >>= 8;
		}
		if (single_multiplication != 0)
		{
			middle_addition.insert(middle_addition.begin(), (byte)(single_multiplication & 0x00ff));
		}
		for (Ullong i = 0; i < offset; i++)
		{
			middle_addition.push_back(0x00);
		}
		res = res + middle_addition;
		middle_addition.set0();
		middle_addition.pop_back();
		middle_addition.set_positive();
		single_multiplication = 0;
		offset++;
	}
	if (a.get_sign() == b.get_sign())
	{
		res.set_positive();
	}
	else
	{
		res.set_negative();
	}
	return res;
}
DogNumber::BigInteger DogNumber::BigInteger::multiplyKaratsuba0(BigInteger a, BigInteger b)
{
	if (a.get_sign() == 0 || b.get_sign() == 0)
	{
		//std::cout << space << "00" << std::endl;
		//std::cout << a.getUpHEX() << "*" << b.getUpHEX() << std::endl;

		return BigInteger();
	}
	if (a.size() == 1 && b.size() == 1)
	{
		//std::cout << space << BigInteger::multiplysingle(a, b).getUpHEX() << std::endl;
		//std::cout << a.getUpHEX() << "*" << b.getUpHEX() << std::endl;

		return BigInteger::multiplysingle(a, b);
	}
	if (a.size() == 1 || b.size() == 1)
	{
		//std::cout << space << BigInteger::multiplyDistribute(a, b).getUpHEX() << std::endl;
		//std::cout << a.getUpHEX() << "*" << b.getUpHEX() << std::endl;

		return BigInteger::multiplyDistribute(a, b);
	}
	Ullong n = a.size() > b.size() ? a.size() : b.size(), pow2 = 1;
	while (pow2 < n) { pow2 <<= 1; } n = pow2;
	while (a.size() < n) { a.insert(a.begin(), 0x00); }
	while (b.size() < n) { b.insert(b.begin(), 0x00); }
	//std::cout << a.getUpHEX() << "*" << b.getUpHEX() << std::endl;
	auto spilt = [](BigInteger& a, Ullong start, Ullong end)->DogNumber::BigInteger
		{
			BigInteger res;
			res.pop_back();
			res.set_positive();
			bool is_zero = true;
			for (Ullong i = start; i < end; ++i)
			{
				res.push_back(a[i]);
				if (a[i] != 0) { is_zero = false; }
			}
			if (is_zero) { return BigInteger(); }
			return res;
		};
	auto a_head = spilt(a, 0, (n >> 1)), a_tail = spilt(a, (n >> 1), n);
	auto b_head = spilt(b, 0, (n >> 1)), b_tail = spilt(b, (n >> 1), n);
	BigInteger head = multiplyKaratsuba0(a_head, b_head);
	BigInteger middle = multiplyKaratsuba0(a_head + a_tail, b_head + b_tail);
	BigInteger tail = multiplyKaratsuba0(a_tail, b_tail);
	middle -= head + tail;
	if (middle.get_sign() != 0)
	{
		for (Ullong i = 0; i < (n >> 1); i++) { middle.push_back(0x00); }
	}
	if (head.get_sign() != 0)
	{
		for (Ullong i = 0; i < n; i++) { head.push_back(0x00); }
	}
	BigInteger res = head + middle + tail;
	if (a.get_sign() == b.get_sign())
	{
		res.set_positive();
	}
	else
	{
		res.set_negative();
	}
	return res;
}

/*
DogNumber::BigInteger DogNumber::BigInteger::multiplyKaratsuba0_showing(BigInteger a, BigInteger b, std::string space)
{
	if (a.get_sign() == 0 || b.get_sign() == 0)
	{
		std::cout << space << a.getUpHEX() << "*" << b.getUpHEX() << std::endl;
		std::cout << space << "00" << std::endl;

		return BigInteger();
	}
	if (a.size() == 1 && b.size() == 1)
	{
		std::cout << space << a.getUpHEX() << "*" << b.getUpHEX() << std::endl;
		std::cout << space << BigInteger::multiplysingle(a, b).getUpHEX() << std::endl;

		return BigInteger::multiplysingle(a, b);
	}
	if (a.size() == 1 || b.size() == 1)
	{
		std::cout << space << a.getUpHEX() << "*" << b.getUpHEX() << std::endl;
		std::cout << space << BigInteger::multiplyDistribute(a, b).getUpHEX() << std::endl;

		return BigInteger::multiplyDistribute(a, b);
	}
	Ullong n = a.size() > b.size() ? a.size() : b.size(), pow2 = 1;
	while (pow2 < n) { pow2 <<= 1; } n = pow2;
	while (a.size() < n) { a.insert(a.begin(), 0x00); }
	while (b.size() < n) { b.insert(b.begin(), 0x00); }
	std::cout << space << a.getUpHEX() << "*" << b.getUpHEX() << std::endl;
	auto spilt = [](BigInteger& a, Ullong start, Ullong end)->DogNumber::BigInteger
		{
			BigInteger res;
			res.pop_back();
			res.set_positive();
			res.reverse();
			bool is_zero = true;
			for (Ullong i = start; i < end; ++i)
			{
				res.push_back(a[i]);
				if (a[i] != 0) { is_zero = false; }
			}
			if (is_zero) { return BigInteger(); }
			return res;
		};
	auto a_head = spilt(a, 0, (n >> 1)), a_tail = spilt(a, (n >> 1), n);
	auto b_head = spilt(b, 0, (n >> 1)), b_tail = spilt(b, (n >> 1), n);
	BigInteger head = multiplyKaratsuba0_showing(a_head, b_head, "| " + space);
	BigInteger middle = multiplyKaratsuba0_showing(a_head + a_tail, b_head + b_tail, "| " + space);
	BigInteger tail = multiplyKaratsuba0_showing(a_tail, b_tail, "| " + space);
	middle = middle - head - tail;
	if (middle.get_sign() != 0)
	{
		for (Ullong i = 0; i < (n >> 1); i++) { middle.push_back(0x00); }
	}
	if (head.get_sign() != 0)
	{
		for (Ullong i = 0; i < n; i++) { head.push_back(0x00); }
	}
	auto res= head + middle + tail;
	std::cout << space << res.getUpHEX()  << std::endl;
	return head + middle + tail;
}
*/
DogNumber::BigInteger DogNumber::BigInteger::multiplyKaratsuba1(BigInteger a, BigInteger b)
{
	//throw number_exception("Error:Not implemented\n错误：暂不支持的操作", __FILE__, __FUNCTION__, __LINE__);
	a.trims(); b.trims();
	if (a.get_sign() == 0 || b.get_sign() == 0) { return BigInteger(); }
	if (a.size() == 1 && b.size() == 1) { return BigInteger::multiplysingle(a, b); }
	if (a.size() == 1 || b.size() == 1) { return BigInteger::multiplyDistribute(a, b); }
	Ullong n = a.size() > b.size() ? a.size() : b.size(), pow2 = 1;
	while (pow2 < n) { pow2 <<= 1; } n = pow2;
	while (a.size() < n) { a.insert(a.begin(), 0x00); }
	while (b.size() < n) { b.insert(b.begin(), 0x00); }
	auto spilt = [](BigInteger& a, Ullong start, Ullong end)->DogNumber::BigInteger
		{
			BigInteger res;
			res.pop_back();
			res.set_positive();
			bool is_zero = true;
			for (Ullong i = start; i < end; ++i)
			{
				res.push_back(a[i]);
				if (a[i] != 0) { is_zero = false; }
			}
			if (is_zero) { return BigInteger(); }
			return res;
		};
	std::vector<std::pair<BigInteger, BigInteger>> pair_cache;

	/*
	auto space = [](Ullong n, Ullong m)->Ullong
		{
			Ullong time = 0;
			while (m >>= 1)
			{
				time++;
			}
			Ullong res = 1;
			//改为快速幂
			for (Ullong i = 0; i < time; i++)
			{
				res *= n;
			}
			return res;
		};
	Ullong temp_reserver = space(3, n);
	pair_cache.reserve(temp_reserver); sign_cache.reserve(temp_reserver);
	*/

	pair_cache.emplace_back(a, b);
	Ullong location = 0;
	while (location < pair_cache.size())
	{
		std::pair<BigInteger, BigInteger>& now_pair = pair_cache[location];

		Ullong a_len = now_pair.first.size(), b_len = now_pair.second.size();

		if (!(a_len == 1 || b_len == 1))
		{
			Ullong n = a_len > b_len ? a_len : b_len, pow2 = 1;
			while (pow2 < n) { pow2 <<= 1; } n = pow2;
			while (now_pair.first.size() < n) { now_pair.first.insert(now_pair.first.begin(), 0x00); }
			while (now_pair.second.size() < n) { now_pair.second.insert(now_pair.second.begin(), 0x00); }

			auto a_head = spilt(now_pair.first, 0, (n >> 1));
			auto a_tail = spilt(now_pair.first, (n >> 1), n);

			auto b_head = spilt(now_pair.second, 0, (n >> 1));
			auto b_tail = spilt(now_pair.second, (n >> 1), n);

			pair_cache.emplace_back(a_head, b_head);
			pair_cache.emplace_back(a_head + a_tail, b_head + b_tail);
			pair_cache.emplace_back(a_tail, b_tail);
		}
		location++;

	}

	/*
	for (auto& now_pair : pair_cache)
	{
		std::cout << now_pair.first.getUpHEX() << "*" << now_pair.second.getUpHEX() << std::endl;
	}
	std::cout << "-----------------------" << std::endl;
	*/

	std::deque<BigInteger> middle_cache;

	while (true)
	{
		auto now_pair = pair_cache.back();

		if (now_pair.first.size() == 1 && now_pair.second.size() == 1)
		{
			middle_cache.emplace_back(multiplysingle(now_pair.first, now_pair.second));
		}
		else if (now_pair.first.size() == 1 || now_pair.second.size() == 1)
		{
			middle_cache.emplace_back(multiplyDistribute(now_pair.first, now_pair.second));
		}
		else
		{
			Ullong n = now_pair.first.size();

			BigInteger tail = middle_cache.front();
			middle_cache.pop_front();
			BigInteger middle = middle_cache.front();
			middle_cache.pop_front();
			BigInteger head = middle_cache.front();
			middle_cache.pop_front();

			middle -= head + tail;
			if (middle.get_sign() != 0)
			{
				for (Ullong i = 0; i < (n >> 1); i++) { middle.push_back(0x00); }
			}
			if (head.get_sign() != 0)
			{
				for (Ullong i = 0; i < n; i++) { head.push_back(0x00); }
			}

			middle_cache.emplace_back(head + middle + tail);

		}

		/*
		for (auto& temp : middle_cache)
		{
			std::cout << temp.getUpHEX() << std::endl;
		}
		std::cout << "-----------------------" << std::endl;
		*/

		pair_cache.pop_back();

		if (pair_cache.size() == 0) { break; }
	}
	BigInteger res = middle_cache.back();
	if (a.get_sign() == b.get_sign())
	{
		res.set_positive();
	}
	else
	{
		res.set_negative();
	}
	return res;
}
DogNumber::BigInteger DogNumber::BigInteger::multiplyToomCook30(BigInteger a, BigInteger b)
{
	throw number_exception("Error:Not implemented\n错误：暂不支持的操作", __FILE__, __FUNCTION__, __LINE__);
	if (a.get_sign() == 0 || b.get_sign() == 0) { return BigInteger(); }
	Ullong a_len = a.size(), b_len = b.size();
	if (a_len == 1 && b_len == 1) { return multiplysingle(a, b); }
	if (a_len <= 3 || b_len <= 3) { return multiplyDistribute(a, b); }
	Ullong len = a_len > b_len ? a_len : b_len, pow3 = 1;
	while (pow3 < len) { pow3 *= 3; }

	while (a.size() < pow3) { a.insert(a.begin(), 0x00); }
	while (b.size() < pow3) { b.insert(b.begin(), 0x00); }
	auto spilt = [](BigInteger a, Ullong start, Ullong end)->BigInteger
		{
			BigInteger res;
			res.pop_back();
			res.set_positive();
			bool is_zero = true;
			for (Ullong i = start; i < end; ++i)
			{
				res.push_back(a[i]);
				if (a[i] != 0) { is_zero = false; }
			}
			if (is_zero) { return BigInteger(); }
			return res;
		};
	//a=a0+a1*x+a2*x^2
	BigInteger a0 = spilt(a, 0, (pow3 / 3));
	BigInteger a1 = spilt(a, (pow3 / 3), (pow3 / 3) * 2);
	BigInteger a2 = spilt(a, (pow3 / 3) * 2, pow3);

	BigInteger b0 = spilt(b, 0, (pow3 / 3));
	BigInteger b1 = spilt(b, (pow3 / 3), (pow3 / 3) * 2);
	BigInteger b2 = spilt(b, (pow3 / 3) * 2, pow3);
	//
	auto md = multiplyDistribute;
	BigInteger(*ti)(int32_t) = &toBigInteger;

	BigInteger a1_2 = md(a1, ti(2));
	BigInteger a2_4 = md(a2, ti(4));

	BigInteger b1_2 = md(b1, ti(2));
	BigInteger b2_4 = md(b2, ti(4));

	BigInteger a_ = multiplyToomCook30(a0, b0);
	BigInteger b_ = multiplyToomCook30(a0 + a1 + a2, b0 + b1 + b2);
	BigInteger c_ = multiplyToomCook30(a0 - a1 + a2, b0 - b1 + b2);
	BigInteger d_ = multiplyToomCook30(a0 + a1_2 + a2_4, b0 + b1_2 + b2_4);
	BigInteger e_ = multiplyToomCook30(a0 - a1_2 + a2_4, b0 - b1_2 + b2_4);

	auto change = [](BigInteger a)->uint64_t
		{
			uint64_t res = 0, n = 8;
			for (auto it = a.rbegin(); it != a.rend(); ++it)
			{
				res |= ((Ullong)*it << ((8 - n) * 8));
				if (--n == 0) { break; }
			}
			return res;
		};

	BigInteger w0 = a_;
	BigInteger w1 = md(b_, ti(8)) - md(c_, ti(8)) - d_ + e_;
	BigInteger w2 = md(a_, ti(-30)) + md(b_ + c_, ti(16)) - d_ - e_;
	BigInteger w3 = md(c_ - b_, ti(2)) + d_ - e_;
	BigInteger w4 = md(a_, ti(6)) - md(b_ + c_, ti(4)) + d_ + e_;

	Ullong w0_ = change(w0), w1_ = change(w1) / 12, w2_ = change(w2) / 24, w3_ = change(w3) / 24, w4_ = change(w4) / 24;

	BigInteger res;
	res.pop_back();
	res.push_back((byte)w4_);
	res.push_back((byte)w3_);
	res.push_back((byte)w2_);
	res.push_back((byte)w1_);
	res.push_back((byte)w0_);

	return res;
}
DogNumber::BigInteger DogNumber::BigInteger::multiplyToomCook31(BigInteger a, BigInteger b)
{
	throw number_exception("Error:Not implemented\n错误：暂不支持的操作", __FILE__, __FUNCTION__, __LINE__);
	return BigInteger();
}

void DogNumber::BigInteger::FFT0(std::vector<std::complex<double>>& a, int inverse)
{
	double pi = 3.14159265358979323;
	Ullong len = a.size(), lenHalf = len >> 1;
	if (len == 1) { return; }
	std::vector<std::complex<double>> a0(lenHalf), a1(lenHalf);
	for (Ullong i = 0; i < lenHalf; i++) { a0.at(i) = a.at(i * 2); a1.at(i) = a.at(i * 2 + 1); }
	FFT0(a0, inverse); FFT0(a1, inverse);
	std::complex<double> wk(1, 0), w1(cos(2 * pi / len), sin(2 * pi / len) * inverse);
	for (Ullong i = 0; i < lenHalf; i++, wk *= w1)
	{
		a.at(i) = a0.at(i) + wk * a1.at(i);
		a.at(i + lenHalf) = a0.at(i) - wk * a1.at(i);
	}
}
void DogNumber::BigInteger::FFT1(std::vector<std::complex<double>>& a, int inverse, std::vector<Ullong>& rev)
{
	double pi = 3.14159265358979323; Ullong lim = rev.size();
	for (Ullong i = 0; i < lim; i++) { if (rev.at(i) > i) { std::swap(a.at(i), a.at(rev.at(i))); } }
	Ullong num = 1; Ullong res = 0;
	while (lim > num)
	{
		num <<= 1;
		res++;
	}
	for (Ullong i = 1; i <= res; i++)
	{
		Ullong m = (Ullong)1 << i;
		std::complex<double> wn(cos(2 * pi / m), sin(2 * pi / m) * inverse);
		for (Ullong k = 0; k < lim; k += m)
		{
			std::complex<double> w(1, 0);
			for (Ullong j = 0; j < (m / 2); j++)
			{
				std::complex<double> t = w * a.at(k + j + m / 2);
				std::complex<double> u = a.at(k + j);
				a.at(k + j) = u + t;
				a.at(k + j + m / 2) = u - t;
				w = w * wn;
			}
		}
	}
}
void DogNumber::BigInteger::FNTT0(std::vector<Ullong>& a, int inverse)
{
	int g = 3, mod = 998244353, ig = 332748118;
	Ullong len = a.size(), lenHalf = len >> 1;
	if (len == 1) { return; }
	std::vector<Ullong> a0(lenHalf), a1(lenHalf);
	for (Ullong i = 0; i < lenHalf; i++) { a0[i] = a[i * 2]; a1[i] = a[i * 2 + 1]; }
	FNTT0(a0, inverse); FNTT0(a1, inverse);
	auto q_pow = [&mod](Ullong n, Ullong x)->Ullong
		{
			Ullong res(1);
			while (x)
			{
				if (x & 1)
				{
					res = (Ullong)1 * res * n % mod;
				}
				n = (Ullong)1 * n * n % mod;
				x >>= 1;
			}
			return res;
		};
	Ullong g1 = q_pow(inverse == 1 ? g : ig, (mod - 1) / len), gk = 1;
	for (Ullong i = 0; i < lenHalf; i++, gk = gk * g1 % mod)
	{
		a[i] = (a0[i] + a1[i] * gk) % mod;
		a[i + lenHalf] = (a0[i] - a1[i] * gk % mod + mod) % mod;
	}
}
void DogNumber::BigInteger::FNTT1(std::vector<Ullong>& a, int inverse, std::vector<Ullong>& rev)
{
	int g = 3, mod = 998244353, ig = 332748118;
	Ullong lim = rev.size();
	for (Ullong i = 0; i < lim; i++) { if (rev[i] > i) { std::swap(a[i], a[rev[i]]); } }
	auto q_pow = [&mod](Ullong n, Ullong x)->Ullong
		{
			Ullong res(1);
			while (x)
			{
				if (x & 1)
				{
					res = (Ullong)1 * res * n % mod;
				}
				n = (Ullong)1 * n * n % mod;
				x >>= 1;
			}
			return res;
		};
	for (Ullong i = 2; i <= lim; i <<= 1)
	{
		Ullong g1 = q_pow(inverse == 1 ? g : ig, (mod - 1) / i);
		for (Ullong j = 0; j < lim; j += i)
		{
			Ullong gk = 1;
			for (Ullong k = j; k < j + i / 2; ++k)
			{
				Ullong x = a[k], y = gk * a[k + i / 2] % mod;
				a[k] = (x + y) % mod; a[k + i / 2] = (x - y + mod) % mod;
				gk = gk * g1 % mod;
			}
		}
	}
}

void DogNumber::BigInteger::FNTTinv(std::vector<Ullong>& a, std::vector<Ullong>& rev)
{
	throw number_exception("Error:Not implemented\n错误：暂不支持的操作", __FILE__, __FUNCTION__, __LINE__);

}


DogNumber::BigInteger DogNumber::BigInteger::multiplyFFT0(BigInteger a, BigInteger b)
{
	Ullong n = 1;
	while (n < a.size() + b.size()) { n <<= 1; }
	std::vector<std::complex<double>> a0(n), b0(n);
	Ullong na = a.size(), nb = b.size();
	for (Ullong i = 0; i < n - na; i++) { a0.at(i) = std::complex<double>(0, 0); }
	for (Ullong i = 0; i < n - nb; i++) { b0.at(i) = std::complex<double>(0, 0); }
	for (Ullong i = n - na; i < n; i++) { a0.at(i) = std::complex<double>(a.at(i - n + na), 0); }
	for (Ullong i = n - nb; i < n; i++) { b0.at(i) = std::complex<double>(b.at(i - n + nb), 0); }
	FFT0(a0, 1); FFT0(b0, 1);
	for (Ullong i = 0; i < n; i++) { a0.at(i) *= b0.at(i); }
	FFT0(a0, -1);
	for (std::complex<double>& one : a0) { one.real(one.real() / n + 1e-6); }
	for (auto it = (a0.rbegin() + 1); it != a0.rend(); it++)
	{
		if (it->real() - 256 >= 1e-7)
		{
			if (it != a0.rend() - 1)
			{
				*(it + 1) += it->real() / 256;
				it->real((Ullong)it->real() % 256);
			}
			else
			{
				Ullong temp = it->real() / 256;
				it->real((Ullong)it->real() % 256);
				a0.insert(a0.begin(), std::complex<double>(temp / 1.0, 0.0));
				break;
			}

		}
	}
	Ullong max_size = a.size() + b.size() + 1, now_location = 0;
	BigInteger res; res.reserve(max_size); res.pop_back();
	for (auto it = (a0.rbegin() + 1); it != a0.rend(); it++)
	{
		res.insert(res.begin(), (byte)(it->real()));
		now_location++;
		if (now_location == max_size) { break; }
	}
	res.trims();
	if (a.get_sign() == b.get_sign())
	{
		res.set_positive();
	}
	else
	{
		res.set_negative();
	}
	return res;
}
DogNumber::BigInteger DogNumber::BigInteger::multiplyFFT1(BigInteger a, BigInteger b)
{
	Ullong n = 1;
	while (n < a.size() + b.size()) { n <<= 1; }
	std::vector<std::complex<double>> a0(n), b0(n);
	Ullong na = a.size(), nb = b.size();
	for (Ullong i = 0; i < n - na; i++) { a0.at(i) = std::complex<double>(0, 0); }
	for (Ullong i = 0; i < n - nb; i++) { b0.at(i) = std::complex<double>(0, 0); }
	for (Ullong i = n - na; i < n; i++) { a0.at(i) = std::complex<double>(a.at(i - n + na), 0); }
	for (Ullong i = n - nb; i < n; i++) { b0.at(i) = std::complex<double>(b.at(i - n + nb), 0); }
	Ullong len = 1, lim = 1;
	while (lim < a0.size()) { len++; lim <<= 1; }
	std::vector<Ullong> rev(lim);
	for (Ullong i = 0; i < lim; i++) { rev.at(i) = i; }
	for (Ullong i = 0; i < lim; i++) { rev[i] = (rev.at(i >> 1) >> 1) | ((i & 1) << (len - 2)); }
	FFT1(a0, 1, rev); FFT1(b0, 1, rev);
	for (Ullong i = 0; i < n; i++) { a0.at(i) *= b0.at(i); }
	FFT1(a0, -1, rev);
	for (std::complex<double>& one : a0) { one.real(one.real() / n + 1e-6); }
	for (auto it = (a0.rbegin() + 1); it != a0.rend(); it++)
	{
		if (it->real() - 256 >= 1e-7)
		{
			if (it != a0.rend() - 1)
			{
				*(it + 1) += it->real() / 256;
				it->real((Ullong)it->real() % 256);
			}
			else
			{
				Ullong temp = it->real() / 256;
				it->real((Ullong)it->real() % 256);
				a0.insert(a0.begin(), std::complex<double>(temp / 1.0, 0.0));
				break;
			}

		}
	}
	Ullong max_size = a.size() + b.size() + 1, now_location = 0;
	BigInteger res; res.reserve(max_size); res.pop_back();
	for (auto it = (a0.rbegin() + 1); it != a0.rend(); it++)
	{
		res.insert(res.begin(), (byte)(it->real()));
		now_location++;
		if (now_location == max_size) { break; }
	}
	res.trims();
	if (a.get_sign() == b.get_sign())
	{
		res.set_positive();
	}
	else
	{
		res.set_negative();
	}
	return res;
}
DogNumber::BigInteger DogNumber::BigInteger::multiplyFNTT0(BigInteger a, BigInteger b)
{
	Ullong n = 1;
	while (n < a.size() + b.size()) { n <<= 1; }
	std::vector<Ullong> a0(n), b0(n);
	Ullong na = a.size(), nb = b.size();
	for (Ullong i = 0; i < n - na; i++) { a0[i] = 0; }
	for (Ullong i = 0; i < n - nb; i++) { b0[i] = 0; }
	for (Ullong i = n - na; i < n; i++) { a0[i] = a[i - n + na]; }
	for (Ullong i = n - nb; i < n; i++) { b0[i] = b[i - n + nb]; }
	FNTT0(a0, 1); FNTT0(b0, 1);
	for (Ullong i = 0; i < n; i++) { a0[i] = a0[i] * b0[i] % 998244353; }
	FNTT0(a0, -1);
	auto ninv = [](Ullong a)-> long long
		{
			long long p = 998244353, p_ = 998244353, s0 = 0, s1 = 1, s2 = 0, q = 1, r = 1;
			while (r != 0)
			{
				q = p / a;
				r = p % a;
				p = a;
				a = r;
				s2 = s0 - s1 * q;
				s0 = s1;
				s1 = s2;
			}
			while (s0 < 0)
			{
				s0 += p_;
			}
			return s0;
		};
	for (Ullong& one : a0) { one = one * ninv(n) % 998244353; }
	for (auto it = (a0.rbegin() + 1); it != a0.rend(); it++)
	{
		if (*it >= 256)
		{
			if (it != a0.rend() - 1)
			{
				*(it + 1) += *it / 256;
				*it %= 256;
			}
			else
			{
				Ullong temp = *it / 256;
				*it %= 256;
				a0.insert(a0.begin(), temp);
				break;
			}

		}
	}
	Ullong max_size = a.size() + b.size() + 1, now_location = 0;
	BigInteger res; res.reserve(max_size); res.pop_back();
	for (auto it = (a0.rbegin() + 1); it != a0.rend(); it++)
	{
		res.insert(res.begin(), (byte)(*it));
		now_location++;
		if (now_location == max_size) { break; }
	}
	res.trims();
	if (a.get_sign() == b.get_sign())
	{
		res.set_positive();
	}
	else
	{
		res.set_negative();
	}
	return res;
}
DogNumber::BigInteger DogNumber::BigInteger::multiplyFNTT1(BigInteger a, BigInteger b)
{
	Ullong n = 1;
	while (n < a.size() + b.size()) { n <<= 1; }
	std::vector<Ullong> a0(n), b0(n);
	Ullong na = a.size(), nb = b.size();
	for (Ullong i = 0; i < n - na; i++) { a0[i] = 0; }
	for (Ullong i = 0; i < n - nb; i++) { b0[i] = 0; }
	for (Ullong i = n - na; i < n; i++) { a0[i] = a[i - n + na]; }
	for (Ullong i = n - nb; i < n; i++) { b0[i] = b[i - n + nb]; }
	Ullong len = 1, lim = 1;
	while (lim < a0.size()) { len++; lim <<= 1; }
	std::vector<Ullong> rev(lim);
	for (Ullong i = 0; i < lim; i++) { rev.at(i) = i; }
	for (Ullong i = 0; i < lim; i++) { rev[i] = (rev.at(i >> 1) >> 1) | ((i & 1) << (len - 2)); }
	FNTT1(a0, 1, rev); FNTT1(b0, 1, rev);
	for (Ullong i = 0; i < n; i++) { a0[i] = (a0[i] * b0[i]) % 998244353; }
	FNTT1(a0, -1, rev);
	auto ninv = [](Ullong a)-> long long
		{
			long long p = 998244353, p_ = 998244353, s0 = 0, s1 = 1, s2 = 0, q = 1, r = 1;
			while (r != 0)
			{
				q = p / a;
				r = p % a;
				p = a;
				a = r;
				s2 = s0 - s1 * q;
				s0 = s1;
				s1 = s2;
			}
			while (s0 < 0)
			{
				s0 += p_;
			}
			return s0;
		};
	/*
	* for (Ullong& one : a0) { one /= n; }
	* 以前这里是直接除以n，但现在快速数论变换实在模意义下的，不能直接除，需要转成n在模998244353下的逆元
	*/
	for (Ullong& one : a0) { one = one * ninv(n) % 998244353; }
	for (auto it = (a0.rbegin() + 1); it != a0.rend(); it++)
	{
		if (*it >= 256)
		{
			if (it != a0.rend() - 1)
			{
				*(it + 1) += *it / 256;
				*it %= 256;
			}
			else
			{
				Ullong temp = *it / 256;
				*it %= 256;
				a0.insert(a0.begin(), temp);
				break;
			}

		}
	}
	Ullong max_size = a.size() + b.size() + 1, now_location = 0;
	BigInteger res; res.reserve(max_size); res.pop_back();
	for (auto it = (a0.rbegin() + 1); it != a0.rend(); it++)
	{
		res.insert(res.begin(), (byte)(*it));
		now_location++;
		if (now_location == max_size) { break; }
	}
	res.trims();
	if (a.get_sign() == b.get_sign())
	{
		res.set_positive();
	}
	else
	{
		res.set_negative();
	}
	return res;
}

DogNumber::BigInteger DogNumber::BigInteger::multiply(BigInteger a, BigInteger b)
{
	BigInteger res;
	if (a.get_sign() == 0 || b.get_sign() == 0)
	{
		return 0;
	}
	else if (a.size() == 1)
	{
		res = multiplyDistribute(a, b);

	}
	else if (b.size() == 1)
	{
		res = multiplyDistribute(b, a);
	}
	else
	{
		res = multiplyFNTT1(a, b);
	}
	res.trims();
	if (a.get_sign() == b.get_sign())
	{
		res.set_positive();
	}
	else
	{
		res.set_negative();
	}
	return res;
}
DogNumber::BigInteger DogNumber::operator*(BigInteger a, BigInteger b)
{
	return BigInteger::multiply(a, b);
}
DogNumber::BigInteger DogNumber::BigInteger::multiply_other(BigInteger n)
{
	*this = std::move(multiply(*this, n));
	return *this;
}
void DogNumber::operator*=(BigInteger& a, BigInteger b)
{
	a.multiply_other(b);
}

std::pair<DogNumber::BigInteger, DogNumber::BigInteger> DogNumber::BigInteger::divideDistribute(BigInteger a, BigInteger b, bool is_round_zero)
{
	if (b.get_sign() == 0)
	{
		throw number_exception("Error: Divide by zero\n错误：除0错误", __FILE__, __FUNCTION__, __LINE__);
	}
	if (a.get_sign() == 0)
	{
		return std::pair<BigInteger, BigInteger>(0, b);
	}
	if (a == b)
	{
		return std::pair<BigInteger, BigInteger>(1, 0);
	}
	BigInteger* max = nullptr, * min = nullptr;
	switch (abs_compare(a, b))
	{
	case -1:
	{
		max = &b;
		min = &a;
		break;
	}
	case 0:
	{
		return std::pair<BigInteger, BigInteger>(-1, 0);
	}
	case 1:
	{
		max = &a;
		min = &b;
		break;
	}
	}
	auto spilt = [](BigInteger& a, Ullong start, Ullong end)->DogNumber::BigInteger
		{
			BigInteger res;
			res.pop_back();
			res.set_positive();
			bool is_zero = true;
			for (Ullong i = start; i < end; ++i)
			{
				res.push_back(a[i]);
				if (a[i] != 0) { is_zero = false; }
			}
			if (is_zero) { return BigInteger(); }
			return res;
		};
	BigInteger temp = spilt(*max, 0, min->size());
	byte now = 0x00;
	Ullong index = min->size();
	BigInteger res; res.reserve(max->size() - min->size() + 1);
	int min_sign = min->get_sign();
	min->set_positive();
	bool is_effive = false;
	while (index <= max->size())
	{
		while (temp > *min)
		{
			temp = temp - *min;
			now++;
		}
		if (now != 0)
		{
			is_effive = true;
			res.push_back(now);
		}
		else if (now == 0 && is_effive)
		{
			res.push_back(now);
		}
		if (index == max->size()) { break; }
		now = 0x00;
		temp.push_back(max->at(index));
		index++;
	}
	if (temp == *min)
	{
		res += 1;
		temp = 0;
	}
	if (min_sign == -1) { min->set_negative(); }
	if (a.get_sign() == b.get_sign())
	{
		res.set_positive();
	}
	else
	{
		res.set_negative();
	}
	if (!is_round_zero)
	{
		if (a.get_sign() == -1)
		{
			res -= 1;
		}
		if (a.get_sign() == 1 && b.get_sign() == -1)
		{
			temp = *min + temp;
		}
		else if (a.get_sign() == -1 && b.get_sign() == 1)
		{
			temp = *min - temp;
		}
		else if (a.get_sign() == -1 && b.get_sign() == -1)
		{
			temp.set_negative();
		}
	}
	else
	{
		if (a.get_sign() == -1)
		{
			temp.set_negative();
		}
	}
	return std::pair<BigInteger, BigInteger>(res, temp);
}

DogNumber::BigInteger DogNumber::BigInteger::divideNTT1(BigInteger a, BigInteger b)
{
	if (b.get_sign() == 0)
	{
		throw number_exception("Error: Divide by zero\n错误：除0错误", __FILE__, __FUNCTION__, __LINE__);
	}
	if (a.get_sign() == 0)
	{
		return 0;
	}
	if (a == b)
	{
		return 1;
	}
	throw number_exception("Error:Not implemented\n错误：暂不支持的操作", __FILE__, __FUNCTION__, __LINE__);


	return BigInteger();
}

//大于
bool DogNumber::operator>(BigInteger a, BigInteger b)
{
	if (a.get_sign() > b.get_sign())
	{
		return true;
	}
	else if (a.get_sign() < b.get_sign())
	{
		return false;
	}
	if (a.size() != b.size())
	{
		return a.size() > b.size();
	}
	else
	{
		for (Ullong i = 0; i < a.size(); i++)
		{
			if (a.at(i) > b.at(i))
			{
				return true;
			}
			else if (a.at(i) < b.at(i))
			{
				return false;
			}
		}
	}
	return false;
}
bool DogNumber::operator>(BigInteger a, uint8_t b)
{
	return a > BigInteger::toBigInteger(b);
}
bool DogNumber::operator>(BigInteger a, uint16_t b)
{
	return a > BigInteger::toBigInteger(b);
}
bool DogNumber::operator>(BigInteger a, uint32_t b)
{
	return a > BigInteger::toBigInteger(b);
}
bool DogNumber::operator>(BigInteger a, uint64_t b)
{
	return a > BigInteger::toBigInteger(b);
}
bool DogNumber::operator>(BigInteger a, int8_t b)
{
	return a > BigInteger::toBigInteger(b);
}
bool DogNumber::operator>(BigInteger a, int16_t b)
{
	return a > BigInteger::toBigInteger(b);
}
bool DogNumber::operator>(BigInteger a, int32_t b)
{
	return a > BigInteger::toBigInteger(b);
}
bool DogNumber::operator>(BigInteger a, int64_t b)
{
	return a > BigInteger::toBigInteger(b);
}

//大于等于
bool DogNumber::operator>=(BigInteger a, BigInteger b)
{
	if (a.get_sign() > b.get_sign())
	{
		return true;
	}
	else if (a.get_sign() < b.get_sign())
	{
		return false;
	}
	if (a.size() != b.size())
	{
		return a.size() > b.size();
	}
	else
	{
		for (Ullong i = 0; i < a.size(); i++)
		{
			if (a.at(i) > b.at(i))
			{
				return true;
			}
			else if (a.at(i) < b.at(i))
			{
				return false;
			}
		}
	}
	return true;
}
bool DogNumber::operator>=(BigInteger a, int8_t b)
{
	return a >= BigInteger::toBigInteger(b);
}
bool DogNumber::operator>=(BigInteger a, int16_t b)
{
	return a >= BigInteger::toBigInteger(b);
}
bool DogNumber::operator>=(BigInteger a, int32_t b)
{
	return a >= BigInteger::toBigInteger(b);
}
bool DogNumber::operator>=(BigInteger a, int64_t b)
{
	return a >= BigInteger::toBigInteger(b);
}
bool DogNumber::operator>=(BigInteger a, uint8_t b)
{
	return a >= BigInteger::toBigInteger(b);
}
bool DogNumber::operator>=(BigInteger a, uint16_t b)
{
	return a >= BigInteger::toBigInteger(b);
}
bool DogNumber::operator>=(BigInteger a, uint32_t b)
{
	return a >= BigInteger::toBigInteger(b);
}
bool DogNumber::operator>=(BigInteger a, uint64_t b)
{
	return a >= BigInteger::toBigInteger(b);
}

//小于
bool DogNumber::operator<(BigInteger a, BigInteger b)
{
	return !(a >= b);
}
bool DogNumber::operator<(BigInteger a, int8_t b)
{
	return a < BigInteger::toBigInteger(b);
}
bool DogNumber::operator<(BigInteger a, int16_t b)
{
	return a < BigInteger::toBigInteger(b);
}
bool DogNumber::operator<(BigInteger a, int32_t b)
{
	return a < BigInteger::toBigInteger(b);
}
bool DogNumber::operator<(BigInteger a, int64_t b)
{
	return a < BigInteger::toBigInteger(b);
}
bool DogNumber::operator<(BigInteger a, uint8_t b)
{
	return a < BigInteger::toBigInteger(b);
}
bool DogNumber::operator<(BigInteger a, uint16_t b)
{
	return a < BigInteger::toBigInteger(b);
}
bool DogNumber::operator<(BigInteger a, uint32_t b)
{
	return a < BigInteger::toBigInteger(b);
}
bool DogNumber::operator<(BigInteger a, uint64_t b)
{
	return a < BigInteger::toBigInteger(b);
}

//小于等于
bool DogNumber::operator<=(BigInteger a, BigInteger b)
{
	return !(a > b);
}
bool DogNumber::operator<=(BigInteger a, int8_t b)
{
	return a <= BigInteger::toBigInteger(b);
}
bool DogNumber::operator<=(BigInteger a, int16_t b)
{
	return a <= BigInteger::toBigInteger(b);
}
bool DogNumber::operator<=(BigInteger a, int32_t b)
{
	return a <= BigInteger::toBigInteger(b);
}
bool DogNumber::operator<=(BigInteger a, int64_t b)
{
	return a <= BigInteger::toBigInteger(b);
}
bool DogNumber::operator<=(BigInteger a, uint8_t b)
{
	return a <= BigInteger::toBigInteger(b);
}
bool DogNumber::operator<=(BigInteger a, uint16_t b)
{
	return a <= BigInteger::toBigInteger(b);
}
bool DogNumber::operator<=(BigInteger a, uint32_t b)
{
	return a <= BigInteger::toBigInteger(b);
}
bool DogNumber::operator<=(BigInteger a, uint64_t b)
{
	return a <= BigInteger::toBigInteger(b);
}

//等于
bool DogNumber::operator==(BigInteger a, BigInteger b)
{
	if (a.get_sign() != b.get_sign())
	{
		return false;
	}
	if (a.size() != b.size())
	{
		return false;
	}
	else
	{
		for (Ullong i = 0; i < a.size(); i++)
		{
			if (a.at(i) != b.at(i))
			{
				return false;
			}
		}
	}
	return true;
}
bool DogNumber::operator==(BigInteger a, int8_t b)
{
	return a == BigInteger::toBigInteger(b);
}
bool DogNumber::operator==(BigInteger a, int16_t b)
{
	return a == BigInteger::toBigInteger(b);
}
bool DogNumber::operator==(BigInteger a, int32_t b)
{
	return a == BigInteger::toBigInteger(b);
}
bool DogNumber::operator==(BigInteger a, int64_t b)
{
	return a == BigInteger::toBigInteger(b);
}
bool DogNumber::operator==(BigInteger a, uint8_t b)
{
	return a == BigInteger::toBigInteger(b);
}
bool DogNumber::operator==(BigInteger a, uint16_t b)
{
	return a == BigInteger::toBigInteger(b);
}
bool DogNumber::operator==(BigInteger a, uint32_t b)
{
	return a == BigInteger::toBigInteger(b);
}
bool DogNumber::operator==(BigInteger a, uint64_t b)
{
	return a == BigInteger::toBigInteger(b);
}

//不等于
bool DogNumber::operator!=(BigInteger a, BigInteger b)
{
	return !(a == b);
}
bool DogNumber::operator!=(BigInteger a, int8_t b)
{
	return a != BigInteger::toBigInteger(b);
}
bool DogNumber::operator!=(BigInteger a, int16_t b)
{
	return a != BigInteger::toBigInteger(b);
}
bool DogNumber::operator!=(BigInteger a, int32_t b)
{
	return a != BigInteger::toBigInteger(b);
}
bool DogNumber::operator!=(BigInteger a, int64_t b)
{
	return a != BigInteger::toBigInteger(b);
}
bool DogNumber::operator!=(BigInteger a, uint8_t b)
{
	return a != BigInteger::toBigInteger(b);
}
bool DogNumber::operator!=(BigInteger a, uint16_t b)
{
	return a != BigInteger::toBigInteger(b);
}
bool DogNumber::operator!=(BigInteger a, uint32_t b)
{
	return a != BigInteger::toBigInteger(b);
}
bool DogNumber::operator!=(BigInteger a, uint64_t b)
{
	return a != BigInteger::toBigInteger(b);
}

