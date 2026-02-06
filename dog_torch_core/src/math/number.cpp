#include "math/number.h"

#define DOG_ERROR_MINUS_SIGN_ERROR "Error:minus sign is not at first"
#define DOG_ERROR_WRONG_CHAR_HEX "Error:wrong char in hex\ncorrect chars are 0123456789abcdefABCDEF"
#define DOG_ERROR_WRONG_CHAR_DEC "Error:wrong char in oct\ncorrect chars are 0123456789"
#define DOG_ERROR_WRONG_CHAR_OCT "Error:wrong char in oct\ncorrect chars are 01234567"
#define DOG_ERROR_WRONG_CHAR_BIN "Error:wrong char in bin\ncorrect chars are 01"

#define DOG_ERROR_WRONG_RADIX std::format("Error:radix must be between 2 and 16,now is {}", radix)

#define DOG_ERROR_NO_SUPPORT "Error:Not support"

#define DOG_ERROR_DIVIDE_BY_ZERO "Error: Divide by zero"
#define DOG_ERROR_NEGATIVE_NUMBER "Error: no support Negative number"
#define DOG_ERROR_ZERO "Error: no support ZERO"

dog_torch::math::number::BigInteger::BigInteger()
{
	this->sign_ = 0;
	this->num_.push_back(0);
}
dog_torch::math::number::BigInteger::BigInteger(const char* str, const int radix)
{
	const char* p = str;
	uint64_t size = strlen(str);
	if (radix == HEX)
	{
		uint8_t temp = 0x00;
		int num = 0;//取值 0 1 2
		if (*str == '-')
		{
			this->num_.reserve((size - 1) >> 1);
			num = ((size & 0x01) == 0x01) ? 0 : 1;
		}
		else
		{
			this->num_.reserve(size >> 1);
			num = ((size & 0x01) == 0x00) ? 0 : 1;
		}
		while (*p != '\0')
		{
			if (*p == '-' && p == str)
			{
				this->sign_ = -1;
			}
			else if (*p == '-' && p != str)
			{
				throw NumberException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_MINUS_SIGN_ERROR));
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
				throw NumberException(
					DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_WRONG_CHAR_HEX)
				);
			}
			if (num == 2)
			{
				this->num_.push_back(temp);
				temp = 0x00;
				num = 0;
			}
			p++;
		}
	}
	else if (radix == OCT)
	{
		//--------------______
		uint32_t temp = 0x00000000;
		//0x00ff0000
		//0x0000ff00
		//0x000000ff
		int num = 0;//取值 0 1 2 3 4 5 6 7 8
		if (*str == '-')
		{
			this->num_.reserve((size - 1) * 3 / 8);
			num = (8 - (size - 1) % 8) % 8;
		}
		else
		{
			this->num_.reserve(size * 3 / 8);
			num = (8 - (size % 8)) % 8;
		}
		//printf("%d\n", num);
		auto filling = [&temp](uint8_t b, int num)->void
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
				this->sign_ = -1;
			}
			else if (*p == '-' && p != str)
			{
				throw NumberException(
					DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_MINUS_SIGN_ERROR)
				);
			}
			else if (*p >= '0' && *p <= '7')
			{
				filling(*p - '0', num);
				num++;
			}
			else
			{
				throw NumberException(
					DOG_EXCEPTION_MSG_OPINION()
				);
			}
			if (num == 8)
			{
				this->num_.push_back(((temp & 0x00ff0000) >> 16));
				this->num_.push_back(((temp & 0x0000ff00) >> 8));
				this->num_.push_back((temp & 0x000000ff));
				num = 0;
				temp = 0x00000000;
			}
			p++;
		}
	}
	else if (radix == BIN)
	{
		uint8_t temp = 0x00;
		int num = 0;//取值 0 1 2 3 4 5 6 7 8
		if (*str == '-')
		{
			this->num_.reserve(((size - 1) / 8) + 1);
			num = (8 - (size - 1) % 8) % 8;
		}
		else
		{
			this->num_.reserve((size / 8) + 1);
			num = (8 - (size % 8)) % 8;
		}
		//printf("%d\n", num);
		auto filling = [&temp](uint8_t b, int num)->void
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
				this->sign_ = -1;
			}
			else if (*p == '-' && p != str)
			{
				throw NumberException(
					DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_MINUS_SIGN_ERROR)
				);
			}
			else if (*p == '0' || *p == '1')
			{
				filling(*p - '0', num);
				num++;
			}
			else
			{
				throw NumberException(
					DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_WRONG_CHAR_BIN)
				);
			}
			if (num == 8)
			{
				this->num_.push_back(temp);
				temp = 0x00;
				num = 0;
			}
			p++;
		}

	}
	else if (radix == DEC)
	{
		/*
		std::vector<uint8_t> temp_quotient;//商
		uint64_t start = 0;
		if (*str != '-')
		{
			temp_quotient.reserve(size);
			for (uint64_t i = 0; i < size; i++)
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
			for (uint64_t i = 1; i < size; i++)
			{
				temp_quotient.push_back(*p - '0');
				p++;
			}
		}
		uint8_t highSet = 0;
		auto isZero = [&start](std::vector<uint8_t> tempBs)->bool
			{
				for (uint64_t i = start; i < tempBs.size(); i++)
				{
					if (tempBs.at(i) != 0) { return false; }
				}
				return true;
			};
		while (temp_quotient.size() != start && !isZero(temp_quotient))
		{
			uint8_t B = 0;
			for (int j = 0; j < 8; j++)
			{
				B |= (uint8_t)(temp_quotient.at(temp_quotient.size() - 1) % 2) << j;
				for (uint64_t i = start; i < temp_quotient.size(); i++)
				{
					uint8_t c = highSet * 10 + temp_quotient.at(i);
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

		std::vector<uint8_t> total_quotient;
		if (*str != '-')
		{
			total_quotient.reserve(size);
			for (uint64_t i = 0; i < size; i++)
			{
				total_quotient.push_back(*p - '0');
				p++;
			}
		}
		else
		{
			total_quotient.reserve(size - 1);
			this->sign_ = -1;
			p++;
			for (uint64_t i = 1; i < size; i++)
			{
				if (*p - '0' < 0 || *p - '0' > 9)
				{
					throw NumberException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_WRONG_CHAR_DEC));
				}
				total_quotient.push_back(*p - '0');
				p++;
			}
		}
		while (total_quotient.size() > 2)
		{
			uint64_t middle_quotient = total_quotient[0] * 100 + total_quotient[1] * 10 + total_quotient[2];
			uint64_t start = 3;
			std::vector<uint8_t> temp_quotient;
			while (true)
			{
				uint8_t temp_singel_quotient = middle_quotient / 256;
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
			this->num_.insert(this->num_.begin(), middle_quotient);
		}
		if (total_quotient.size() == 2)
		{
			this->num_.insert(this->num_.begin(), total_quotient[0] * 10 + total_quotient[1]);
		}
		else if (total_quotient.size() == 1)
		{
			this->num_.insert(this->num_.begin(), total_quotient[0]);
		}

	}

	this->trims();
	if (this->sign_ != -1 && this->num_.size() == 1 && this->num_.front() == 0)
	{
		this->sign_ = 0;
	}
	else if (this->sign_ != -1)
	{
		this->sign_ = 1;
	}

}
dog_torch::math::number::BigInteger::BigInteger(const std::string& str, const int radix)
{
	const char* p = str.c_str();
	const char* str_ = str.c_str();
	uint64_t size = str.size();
	if (radix == HEX)
	{
		uint8_t temp = 0x00;
		int num = 0;//取值 0 1 2
		if (*str_ == '-')
		{
			this->num_.reserve((size - 1) / 2);
			num = ((size & 0x01) == 0x01) ? 0 : 1;
		}
		else
		{
			this->num_.reserve(size / 2);
			num = ((size & 0x01) == 0x00) ? 0 : 1;
		}
		for (uint64_t i = 0; i < size; ++i)
		{
			if (*p == '-' && p == str_)
			{
				this->sign_ = -1;
			}
			else if (*p == '-' && p != str_)
			{
				throw NumberException(
					DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_MINUS_SIGN_ERROR)
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
				throw NumberException(
					DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_WRONG_CHAR_HEX)
				);
			}
			if (num == 2)
			{
				this->num_.push_back(temp);
				temp = 0x00;
				num = 0;
			}
			p++;
		}
	}
	else if (radix == OCT)
	{
		//--------------______
		uint32_t temp = 0x00000000;
		//0x00ff0000
		//0x0000ff00
		//0x000000ff
		int num = 0;//取值 0 1 2 3 4 5 6 7 8
		if (*str_ == '-')
		{
			this->num_.reserve((size - 1) * 3 / 8);
			num = (8 - (size - 1) % 8) % 8;
		}
		else
		{
			this->num_.reserve(size * 3 / 8);
			num = (8 - (size % 8)) % 8;
		}
		//printf("%d\n", num);
		auto filling = [&temp](uint8_t b, int num)->void
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
		for (uint64_t i = 0; i < size; ++i)
		{
			if (*p == '-' && p == str_)
			{
				this->sign_ = -1;
			}
			else if (*p == '-' && p != str_)
			{
				throw NumberException(
					DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_MINUS_SIGN_ERROR)
				);
			}
			else if (*p >= '0' && *p <= '7')
			{
				filling(*p - '0', num);
				num++;
			}
			else
			{
				throw NumberException(
					DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_WRONG_CHAR_OCT)
				);
			}
			if (num == 8)
			{
				this->num_.push_back(((temp & 0x00ff0000) >> 16));
				this->num_.push_back(((temp & 0x0000ff00) >> 8));
				this->num_.push_back((temp & 0x000000ff));
				num = 0;
				temp = 0x00000000;
			}
			p++;
		}
	}
	else if (radix == BIN)
	{
		uint8_t temp = 0x00;
		int num = 0;//取值 0 1 2 3 4 5 6 7 8
		if (*str_ == '-')
		{
			this->num_.reserve(((size - 1) / 8) + 1);
			num = (8 - (size - 1) % 8) % 8;
		}
		else
		{
			this->num_.reserve((size / 8) + 1);
			num = (8 - (size % 8)) % 8;
		}
		//printf("%d\n", num);
		auto filling = [&temp](uint8_t b, int num)->void
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
		for (uint64_t i = 0; i < size; ++i)
		{
			if (*p == '-' && p == str_)
			{
				this->sign_ = -1;
			}
			else if (*p == '-' && p != str_)
			{
				throw NumberException(
					DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_MINUS_SIGN_ERROR)
				);
			}
			else if (*p == '0' || *p == '1')
			{
				filling(*p - '0', num);
				num++;
			}
			else
			{
				throw NumberException(
					DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_WRONG_CHAR_BIN)
				);
			}
			if (num == 8)
			{
				this->num_.push_back(temp);
				temp = 0x00;
				num = 0;
			}
			p++;
		}

	}
	else if (radix == DEC)
	{
		std::vector<uint8_t> total_quotient;
		if (*str_ != '-')
		{
			total_quotient.reserve(size);
			for (uint64_t i = 0; i < size; i++)
			{
				total_quotient.push_back(*p - '0');
				p++;
			}
		}
		else
		{
			total_quotient.reserve(size - 1);
			this->sign_ = -1;
			p++;
			for (uint64_t i = 1; i < size; i++)
			{
				total_quotient.push_back(*p - '0');
				p++;
			}
		}
		while (total_quotient.size() > 2)
		{
			uint64_t middle_quotient = total_quotient[0] * 100 + total_quotient[1] * 10 + total_quotient[2];
			uint64_t start = 3;
			std::vector<uint8_t> temp_quotient;
			while (true)
			{
				uint8_t temp_singel_quotient = middle_quotient / 256;
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
			this->num_.insert(this->num_.begin(), middle_quotient);
		}
		switch (total_quotient.size())
		{
		case 1:
		{
			this->num_.insert(this->num_.begin(), total_quotient[0]);
			break;
		}
		case 2:
		{
			this->num_.insert(this->num_.begin(), total_quotient[0] * 10 + total_quotient[1]);
			break;
		}
		}
	}

	this->trims();
	if (this->sign_ != -1 && this->num_.size() == 1 && this->num_.front() == '0')
	{
		this->sign_ = 0;
	}
	else if (this->sign_ != -1)
	{
		this->sign_ = 1;
	}
}
dog_torch::math::number::BigInteger::BigInteger(const std::vector<char>& str, const int radix)
{
	const char* p = &str.at(0);
	const char* str_ = &str.at(0);
	uint64_t size = str.size();
	if (radix == HEX)
	{
		uint8_t temp = 0x00;
		int num = 0;//取值 0 1 2
		if (*str_ == '-')
		{
			this->num_.reserve((size - 1) / 2);
			num = ((size & 0x01) == 0x01) ? 0 : 1;
		}
		else
		{
			this->num_.reserve(size / 2);
			num = ((size & 0x01) == 0x00) ? 0 : 1;
		}
		for (uint64_t i = 0; i < size; ++i)
		{
			if (*p == '-' && p == str_)
			{
				this->sign_ = -1;
			}
			else if (*p == '-' && p != str_)
			{
				throw NumberException(
					DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_MINUS_SIGN_ERROR)
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
				throw NumberException(
					DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_WRONG_CHAR_HEX)
				);
			}
			if (num == 2)
			{
				this->num_.push_back(temp);
				temp = 0x00;
				num = 0;
			}
			p++;
		}
	}
	else if (radix == OCT)
	{
		//--------------______
		uint32_t temp = 0x00000000;
		//0x00ff0000
		//0x0000ff00
		//0x000000ff
		int num = 0;//取值 0 1 2 3 4 5 6 7 8
		if (*str_ == '-')
		{
			this->num_.reserve((size - 1) * 3 / 8);
			num = (8 - (size - 1) % 8) % 8;
		}
		else
		{
			this->num_.reserve(size * 3 / 8);
			num = (8 - (size % 8)) % 8;
		}
		//printf("%d\n", num);
		auto filling = [&temp](uint8_t b, int num)->void
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
		for (uint64_t i = 0; i < size; ++i)
		{
			if (*p == '-' && p == str_)
			{
				this->sign_ = -1;
			}
			else if (*p == '-' && p != str_)
			{
				throw NumberException(
					DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_MINUS_SIGN_ERROR)
				);
			}
			else if (*p >= '0' && *p <= '7')
			{
				filling(*p - '0', num);
				num++;
			}
			else
			{
				throw NumberException(
					DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_WRONG_CHAR_OCT)
				);
			}
			if (num == 8)
			{
				this->num_.push_back(((temp & 0x00ff0000) >> 16));
				this->num_.push_back(((temp & 0x0000ff00) >> 8));
				this->num_.push_back((temp & 0x000000ff));
				num = 0;
				temp = 0x00000000;
			}
			p++;
		}
	}
	else if (radix == BIN)
	{
		uint8_t temp = 0x00;
		int num = 0;//取值 0 1 2 3 4 5 6 7 8
		if (*str_ == '-')
		{
			this->num_.reserve(((size - 1) / 8) + 1);
			num = (8 - (size - 1) % 8) % 8;
		}
		else
		{
			this->num_.reserve((size / 8) + 1);
			num = (8 - (size % 8)) % 8;
		}
		//printf("%d\n", num);
		auto filling = [&temp](uint8_t b, int num)->void
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
		for (uint64_t i = 0; i < size; ++i)
		{
			if (*p == '-' && p == str_)
			{
				this->sign_ = -1;
			}
			else if (*p == '-' && p != str_)
			{
				throw NumberException(
					DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_MINUS_SIGN_ERROR)
				);
			}
			else if (*p == '0' || *p == '1')
			{
				filling(*p - '0', num);
				num++;
			}
			else
			{
				throw NumberException(
					DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_WRONG_CHAR_BIN)
				);
			}
			if (num == 8)
			{
				this->num_.push_back(temp);
				temp = 0x00;
				num = 0;
			}
			p++;
		}

	}
	else if (radix == DEC)
	{
		std::vector<uint8_t> total_quotient;
		if (*str_ != '-')
		{
			total_quotient.reserve(size);
			for (uint64_t i = 0; i < size; i++)
			{
				total_quotient.push_back(*p - '0');
				p++;
			}
		}
		else
		{
			total_quotient.reserve(size - 1);
			this->sign_ = -1;
			p++;
			for (uint64_t i = 1; i < size; i++)
			{
				total_quotient.push_back(*p - '0');
				p++;
			}
		}
		while (total_quotient.size() > 2)
		{
			uint64_t middle_quotient = total_quotient[0] * 100 + total_quotient[1] * 10 + total_quotient[2];
			uint64_t start = 3;
			std::vector<uint8_t> temp_quotient;
			while (true)
			{
				uint8_t temp_singel_quotient = middle_quotient / 256;
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
			this->num_.insert(this->num_.begin(), middle_quotient);
		}
		if (total_quotient.size() == 2)
		{
			this->num_.insert(this->num_.begin(), total_quotient[0] * 10 + total_quotient[1]);
		}
		else
		{
			this->num_.insert(this->num_.begin(), total_quotient[0]);
		}
	}

	this->trims();
	if (this->sign_ != -1 && this->num_.size() == 1 && this->num_.front() == '0')
	{
		this->sign_ = 0;
	}
	else if (this->sign_ != -1)
	{
		this->sign_ = 1;
	}
}

dog_torch::math::number::BigInteger::BigInteger(uint8_t n)
{
	BigInteger::toBigInteger(n).swap(*this);
}
dog_torch::math::number::BigInteger::BigInteger(uint16_t n)
{
	BigInteger::toBigInteger(n).swap(*this);
}
dog_torch::math::number::BigInteger::BigInteger(uint32_t n)
{
	BigInteger::toBigInteger(n).swap(*this);
}
dog_torch::math::number::BigInteger::BigInteger(uint64_t n)
{
	BigInteger::toBigInteger(n).swap(*this);
}
dog_torch::math::number::BigInteger::BigInteger(int8_t n)
{
	BigInteger::toBigInteger(n).swap(*this);
}
dog_torch::math::number::BigInteger::BigInteger(int16_t n)
{
	BigInteger::toBigInteger(n).swap(*this);
}
dog_torch::math::number::BigInteger::BigInteger(int32_t n)
{
	BigInteger::toBigInteger(n).swap(*this);
}
dog_torch::math::number::BigInteger::BigInteger(int64_t n)
{
	BigInteger::toBigInteger(n).swap(*this);
}

dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::from_vector(const std::vector<uint8_t>& v, char sign)
{
	if (v.empty()) return BigInteger(0);
	BigInteger res;
	res.sign_ = sign;
	for (auto& b : v)
	{
		res.num_.push_back(b);
	}
	res.reverse();
	if (res.size() == 1 && res[0] == 0x00)
	{
		res.sign_ = 0;
	}
	return res;
}

void dog_torch::math::number::BigInteger::swap(BigInteger& b)
{
	std::swap(this->num_, b.num_);
	std::swap(this->sign_, b.sign_);
}

void dog_torch::math::number::BigInteger::trims()
{
	while (*(this->num_.begin()) == 0x00 && this->num_.size() > 1)
	{
		this->num_.erase(this->num_.begin());
	}
	if (this->num_.size() == 1 && this->num_.front() == 0x00)
	{
		this->sign_ = 0;
	}
	this->num_.shrink_to_fit();
}
std::string dog_torch::math::number::BigInteger::getUpHEX() const
{
	std::string res;
	if (sign_ == -1)
	{
		res.reserve(this->num_.size() + 1);
		res += '-';
	}
	else
	{
		res.reserve(this->num_.size());
	}
	char hexChar[17] = "0123456789ABCDEF";
	for (uint8_t b : this->num_)
	{
		res.push_back(hexChar[(b & 0xF0) >> 4]);
		res.push_back(hexChar[(b & 0x0F)]);
	}
	return res;
}
std::string dog_torch::math::number::BigInteger::getLowHEX() const
{
	std::string res;
	if (sign_ == -1)
	{
		res.reserve(this->num_.size() + 1);
		res += '-';
	}
	else
	{
		res.reserve(this->num_.size());
	}
	char hexChar[17] = "0123456789abcdef";
	for (uint8_t b : this->num_)
	{
		res.push_back(hexChar[(b & 0xF0) >> 4]);
		res.push_back(hexChar[(b & 0x0F)]);
	}
	return res;
}
std::string dog_torch::math::number::BigInteger::getDEC() const
{
	/*
	BigInteger temp = *this;
	BigInteger res;
	uint16_t tB = 0;
	std::string NumStr;
	std::string DecChars;
	bool isFillHigh = false;
	while (temp != 0)
	{
		for (uint64_t i = 0; i < temp.size(); i++)
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
		NumStr = std::to_string((uint8_t)(tB >> 8));
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
	if (this->size() == 0 && this->num_.at(0) == 0)
	{
		return "0";
	}
	std::vector<uint8_t> total_quotient = this->num_;
	std::string res;
	while (total_quotient.size() > 7)
	{
		uint64_t middle_quotient =
			((uint64_t)total_quotient[0] << 48) |
			((uint64_t)total_quotient[1] << 40) |
			((uint64_t)total_quotient[2] << 32) |
			((uint64_t)total_quotient[3] << 24) |
			((uint64_t)total_quotient[4] << 16) |
			((uint64_t)total_quotient[5] << 8) |
			((uint64_t)total_quotient[6] << 0), start = 7;
		std::vector<uint8_t> temp_quotient;
		while (true)
		{
			uint8_t temp_singel_quotient = middle_quotient / 10000000000000000;
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
	uint64_t last_remainder = 0;
	int offset = 0;
	for (auto one = total_quotient.end() - 1;; one--)
	{
		last_remainder |= ((uint64_t)(*one)) << offset;
		offset += 8;
		if (one == total_quotient.begin()) { break; }
	}
	std::string last_remainder_str = std::to_string(last_remainder);
	//printf("%s\n", last_remainder_str.c_str());
	res = last_remainder_str + res;
	if (this->sign_ == -1)
	{
		res = '-' + res;
	}
	return res;
}
std::string dog_torch::math::number::BigInteger::to_num_string(int radix, bool isUpper) const
{
	if (this->get_sign() == 0)
	{
		return "0";
	}
	if (radix > 16 || radix < 2)
	{
		throw NumberException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_WRONG_RADIX));
	}
	if (radix == 16 && isUpper)
	{
		return this->getUpHEX();
	}
	else if (radix == 16 && !isUpper)
	{
		return this->getLowHEX();
	}
	uint64_t long_radix = radix;
	while (long_radix < (0x0100000000000000 - 1))
	{
		long_radix *= radix;
	}
	long_radix /= radix;
	if (this->size() == 0 && this->num_.at(0) == 0)
	{
		return "0";
	}
	std::vector<uint8_t> total_quotient = this->num_;
	std::string res;
	auto to_string = [radix, isUpper](uint64_t a)->std::string
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
		uint64_t middle_quotient =
			((uint64_t)total_quotient[0] << 48) |
			((uint64_t)total_quotient[1] << 40) |
			((uint64_t)total_quotient[2] << 32) |
			((uint64_t)total_quotient[3] << 24) |
			((uint64_t)total_quotient[4] << 16) |
			((uint64_t)total_quotient[5] << 8) |
			((uint64_t)total_quotient[6] << 0), start = 7;
		std::vector<uint8_t> temp_quotient;
		while (true)
		{
			uint8_t temp_singel_quotient = middle_quotient / long_radix;
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
	uint64_t last_remainder = 0;
	int offset = 0;
	for (auto one = total_quotient.end() - 1;; one--)
	{
		last_remainder |= ((uint64_t)(*one)) << offset;
		offset += 8;
		if (one == total_quotient.begin()) { break; }
	}
	std::string last_remainder_str = to_string(last_remainder);
	//printf("%s\n", last_remainder_str.c_str());
	res = last_remainder_str + res;
	if (this->sign_ == -1)
	{
		res = '-' + res;
	}
	return res;
}
std::vector<uint8_t> dog_torch::math::number::BigInteger::to_byte_vector() const
{
	return this->num_;
}
uint64_t dog_torch::math::number::BigInteger::to_abs_uint64() const
{
	if (this->num_.empty())
	{
		return 0;
	}
	uint64_t n = 0;
	for (uint64_t i = 0; i < (8 > this->num_.size() ? this->num_.size() : 8); i++)
	{
		n |= ((uint64_t)this->num_[i]) << (56 - (i * 8));
	}
	return n >> ((8 - this->num_.size()) * 8);
}
double dog_torch::math::number::BigInteger::to_float64() const
{
	if (this->sign_ == 0)
	{
		return 0.0;
	}
	uint64_t e = this->size() < 128 ? this->size() * 8 : 1024;
	uint64_t byte_pos = 0;
	uint8_t bit_pos = 0;
	for (int i = 0;i < 8;i++)
	{
		if (this->num_[0] >> (7 - i) & 0x01) break;
		e--;
		bit_pos++;
	}
	e += 1022;
	uint64_t buf = 0;
	for (int i = 0;i < 53;i++)
	{
		if (byte_pos >= this->num_.size()) break;
		buf |= (((uint64_t)this->num_[byte_pos]) >> (7 - bit_pos) & 0x01) << (52 - i);
		if (bit_pos == 7)
		{
			bit_pos = 0;
			byte_pos++;
		}
		else
		{
			bit_pos++;
		}
	}
	buf &= 0x0FFFFFFFFFFFFF;
	buf |= ((e & 0x07FF) << 52);
	buf |= ((uint64_t)(this->sign_ >= 0 ? 0 : 1) << 63);
	double result;
	std::memcpy(&result, &buf, sizeof(result));
	return result;
}
uint64_t dog_torch::math::number::BigInteger::size() const
{
	return this->num_.size();
}
void dog_torch::math::number::BigInteger::reserve(uint64_t n)
{
	this->num_.reserve(n);
}
void dog_torch::math::number::BigInteger::push_back(uint8_t n)
{
	this->num_.push_back(n);
}
void dog_torch::math::number::BigInteger::pop_back()
{
	this->num_.pop_back();
}
uint8_t& dog_torch::math::number::BigInteger::at(uint64_t i)
{
	return this->num_.at(i);
}
uint8_t& dog_torch::math::number::BigInteger::operator[](uint64_t i)
{
	return this->num_[i];
}
const uint8_t& dog_torch::math::number::BigInteger::at(uint64_t i) const
{
	return this->num_.at(i);
}
const uint8_t& dog_torch::math::number::BigInteger::operator[](uint64_t i) const
{
	return (this->num_)[i];
}
void dog_torch::math::number::BigInteger::insert(const std::vector<uint8_t>::iterator pos, uint8_t n)
{
	this->num_.insert(pos, n);
}
char dog_torch::math::number::BigInteger::get_sign() const
{
	return this->sign_;
}
void dog_torch::math::number::BigInteger::change_sign()
{
	if (this->sign_ != 0)
	{
		this->sign_ *= -1;
	}
}
void dog_torch::math::number::BigInteger::set_positive()
{
	this->sign_ = 1;
}
void dog_torch::math::number::BigInteger::set_negative()
{
	this->sign_ = -1;
}
void dog_torch::math::number::BigInteger::reverse()
{
	for (int i = 0; i < this->num_.size() / 2; i++)
	{
		uint8_t tempB = this->num_.at(i);
		this->num_.at(i) = this->num_.at(this->num_.size() - i - 1);
		this->num_.at(this->num_.size() - i - 1) = tempB;
	}
}
void dog_torch::math::number::BigInteger::set2b(uint64_t n)
{
	if (n == 0)
	{
		this->sign_ = 0;
	}
	else
	{
		this->sign_ = 1;
	}
	this->num_.clear();
	this->reserve(n / 8);
	int m = 0;
	uint8_t B = 0;
	for (uint64_t i = 0; i < n; i++)
	{
		B |= (uint8_t)(1) << m;
		m++;
		if (m == 8) { this->num_.push_back(B); B = 0; m = 0; }
	}
	if (B != 0) { this->num_.push_back(B); }
	this->reverse();
}
void dog_torch::math::number::BigInteger::set0()
{
	this->num_.clear();
	this->num_.push_back(0);
	this->sign_ = 0;
}

std::vector<uint8_t>::iterator dog_torch::math::number::BigInteger::begin()
{
	return this->num_.begin();
}
std::vector<uint8_t>::iterator dog_torch::math::number::BigInteger::end()
{
	return this->num_.end();
}

std::vector<uint8_t>::const_iterator dog_torch::math::number::BigInteger::cbegin() const
{
	return this->num_.cbegin();
}
std::vector<uint8_t>::const_iterator dog_torch::math::number::BigInteger::cend() const
{
	return this->num_.cend();
}

std::reverse_iterator<std::vector<uint8_t>::iterator> dog_torch::math::number::BigInteger::rbegin()
{
	return this->num_.rbegin();
}
std::reverse_iterator<std::vector<uint8_t>::iterator> dog_torch::math::number::BigInteger::rend()
{
	return this->num_.rend();
}

std::reverse_iterator<std::vector<uint8_t>::const_iterator> dog_torch::math::number::BigInteger::crbegin() const
{
	return this->num_.crbegin();
}
std::reverse_iterator<std::vector<uint8_t>::const_iterator> dog_torch::math::number::BigInteger::crend() const
{
	return this->num_.crend();
}

/*
	2025.2.10 23:19 在颓废了两天，看来无数时间的b站消遣之后，
	总是想起来用py检验正确性，发现90*60=36这种低级错误，然后发现是转换这里遇0就不加，气的写了这个东西
*/
dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::toBigInteger(uint8_t n)
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
		res.sign_ = 1;
	}
	return res;
}
dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::toBigInteger(uint16_t n)
{
	BigInteger res;
	if (n == 0)
	{
		return res;
	}
	else
	{
		res.sign_ = 1;
		res.pop_back();
	}
	res.reserve(2);
	bool high_is_not_zero = false;
	if ((uint8_t)(n >> 8) != 0 || high_is_not_zero)
	{
		res.push_back((uint8_t)(n >> 8));
		high_is_not_zero = true;
	}
	if ((uint8_t)(n & 0xFF) || high_is_not_zero)
	{
		res.push_back((uint8_t)(n & 0xFF));
		high_is_not_zero = true;
	}
	return res;
}
dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::toBigInteger(uint32_t n)
{
	BigInteger res;
	if (n == 0)
	{
		return res;
	}
	else
	{
		res.pop_back();
		res.sign_ = 1;
	}
	res.reserve(4);
	bool high_is_not_zero = false;
	if (((uint8_t)(n >> 24)) || high_is_not_zero)
	{
		res.push_back((uint8_t)(n >> 24));
		high_is_not_zero = true;
	}
	if (((uint8_t)(n >> 16)) || high_is_not_zero)
	{
		res.push_back((uint8_t)(n >> 16));
		high_is_not_zero = true;
	}
	if (((uint8_t)(n >> 8)) || high_is_not_zero)
	{
		res.push_back((uint8_t)(n >> 8));
		high_is_not_zero = true;
	}
	if (((uint8_t)(n & 0xFF)) || high_is_not_zero)
	{
		res.push_back((uint8_t)(n & 0xFF));
		high_is_not_zero = true;
	}
	return res;
}
dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::toBigInteger(uint64_t n)
{
	BigInteger res;
	if (n == 0)
	{
		return res;
	}
	else
	{
		res.sign_ = 1;
		res.pop_back();
	}
	res.reserve(8);
	bool high_is_not_zero = false;
	if (((uint8_t)(n >> 56)) || high_is_not_zero)
	{
		res.push_back((uint8_t)(n >> 56));
		high_is_not_zero = true;
	}
	if (((uint8_t)(n >> 48)) || high_is_not_zero)
	{
		res.push_back((uint8_t)(n >> 48));
		high_is_not_zero = true;
	}
	if (((uint8_t)(n >> 40)) || high_is_not_zero)
	{
		res.push_back((uint8_t)(n >> 40));
		high_is_not_zero = true;
	}
	if (((uint8_t)(n >> 32)) || high_is_not_zero)
	{
		res.push_back((uint8_t)(n >> 32));
		high_is_not_zero = true;
	}
	if (((uint8_t)(n >> 24)) || high_is_not_zero)
	{
		res.push_back((uint8_t)(n >> 24));
		high_is_not_zero = true;
	}
	if (((uint8_t)(n >> 16)) || high_is_not_zero)
	{
		res.push_back((uint8_t)(n >> 16));
		high_is_not_zero = true;
	}
	if (((uint8_t)(n >> 8)) || high_is_not_zero)
	{
		res.push_back((uint8_t)(n >> 8));
		high_is_not_zero = true;
	}
	if (((uint8_t)(n & 0xFF)) || high_is_not_zero)
	{
		res.push_back((uint8_t)(n & 0xFF));
		high_is_not_zero = true;
	}
	return res;
}
dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::toBigInteger(int8_t n)
{
	BigInteger res;
	if (n < 0)
	{
		res = toBigInteger((uint8_t)(-n));
		res.sign_ = -1;
	}
	else
	{
		res = toBigInteger((uint8_t)(n));
	}
	return res;
}
dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::toBigInteger(int16_t n)
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
dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::toBigInteger(int32_t n)
{
	BigInteger res;
	if (n < 0)
	{
		res = toBigInteger((uint32_t)(-n));
		res.sign_ = -1;
	}
	else
	{
		res = toBigInteger((uint32_t)(n));
	}
	return res;
}
dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::toBigInteger(int64_t n)
{
	BigInteger res;
	if (n < 0)
	{
		res = toBigInteger((uint64_t)(-n));
		res.sign_ = -1;
	}
	else
	{
		res = toBigInteger((uint64_t)(n));
	}
	return res;
}

dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::operator-()
{
	switch (this->get_sign())
	{
	case -1: this->set_positive(); break;
	case 1: this->set_negative(); break;
	}
	return *this;
}

dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::abs(BigInteger a)
{
	BigInteger res = a;
	res.sign_ = 1;
	return res;
}

int dog_torch::math::number::BigInteger::abs_compare(const BigInteger& a, const BigInteger& b)
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
int dog_torch::math::number::BigInteger::value_compare(const BigInteger& a, const BigInteger& b)
{
	if (a.sign_ > b.sign_)      return 1;
	else if (a.sign_ < b.sign_) return -1;
	else
	{
		int abs_res = abs_compare(a, b);

		if (a.sign_ == 1)
		{
			if (abs_res == 1)       return 1;
			else if (abs_res == -1) return -1;
		}
		else if (a.sign_ == -1)
		{
			if (abs_res == 1)       return -1;
			else if (abs_res == -1) return 1;
		}
	}
	return 0;
}
uint8_t dog_torch::math::number::BigInteger::plenty_compare(const BigInteger& a, const BigInteger& b)
{
	uint8_t res = 0;
	//                              |__------
	if (a.sign_ == 1)       res |= 0b01000000;
	else if (a.sign_ == 0)  res |= 0b00000000;
	else if (a.sign_ == -1) res |= 0b10000000;

	//                              |--__----
	if (b.sign_ == 1)       res |= 0b00010000;
	else if (b.sign_ == 0)  res |= 0b00000000;
	else if (b.sign_ == -1) res |= 0b00100000;

	int abs_res = abs_compare(a, b);
	//                              |----__--
	if (abs_res == 1)       res |= 0b00001000;
	else if (abs_res == 0)  res |= 0b00000000;
	else if (abs_res == -1) res |= 0b00000100;

	//                                  |------__
	if (a.sign_ > b.sign_)      res |= 0b00000010;
	else if (a.sign_ < b.sign_) res |= 0b00000001;
	else
	{
		if (a.sign_ == 1)
		{
	//                                      |------__
			if (abs_res == 1)       res |= 0b00000010;
			else if (abs_res == -1) res |= 0b00000001;
		}
		else if (a.sign_ == -1)
		{
	//                                      |------__
			if (abs_res == 1)       res |= 0b00000001;
			else if (abs_res == -1) res |= 0b00000010;
		}
	}
	return res;
}

bool dog_torch::math::number::operator==(const BigInteger& a, const BigInteger& b)
{
	return BigInteger::value_compare(a, b) == 0;
}
bool dog_torch::math::number::operator!=(const BigInteger& a, const BigInteger& b)
{
	return BigInteger::value_compare(a, b) != 0;
}
bool dog_torch::math::number::operator>(const BigInteger& a, const BigInteger& b)
{
	return BigInteger::value_compare(a, b) == 1;
}
bool dog_torch::math::number::operator>=(const BigInteger& a, const BigInteger& b)
{
	return !(a < b);
}
bool dog_torch::math::number::operator<(const BigInteger& a, const BigInteger& b)
{
	return BigInteger::value_compare(a, b) == -1;
}
bool dog_torch::math::number::operator<=(const BigInteger& a, const BigInteger& b)
{
	return !(a > b);
}

dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::add(BigInteger a, BigInteger b)
{
	if (a == 0) { return b; }
	if (b == 0) { return a; }
	BigInteger res;res.pop_back();
	int is_a_big = BigInteger::abs_compare(a, b);
	BigInteger* max = nullptr, * min = nullptr;
	if (is_a_big == 1) { max = &a; min = &b; }
	else { max = &b; min = &a; }
	if (a.sign_ == b.sign_)
	{
		res.sign_ = a.sign_;
		uint16_t single_addition = 0;
		auto max_it = max->rbegin(), min_it = min->rbegin();
		for (; min_it != min->rend(); max_it++, min_it++)
		{
			single_addition += ((uint16_t)*max_it + (uint16_t)*min_it);
			res.insert(res.begin(), (uint8_t)(single_addition & 0x00ff));
			single_addition >>= 8;
		}
		for (; max_it != max->rend(); max_it++)
		{
			single_addition += (uint16_t)*max_it;
			res.insert(res.begin(), (uint8_t)(single_addition & 0x00ff));
			single_addition >>= 8;
		}
		if (single_addition != 0)
		{
			res.insert(res.begin(), (uint8_t)(single_addition & 0x00ff));
		}
	}
	else
	{
		res.sign_ = max->sign_;
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
			res.insert(res.begin(), (uint8_t)(temp & 0x00ff));
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
			res.insert(res.begin(), (uint8_t)(temp & 0x00ff));
		}
	}
	res.trims();
	return res;
}
dog_torch::math::number::BigInteger dog_torch::math::number::operator+(BigInteger a, BigInteger b)
{
	return dog_torch::math::number::BigInteger::add(a, b);
}
dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::add_other(BigInteger n)
{
	if (n.size() == 1 && n.get_sign() == 0 && n[0] == 0x00)
	{
		return *this;
	}
	if (this->size() == 1 && this->sign_ == 0 && this->num_[0] == 0)
	{
		std::swap(*this, n);
		return *this;
	}
	int sign = BigInteger::abs_compare(*this, n);
	if (sign == 0 && (this->sign_ != n.get_sign()))
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
	if (this->sign_ == n.get_sign())
	{
		uint16_t single_addition = 0;
		auto max_it = max->rbegin(), min_it = min->rbegin(), this_it = this->rbegin();
		for (; min_it != min->rend(); max_it++, min_it++, this_it++)
		{
			single_addition += ((uint16_t)*max_it + (uint16_t)*min_it);
			*this_it = (uint8_t)(single_addition & 0x00ff);
			single_addition >>= 8;
		}
		for (; max_it != max->rend(); max_it++, this_it++)
		{
			single_addition += (uint16_t)*max_it;
			*this_it = (uint8_t)(single_addition & 0x00ff);
			single_addition >>= 8;

		}
		if (single_addition != 0)
		{
			this->insert(this->begin(), (uint8_t)(single_addition & 0x00ff));
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
			*this_it = (uint8_t)(temp & 0x00ff);
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
			*this_it = (uint8_t)(temp & 0x00ff);

		}
	}
	this->sign_ = max->get_sign();
	this->trims();
	return *this;
}
void dog_torch::math::number::operator+=(BigInteger& a, BigInteger b)
{
	a.add_other(b);
}

void dog_torch::math::number::operator+=(BigInteger& a, uint64_t b)
{
	a.add_other(BigInteger::toBigInteger(b));
}

dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::subtract(BigInteger a, BigInteger b)
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
	return dog_torch::math::number::BigInteger::add(a, b);
}
dog_torch::math::number::BigInteger dog_torch::math::number::operator-(BigInteger a, BigInteger b)
{
	return dog_torch::math::number::BigInteger::subtract(a, b);
}
dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::subtract_other(BigInteger n)
{
	n.change_sign();
	return this->add_other(n);
}
void dog_torch::math::number::operator-=(BigInteger& a, BigInteger b)
{
	a.subtract_other(b);
}

dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::multiplysingle(BigInteger a, BigInteger b)
{
	uint16_t res_ = (uint16_t)a[0] * (uint16_t)b[0];
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
dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::multiplyDistribute(BigInteger a, BigInteger b)
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
	uint16_t single_multiplication = 0;
	uint64_t offset = 0;
	for (auto down = min->rbegin(); down != min->rend(); down++)
	{
		for (auto up = max->rbegin(); up != max->rend(); up++)
		{
			single_multiplication += ((uint16_t)*down * (uint16_t)*up);
			middle_addition.insert(middle_addition.begin(), (uint8_t)(single_multiplication & 0x00ff));
			single_multiplication >>= 8;
		}
		if (single_multiplication != 0)
		{
			middle_addition.insert(middle_addition.begin(), (uint8_t)(single_multiplication & 0x00ff));
		}
		for (uint64_t i = 0; i < offset; i++)
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
dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::multiplyDistributeUint64(BigInteger a, uint64_t b)
{
	if (a == 0 || b == 0)
	{
		return 0;
	}
	BigInteger res;res.reserve(a.size());res.sign_ = a.sign_;res.num_.clear();
	uint64_t up_temp = 0;
	for (auto rit = a.rbegin();rit != a.rend();rit++)
	{
		up_temp = *rit * b + up_temp;
		res.push_back((uint8_t)(up_temp & 0xFF));
		up_temp >>= 8;
	}
	while (up_temp > 0)
	{
		res.push_back((uint8_t)(up_temp & 0xFF));
		up_temp >>= 8;
	}
	res.reverse();
	res.trims();
	return res;
}
dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::multiplyKaratsuba0(BigInteger a, BigInteger b)
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
	uint64_t n = a.size() > b.size() ? a.size() : b.size(), pow2 = 1;
	while (pow2 < n) { pow2 <<= 1; } n = pow2;
	while (a.size() < n) { a.insert(a.begin(), 0x00); }
	while (b.size() < n) { b.insert(b.begin(), 0x00); }
	//std::cout << a.getUpHEX() << "*" << b.getUpHEX() << std::endl;
	auto spilt = [](BigInteger& a, uint64_t start, uint64_t end)->dog_torch::math::number::BigInteger
		{
			BigInteger res;
			res.pop_back();
			res.set_positive();
			bool is_zero = true;
			for (uint64_t i = start; i < end; ++i)
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
		for (uint64_t i = 0; i < (n >> 1); i++) { middle.push_back(0x00); }
	}
	if (head.get_sign() != 0)
	{
		for (uint64_t i = 0; i < n; i++) { head.push_back(0x00); }
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
	uint64_t n = a.size() > b.size() ? a.size() : b.size(), pow2 = 1;
	while (pow2 < n) { pow2 <<= 1; } n = pow2;
	while (a.size() < n) { a.insert(a.begin(), 0x00); }
	while (b.size() < n) { b.insert(b.begin(), 0x00); }
	std::cout << space << a.getUpHEX() << "*" << b.getUpHEX() << std::endl;
	auto spilt = [](BigInteger& a, uint64_t start, uint64_t end)->DogNumber::BigInteger
		{
			BigInteger res;
			res.pop_back();
			res.set_positive();
			res.reverse();
			bool is_zero = true;
			for (uint64_t i = start; i < end; ++i)
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
		for (uint64_t i = 0; i < (n >> 1); i++) { middle.push_back(0x00); }
	}
	if (head.get_sign() != 0)
	{
		for (uint64_t i = 0; i < n; i++) { head.push_back(0x00); }
	}
	auto res= head + middle + tail;
	std::cout << space << res.getUpHEX()  << std::endl;
	return head + middle + tail;
}
*/
dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::multiplyKaratsuba1(BigInteger a, BigInteger b)
{
	//throw number_exception("Error:Not implemented\n错误：暂不支持的操作", __FILE__, __FUNCTION__, __LINE__);
	a.trims(); b.trims();
	if (a.get_sign() == 0 || b.get_sign() == 0) { return BigInteger(); }
	if (a.size() == 1 && b.size() == 1) { return BigInteger::multiplysingle(a, b); }
	if (a.size() == 1 || b.size() == 1) { return BigInteger::multiplyDistribute(a, b); }
	uint64_t n = a.size() > b.size() ? a.size() : b.size(), pow2 = 1;
	while (pow2 < n) { pow2 <<= 1; } n = pow2;
	while (a.size() < n) { a.insert(a.begin(), 0x00); }
	while (b.size() < n) { b.insert(b.begin(), 0x00); }
	auto spilt = [](BigInteger& a, uint64_t start, uint64_t end)->dog_torch::math::number::BigInteger
		{
			BigInteger res;
			res.pop_back();
			res.set_positive();
			bool is_zero = true;
			for (uint64_t i = start; i < end; ++i)
			{
				res.push_back(a[i]);
				if (a[i] != 0) { is_zero = false; }
			}
			if (is_zero) { return BigInteger(); }
			return res;
		};
	std::vector<std::pair<BigInteger, BigInteger>> pair_cache;

	/*
	auto space = [](uint64_t n, uint64_t m)->uint64_t
		{
			uint64_t time = 0;
			while (m >>= 1)
			{
				time++;
			}
			uint64_t res = 1;
			//改为快速幂
			for (uint64_t i = 0; i < time; i++)
			{
				res *= n;
			}
			return res;
		};
	uint64_t temp_reserver = space(3, n);
	pair_cache.reserve(temp_reserver); sign_cache.reserve(temp_reserver);
	*/

	pair_cache.emplace_back(a, b);
	uint64_t location = 0;
	while (location < pair_cache.size())
	{
		std::pair<BigInteger, BigInteger>& now_pair = pair_cache[location];

		uint64_t a_len = now_pair.first.size(), b_len = now_pair.second.size();

		if (!(a_len == 1 || b_len == 1))
		{
			uint64_t n = a_len > b_len ? a_len : b_len, pow2 = 1;
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
			uint64_t n = now_pair.first.size();

			BigInteger tail = middle_cache.front();
			middle_cache.pop_front();
			BigInteger middle = middle_cache.front();
			middle_cache.pop_front();
			BigInteger head = middle_cache.front();
			middle_cache.pop_front();

			middle -= head + tail;
			if (middle.get_sign() != 0)
			{
				for (uint64_t i = 0; i < (n >> 1); i++) { middle.push_back(0x00); }
			}
			if (head.get_sign() != 0)
			{
				for (uint64_t i = 0; i < n; i++) { head.push_back(0x00); }
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
dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::multiplyToomCook30(BigInteger a, BigInteger b)
{
	throw NumberException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_NO_SUPPORT));
	if (a.get_sign() == 0 || b.get_sign() == 0) { return BigInteger(); }
	uint64_t a_len = a.size(), b_len = b.size();
	if (a_len == 1 && b_len == 1) { return multiplysingle(a, b); }
	if (a_len <= 3 || b_len <= 3) { return multiplyDistribute(a, b); }
	uint64_t len = a_len > b_len ? a_len : b_len, pow3 = 1;
	while (pow3 < len) { pow3 *= 3; }

	while (a.size() < pow3) { a.insert(a.begin(), 0x00); }
	while (b.size() < pow3) { b.insert(b.begin(), 0x00); }
	auto spilt = [](BigInteger a, uint64_t start, uint64_t end)->BigInteger
		{
			BigInteger res;
			res.pop_back();
			res.set_positive();
			bool is_zero = true;
			for (uint64_t i = start; i < end; ++i)
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
				res |= ((uint64_t)*it << ((8 - n) * 8));
				if (--n == 0) { break; }
			}
			return res;
		};

	BigInteger w0 = a_;
	BigInteger w1 = md(b_, ti(8)) - md(c_, ti(8)) - d_ + e_;
	BigInteger w2 = md(a_, ti(-30)) + md(b_ + c_, ti(16)) - d_ - e_;
	BigInteger w3 = md(c_ - b_, ti(2)) + d_ - e_;
	BigInteger w4 = md(a_, ti(6)) - md(b_ + c_, ti(4)) + d_ + e_;

	uint64_t w0_ = change(w0), w1_ = change(w1) / 12, w2_ = change(w2) / 24, w3_ = change(w3) / 24, w4_ = change(w4) / 24;

	BigInteger res;
	res.pop_back();
	res.push_back((uint8_t)w4_);
	res.push_back((uint8_t)w3_);
	res.push_back((uint8_t)w2_);
	res.push_back((uint8_t)w1_);
	res.push_back((uint8_t)w0_);

	return res;
}
dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::multiplyToomCook31(BigInteger a, BigInteger b)
{
	throw NumberException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_NO_SUPPORT));
	return BigInteger();
}

void dog_torch::math::number::BigInteger::FFT0(std::vector<std::complex<double>>& a, int inverse)
{
	double pi = 3.14159265358979323;
	uint64_t len = a.size(), lenHalf = len >> 1;
	if (len == 1) { return; }
	std::vector<std::complex<double>> a0(lenHalf), a1(lenHalf);
	for (uint64_t i = 0; i < lenHalf; i++) { a0.at(i) = a.at(i * 2); a1.at(i) = a.at(i * 2 + 1); }
	FFT0(a0, inverse); FFT0(a1, inverse);
	std::complex<double> wk(1, 0), w1(cos(2 * pi / len), sin(2 * pi / len) * inverse);
	for (uint64_t i = 0; i < lenHalf; i++, wk *= w1)
	{
		a.at(i) = a0.at(i) + wk * a1.at(i);
		a.at(i + lenHalf) = a0.at(i) - wk * a1.at(i);
	}
}
void dog_torch::math::number::BigInteger::FFT1(std::vector<std::complex<double>>& a, int inverse, std::vector<uint64_t>& rev)
{
	double pi = 3.14159265358979323; uint64_t lim = rev.size();
	for (uint64_t i = 0; i < lim; i++) { if (rev.at(i) > i) { std::swap(a.at(i), a.at(rev.at(i))); } }
	uint64_t num = 1; uint64_t res = 0;
	while (lim > num)
	{
		num <<= 1;
		res++;
	}
	for (uint64_t i = 1; i <= res; i++)
	{
		uint64_t m = (uint64_t)1 << i;
		std::complex<double> wn(cos(2 * pi / m), sin(2 * pi / m) * inverse);
		for (uint64_t k = 0; k < lim; k += m)
		{
			std::complex<double> w(1, 0);
			for (uint64_t j = 0; j < (m / 2); j++)
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
void dog_torch::math::number::BigInteger::FNTT0(std::vector<uint64_t>& a, int inverse)
{
	int g = 3, mod = 998244353, ig = 332748118;
	uint64_t len = a.size(), lenHalf = len >> 1;
	if (len == 1) { return; }
	std::vector<uint64_t> a0(lenHalf), a1(lenHalf);
	for (uint64_t i = 0; i < lenHalf; i++) { a0[i] = a[i * 2]; a1[i] = a[i * 2 + 1]; }
	FNTT0(a0, inverse); FNTT0(a1, inverse);
	auto q_pow = [&mod](uint64_t n, uint64_t x)->uint64_t
		{
			uint64_t res(1);
			while (x)
			{
				if (x & 1)
				{
					res = (uint64_t)1 * res * n % mod;
				}
				n = (uint64_t)1 * n * n % mod;
				x >>= 1;
			}
			return res;
		};
	uint64_t g1 = q_pow(inverse == 1 ? g : ig, (mod - 1) / len), gk = 1;
	for (uint64_t i = 0; i < lenHalf; i++, gk = gk * g1 % mod)
	{
		a[i] = (a0[i] + a1[i] * gk) % mod;
		a[i + lenHalf] = (a0[i] - a1[i] * gk % mod + mod) % mod;
	}
}
void dog_torch::math::number::BigInteger::FNTT1(std::vector<uint64_t>& a, int inverse, std::vector<uint64_t>& rev)
{
	int g = 3, mod = 998244353, ig = 332748118;
	uint64_t lim = rev.size();
	for (uint64_t i = 0; i < lim; i++) { if (rev[i] > i) { std::swap(a[i], a[rev[i]]); } }
	auto q_pow = [&mod](uint64_t n, uint64_t x)->uint64_t
		{
			uint64_t res(1);
			while (x)
			{
				if (x & 1)
				{
					res = (uint64_t)1 * res * n % mod;
				}
				n = (uint64_t)1 * n * n % mod;
				x >>= 1;
			}
			return res;
		};
	for (uint64_t i = 2; i <= lim; i <<= 1)
	{
		uint64_t g1 = q_pow(inverse == 1 ? g : ig, (mod - 1) / i);
		for (uint64_t j = 0; j < lim; j += i)
		{
			uint64_t gk = 1;
			for (uint64_t k = j; k < j + i / 2; ++k)
			{
				uint64_t x = a[k], y = gk * a[k + i / 2] % mod;
				a[k] = (x + y) % mod; a[k + i / 2] = (x - y + mod) % mod;
				gk = gk * g1 % mod;
			}
		}
	}
}

void dog_torch::math::number::BigInteger::FNTTinv(std::vector<uint64_t>& a, std::vector<uint64_t>& rev)
{
	throw NumberException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_NO_SUPPORT));

}


dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::multiplyFFT0(BigInteger a, BigInteger b)
{
	uint64_t n = 1;
	while (n < a.size() + b.size()) { n <<= 1; }
	std::vector<std::complex<double>> a0(n), b0(n);
	uint64_t na = a.size(), nb = b.size();
	for (uint64_t i = 0; i < n - na; i++) { a0.at(i) = std::complex<double>(0, 0); }
	for (uint64_t i = 0; i < n - nb; i++) { b0.at(i) = std::complex<double>(0, 0); }
	for (uint64_t i = n - na; i < n; i++) { a0.at(i) = std::complex<double>(a.at(i - n + na), 0); }
	for (uint64_t i = n - nb; i < n; i++) { b0.at(i) = std::complex<double>(b.at(i - n + nb), 0); }
	FFT0(a0, 1); FFT0(b0, 1);
	for (uint64_t i = 0; i < n; i++) { a0.at(i) *= b0.at(i); }
	FFT0(a0, -1);
	for (std::complex<double>& one : a0) { one.real(one.real() / n + 1e-6); }
	for (auto it = (a0.rbegin() + 1); it != a0.rend(); it++)
	{
		if (it->real() - 256 >= 1e-7)
		{
			if (it != a0.rend() - 1)
			{
				*(it + 1) += it->real() / 256;
				it->real((uint64_t)it->real() % 256);
			}
			else
			{
				uint64_t temp = it->real() / 256;
				it->real((uint64_t)it->real() % 256);
				a0.insert(a0.begin(), std::complex<double>(temp / 1.0, 0.0));
				break;
			}

		}
	}
	uint64_t max_size = a.size() + b.size() + 1, now_location = 0;
	BigInteger res; res.reserve(max_size); res.pop_back();
	for (auto it = (a0.rbegin() + 1); it != a0.rend(); it++)
	{
		res.insert(res.begin(), (uint8_t)(it->real()));
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
dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::multiplyFFT1(BigInteger a, BigInteger b)
{
	uint64_t n = 1;
	while (n < a.size() + b.size()) { n <<= 1; }
	std::vector<std::complex<double>> a0(n), b0(n);
	uint64_t na = a.size(), nb = b.size();
	for (uint64_t i = 0; i < n - na; i++) { a0.at(i) = std::complex<double>(0, 0); }
	for (uint64_t i = 0; i < n - nb; i++) { b0.at(i) = std::complex<double>(0, 0); }
	for (uint64_t i = n - na; i < n; i++) { a0.at(i) = std::complex<double>(a.at(i - n + na), 0); }
	for (uint64_t i = n - nb; i < n; i++) { b0.at(i) = std::complex<double>(b.at(i - n + nb), 0); }
	uint64_t len = 1, lim = 1;
	while (lim < a0.size()) { len++; lim <<= 1; }
	std::vector<uint64_t> rev(lim);
	for (uint64_t i = 0; i < lim; i++) { rev.at(i) = i; }
	for (uint64_t i = 0; i < lim; i++) { rev[i] = (rev.at(i >> 1) >> 1) | ((i & 1) << (len - 2)); }
	FFT1(a0, 1, rev); FFT1(b0, 1, rev);
	for (uint64_t i = 0; i < n; i++) { a0.at(i) *= b0.at(i); }
	FFT1(a0, -1, rev);
	for (std::complex<double>& one : a0) { one.real(one.real() / n + 1e-6); }
	for (auto it = (a0.rbegin() + 1); it != a0.rend(); it++)
	{
		if (it->real() - 256 >= 1e-7)
		{
			if (it != a0.rend() - 1)
			{
				*(it + 1) += it->real() / 256;
				it->real((uint64_t)it->real() % 256);
			}
			else
			{
				uint64_t temp = it->real() / 256;
				it->real((uint64_t)it->real() % 256);
				a0.insert(a0.begin(), std::complex<double>(temp / 1.0, 0.0));
				break;
			}

		}
	}
	uint64_t max_size = a.size() + b.size() + 1, now_location = 0;
	BigInteger res; res.reserve(max_size); res.pop_back();
	for (auto it = (a0.rbegin() + 1); it != a0.rend(); it++)
	{
		res.insert(res.begin(), (uint8_t)(it->real()));
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
dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::multiplyFNTT0(BigInteger a, BigInteger b)
{
	uint64_t n = 1;
	while (n < a.size() + b.size()) { n <<= 1; }
	std::vector<uint64_t> a0(n), b0(n);
	uint64_t na = a.size(), nb = b.size();
	for (uint64_t i = 0; i < n - na; i++) { a0[i] = 0; }
	for (uint64_t i = 0; i < n - nb; i++) { b0[i] = 0; }
	for (uint64_t i = n - na; i < n; i++) { a0[i] = a[i - n + na]; }
	for (uint64_t i = n - nb; i < n; i++) { b0[i] = b[i - n + nb]; }
	FNTT0(a0, 1); FNTT0(b0, 1);
	for (uint64_t i = 0; i < n; i++) { a0[i] = a0[i] * b0[i] % 998244353; }
	FNTT0(a0, -1);
	auto ninv = [](uint64_t a)-> long long
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
	for (uint64_t& one : a0) { one = one * ninv(n) % 998244353; }
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
				uint64_t temp = *it / 256;
				*it %= 256;
				a0.insert(a0.begin(), temp);
				break;
			}

		}
	}
	uint64_t max_size = a.size() + b.size() + 1, now_location = 0;
	BigInteger res; res.reserve(max_size); res.pop_back();
	for (auto it = (a0.rbegin() + 1); it != a0.rend(); it++)
	{
		res.insert(res.begin(), (uint8_t)(*it));
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
dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::multiplyFNTT1(BigInteger a, BigInteger b)
{
	uint64_t n = 1;
	while (n < a.size() + b.size()) { n <<= 1; }
	std::vector<uint64_t> a0(n), b0(n);
	uint64_t na = a.size(), nb = b.size();
	for (uint64_t i = 0; i < n - na; i++) { a0[i] = 0; }
	for (uint64_t i = 0; i < n - nb; i++) { b0[i] = 0; }
	for (uint64_t i = n - na; i < n; i++) { a0[i] = a[i - n + na]; }
	for (uint64_t i = n - nb; i < n; i++) { b0[i] = b[i - n + nb]; }
	uint64_t len = 1, lim = 1;
	while (lim < a0.size()) { len++; lim <<= 1; }
	std::vector<uint64_t> rev(lim);
	for (uint64_t i = 0; i < lim; i++) { rev.at(i) = i; }
	for (uint64_t i = 0; i < lim; i++) { rev[i] = (rev.at(i >> 1) >> 1) | ((i & 1) << (len - 2)); }
	FNTT1(a0, 1, rev); FNTT1(b0, 1, rev);
	for (uint64_t i = 0; i < n; i++) { a0[i] = (a0[i] * b0[i]) % 998244353; }
	FNTT1(a0, -1, rev);
	auto ninv = [](uint64_t a)-> long long
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
	* for (uint64_t& one : a0) { one /= n; }
	* 以前这里是直接除以n，但现在快速数论变换实在模意义下的，不能直接除，需要转成n在模998244353下的逆元
	*/
	for (uint64_t& one : a0) { one = one * ninv(n) % 998244353; }
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
				uint64_t temp = *it / 256;
				*it %= 256;
				a0.insert(a0.begin(), temp);
				break;
			}

		}
	}
	uint64_t max_size = a.size() + b.size() + 1, now_location = 0;
	BigInteger res; res.reserve(max_size); res.pop_back();
	for (auto it = (a0.rbegin() + 1); it != a0.rend(); it++)
	{
		res.insert(res.begin(), (uint8_t)(*it));
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

dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::multiply(BigInteger a, BigInteger b)
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
dog_torch::math::number::BigInteger dog_torch::math::number::operator*(BigInteger a, BigInteger b)
{
	return BigInteger::multiply(a, b);
}
dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::multiply_other(BigInteger n)
{
	*this = std::move(multiply(*this, n));
	return *this;
}
void dog_torch::math::number::operator*=(BigInteger& a, BigInteger b)
{
	a.multiply_other(b);
}

std::pair<dog_torch::math::number::BigInteger, dog_torch::math::number::BigInteger> dog_torch::math::number::BigInteger::divideDistribute(BigInteger a, BigInteger b, bool is_round_zero)
{
	if (b.get_sign() == 0) throw NumberException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_DIVIDE_BY_ZERO));
	if (a.get_sign() == 0) return { 0,0 };
	BigInteger& max = a, min = b;
	uint8_t compare_code = plenty_compare(a, b);
	if ((compare_code & 0x03) == 0) return { 1,0 };
	else if ((compare_code & 0x0C) == 0) return { -1,0 };
	else if ((compare_code & 0x0C) == 0b01)
	{
		max = b;
		min = a;
	}
	auto spilt = [](BigInteger& a, uint64_t start, uint64_t end)->dog_torch::math::number::BigInteger
		{
			BigInteger res;
			res.pop_back();
			res.set_positive();
			bool is_zero = true;
			for (uint64_t i = start; i < end; ++i)
			{
				res.push_back(a[i]);
				if (a[i] != 0) { is_zero = false; }
			}
			if (is_zero) { return BigInteger(); }
			return res;
		};
	BigInteger temp = spilt(max, 0, min.size());
	uint8_t now = 0x00;
	uint64_t index = min.size();
	BigInteger res; res.reserve(max.size() - min.size() + 1);
	int min_sign = min.get_sign();
	min.set_positive();
	bool is_effive = false;
	while (index <= max.size())
	{
		while (temp > min)
		{
			temp = temp - min;
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
		if (index == max.size()) { break; }
		now = 0x00;
		temp.push_back(max.at(index));
		index++;
	}
	if (temp == min)
	{
		res += 1;
		temp = 0;
	}
	if (min_sign == -1) { min.set_negative(); }
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
			temp = min + temp;
		}
		else if (a.get_sign() == -1 && b.get_sign() == 1)
		{
			temp = min - temp;
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
dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::divideFNTT1(BigInteger a, BigInteger b)
{
	if (b.get_sign() == 0)
	{
		throw NumberException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_DIVIDE_BY_ZERO));
	}
	if (a.get_sign() == 0)
	{
		return 0;
	}
	if (a == b)
	{
		return 1;
	}
	throw NumberException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_NO_SUPPORT));


	return BigInteger();
}
dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::divideKnuth(BigInteger a, BigInteger b, bool is_round_zero)
{
	if (b.get_sign() == 0) throw NumberException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_DIVIDE_BY_ZERO));
	if (a.get_sign() == 0) return 0;
	BigInteger& max = a, min = b;
	uint8_t compare_code = plenty_compare(a, b);
	if ((compare_code & 0x03) == 0) return 1;
	else if ((compare_code & 0x0C) == 0) return -1;
	else if ((compare_code & 0x0C) == 0b01)
	{
		max = b;
		min = a;
	}
	if (a.size() < 8)
	{
		auto a_ = a.to_abs_uint64();
		auto b_ = b.to_abs_uint64();
		BigInteger q = a_ / b_;
		if ((a.sign_ == -1 && b.sign_ == -1) || (a.sign_ == 1 && b.sign_ == 1))
		{
			q.set_positive();
		}
		else
		{
			q.set_negative();
		}
		return q;
	}
	auto get_uint32 = [](const BigInteger& n, uint64_t i) -> uint32_t
		{
			if (i == 0)
			{
				uint32_t res = 0;
				switch (n.size() % 4)
				{
				case 0:
				{
					res |= (uint32_t)n[0] << 24;
					res |= (uint32_t)n[1] << 16;
					res |= (uint32_t)n[2] << 8;
					res |= (uint32_t)n[3] << 0;
					return res;
				}
				case 1:
				{
					res |= (uint32_t)n[0] << 0;
					return res;
				}
				case 2:
				{
					res |= (uint32_t)n[0] << 8;
					res |= (uint32_t)n[1] << 0;
					return res;
				}
				case 3:
				{
					res |= (uint32_t)n[0] << 16;
					res |= (uint32_t)n[1] << 8;
					res |= (uint32_t)n[2] << 0;
					return res;
				}
				}
			}
			uint64_t index = n.size() % 4 == 0 ? i * 4 : n.size() % 4 + (i - 1) * 4;
			uint32_t res =
				(uint32_t)n[index]  << 24 |
				(uint32_t)n[index + 1] << 16 |
				(uint32_t)n[index + 2] << 8 |
				(uint32_t)n[index + 3];
			return res;
		};
	auto get_uint32_size = [](const BigInteger& n) -> uint64_t
		{
			return ((n.size() - 1) / 4) + 1;
		};
	char q_sign = -1;
	if ((a.sign_ == -1 && b.sign_ == -1) || (a.sign_ == 1 && b.sign_ == 1))
	{
		q_sign = 1;
	}
	max.set_positive();
	min.set_positive();
	uint64_t v0 = get_uint32(min, 0);
	uint32_t d = 1;
	if (v0 < 0xFFFFFFFF / 2)
	{
		d = 0xFFFFFFFF / (v0 + 1);
		max = multiplyDistributeUint64(max, d);
		min = multiplyDistributeUint64(min, d);
	}
	uint64_t v_32_num = get_uint32_size(min);
	uint64_t u_32_num = get_uint32_size(max);
	uint64_t u_32_index = 0;

	BigInteger max_top;max_top.reserve((v_32_num + 1) * 4);max_top.num_.clear();
	for (;u_32_index < v_32_num;u_32_index++)
	{
		uint32_t temp = get_uint32(max, u_32_index);
		max_top.push_back((uint8_t)(temp >> 24));
		max_top.push_back((uint8_t)(temp >> 16));
		max_top.push_back((uint8_t)(temp >> 8));
		max_top.push_back((uint8_t)(temp >> 0));
	}
	max_top.set_positive();
	max_top.trims();
	
	BigInteger q;q.reserve((v_32_num + 1) * 4);q.num_.clear();
	uint64_t u_head = (uint64_t)(get_uint32(max_top, 0)), v_head = (uint64_t)(get_uint32(min, 0));
	uint32_t q_set = 0, temp = 0;
	if (u_head >= v_head)
	{
		max_top -= min;
		q.push_back(1);
	}
	while (u_32_index <= u_32_num)
	{
		temp = get_uint32(max, u_32_index);
		if (max_top == 0)
		{
			max_top.num_.clear();
			max_top.sign_ = 1;
		}
		max_top.push_back((uint8_t)(temp >> 24));
		max_top.push_back((uint8_t)(temp >> 16));
		max_top.push_back((uint8_t)(temp >> 8));
		max_top.push_back((uint8_t)(temp));
		u_32_index++;
		u_head = (uint64_t)(get_uint32(max_top, 0)) << 32 | (uint64_t)(get_uint32(max_top, 1));
		q_set = u_head / v_head;
		max_top -= multiplyDistributeUint64(min, q_set);
		while (max_top < 0)
		{
			max_top += min;
			q_set--;
		}
		while (max_top >= min)
		{
			max_top -= min;
			q_set++;
		}
		q.push_back((uint8_t)(q_set >> 24));
		q.push_back((uint8_t)(q_set >> 16));
		q.push_back((uint8_t)(q_set >> 8));
		q.push_back((uint8_t)(q_set));
	}
	q.sign_ = q_sign;
	q.trims();
	if (max_top == 0) return q;
	if (!is_round_zero && ((a.sign_ == -1 && b.sign_ == 0) || (a.sign_ == 0 || b.sign_ == -1))) return q - 1;
}
dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::divide(BigInteger a, BigInteger b)
{
	if (b.get_sign() == 0) throw NumberException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_DIVIDE_BY_ZERO));
	if (a.get_sign() == 0) return 0;
	BigInteger& max = a, min = b;
	uint8_t compare_code = plenty_compare(a, b);
	if ((compare_code & 0x03) == 0) return 1;
	else if ((compare_code & 0x0C) == 0) return -1;
	return divideKnuth(a, b, true);
}
dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::remainderKnuth(BigInteger a, BigInteger b)
{
	if (b.get_sign() == 0) throw NumberException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_DIVIDE_BY_ZERO));
	if (a.get_sign() == 0) return b;
	BigInteger& max = a, min = b;
	uint8_t compare_code = plenty_compare(a, b);
	if ((compare_code & 0x03) == 0) return 1;
	else if ((compare_code & 0x0C) == 0) return -1;
	else if ((compare_code & 0x0C) == 0b01)
	{
		max = b;
		min = a;
	}
	if (a.size() < 8)
	{
		auto a_ = a.to_abs_uint64();
		auto b_ = b.to_abs_uint64();
		BigInteger r = a_ % b_;
		if (r.sign_ == 0) return r;
		r.sign_ = a.sign_;
		r.trims();
		return r;
	}
	auto get_uint32 = [](const BigInteger& n, uint64_t i) -> uint32_t
		{
			if (i == 0)
			{
				uint32_t res = 0;
				switch (n.size() % 4)
				{
				case 0:
				{
					res |= (uint32_t)n[0] << 24;
					res |= (uint32_t)n[1] << 16;
					res |= (uint32_t)n[2] << 8;
					res |= (uint32_t)n[3] << 0;
					return res;
				}
				case 1:
				{
					res |= (uint32_t)n[0] << 0;
					return res;
				}
				case 2:
				{
					res |= (uint32_t)n[0] << 8;
					res |= (uint32_t)n[1] << 0;
					return res;
				}
				case 3:
				{
					res |= (uint32_t)n[0] << 16;
					res |= (uint32_t)n[1] << 8;
					res |= (uint32_t)n[2] << 0;
					return res;
				}
				}
			}
			uint64_t index = n.size() % 4 == 0 ? i * 4 : n.size() % 4 + (i - 1) * 4;
			uint32_t res =
				(uint32_t)n[index] << 24 |
				(uint32_t)n[index + 1] << 16 |
				(uint32_t)n[index + 2] << 8 |
				(uint32_t)n[index + 3];
			return res;
		};
	auto get_uint32_size = [](const BigInteger& n) -> uint64_t
		{
			return ((n.size() - 1) / 4) + 1;
		};

	max.set_positive();
	min.set_positive();
	uint64_t v0 = get_uint32(min, 0);
	uint32_t d = 1;
	if (v0 < 0xFFFFFFFF / 2)
	{
		d = 0xFFFFFFFF / (v0 + 1);
		max = multiplyDistributeUint64(max, d);
		min = multiplyDistributeUint64(min, d);
	}
	uint64_t v_32_num = get_uint32_size(min);
	uint64_t u_32_num = get_uint32_size(max);
	uint64_t u_32_index = 0;

	BigInteger max_top;max_top.reserve((v_32_num + 1) * 4);max_top.num_.clear();
	for (;u_32_index < v_32_num;u_32_index++)
	{
		uint32_t temp = get_uint32(max, u_32_index);
		max_top.push_back((uint8_t)(temp >> 24));
		max_top.push_back((uint8_t)(temp >> 16));
		max_top.push_back((uint8_t)(temp >> 8));
		max_top.push_back((uint8_t)(temp >> 0));
	}
	max_top.set_positive();
	max_top.trims();
	uint64_t u_head = (uint64_t)(get_uint32(max_top, 0)), v_head = (uint64_t)(get_uint32(min, 0));
	uint32_t q_set = 0, temp = 0;
	if (u_head >= v_head) max_top -= min;
	while (u_32_index <= u_32_num)
	{
		temp = get_uint32(max, u_32_index);
		if (max_top == 0)
		{
			max_top.num_.clear();
			max_top.sign_ = 1;
		}
		max_top.push_back((uint8_t)(temp >> 24));
		max_top.push_back((uint8_t)(temp >> 16));
		max_top.push_back((uint8_t)(temp >> 8));
		max_top.push_back((uint8_t)(temp));
		u_32_index++;
		u_head = (uint64_t)(get_uint32(max_top, 0)) << 32 | (uint64_t)(get_uint32(max_top, 1));
		q_set = u_head / v_head;
		max_top -= multiplyDistributeUint64(min, q_set);
		while (max_top < 0)
		{
			max_top += min;
			q_set--;
		}
		while (max_top >= min)
		{
			max_top -= min;
			q_set++;
		}
	}
	if (max_top == 0) return 0;
	max_top.sign_ = a.sign_;
	if (d == 1) return max_top;
	else return max_top / d;
}
dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::moduloKnuth(BigInteger a, BigInteger b)
{
	if (b.get_sign() == 0) throw NumberException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_DIVIDE_BY_ZERO));
	if (a.get_sign() == 0) return 0;
	BigInteger& max = a, min = b;
	uint8_t compare_code = plenty_compare(a, b);
	if ((compare_code & 0x03) == 0) return 1;
	else if ((compare_code & 0x0C) == 0) return -1;
	else if ((compare_code & 0x0C) == 0b01)
	{
		max = b;
		min = a;
	}
	if (a.size() < 8)
	{
		auto a_ = a.to_abs_uint64();
		auto b_ = b.to_abs_uint64();
		BigInteger r = a_ % b_;
		if (r == 0) return 0;
		if (a.sign_ == -1 && b.sign_ == 1)       r = b - r;
		else if (a.sign_ == 1 && b.sign_ == -1)  r = -b + r;
		else if (a.sign_ == -1 && b.sign_ == -1) r.sign_ = -1;
		return r;
	}
	auto get_uint32 = [](const BigInteger& n, uint64_t i) -> uint32_t
		{
			if (i == 0)
			{
				uint32_t res = 0;
				switch (n.size() % 4)
				{
				case 0:
				{
					res |= (uint32_t)n[0] << 24;
					res |= (uint32_t)n[1] << 16;
					res |= (uint32_t)n[2] << 8;
					res |= (uint32_t)n[3] << 0;
					return res;
				}
				case 1:
				{
					res |= (uint32_t)n[0] << 0;
					return res;
				}
				case 2:
				{
					res |= (uint32_t)n[0] << 8;
					res |= (uint32_t)n[1] << 0;
					return res;
				}
				case 3:
				{
					res |= (uint32_t)n[0] << 16;
					res |= (uint32_t)n[1] << 8;
					res |= (uint32_t)n[2] << 0;
					return res;
				}
				}
			}
			uint64_t index = n.size() % 4 == 0 ? i * 4 : n.size() % 4 + (i - 1) * 4;
			uint32_t res =
				(uint32_t)n[index] << 24 |
				(uint32_t)n[index + 1] << 16 |
				(uint32_t)n[index + 2] << 8 |
				(uint32_t)n[index + 3];
			return res;
		};
	auto get_uint32_size = [](const BigInteger& n) -> uint64_t
		{
			return ((n.size() - 1) / 4) + 1;
		};

	max.set_positive();
	min.set_positive();
	uint64_t v0 = get_uint32(min, 0);
	uint32_t d = 1;
	if (v0 < 0xFFFFFFFF / 2)
	{
		d = 0xFFFFFFFF / (v0 + 1);
		max = multiplyDistributeUint64(max, d);
		min = multiplyDistributeUint64(min, d);
	}
	uint64_t v_32_num = get_uint32_size(min);
	uint64_t u_32_num = get_uint32_size(max);
	uint64_t u_32_index = 0;

	BigInteger max_top;max_top.reserve((v_32_num + 1) * 4);max_top.num_.clear();
	for (;u_32_index < v_32_num;u_32_index++)
	{
		uint32_t temp = get_uint32(max, u_32_index);
		max_top.push_back((uint8_t)(temp >> 24));
		max_top.push_back((uint8_t)(temp >> 16));
		max_top.push_back((uint8_t)(temp >> 8));
		max_top.push_back((uint8_t)(temp >> 0));
	}
	max_top.set_positive();
	max_top.trims();
	uint64_t u_head = (uint64_t)(get_uint32(max_top, 0)), v_head = (uint64_t)(get_uint32(min, 0));
	uint32_t q_set = 0, temp = 0;
	if (u_head >= v_head) max_top -= min;
	while (u_32_index <= u_32_num)
	{
		temp = get_uint32(max, u_32_index);
		if (max_top == 0)
		{
			max_top.num_.clear();
			max_top.sign_ = 1;
		}
		max_top.push_back((uint8_t)(temp >> 24));
		max_top.push_back((uint8_t)(temp >> 16));
		max_top.push_back((uint8_t)(temp >> 8));
		max_top.push_back((uint8_t)(temp));
		u_32_index++;
		u_head = (uint64_t)(get_uint32(max_top, 0)) << 32 | (uint64_t)(get_uint32(max_top, 1));
		q_set = u_head / v_head;
		max_top -= multiplyDistributeUint64(min, q_set);
		while (max_top < 0)
		{
			max_top += min;
			q_set--;
		}
		while (max_top >= min)
		{
			max_top -= min;
			q_set++;
		}
	}
	if (max_top == 0) return 0;
	if (a.sign_ == -1 && b.sign_ == 1)       max_top = min - max_top;
	else if (a.sign_ == 1 && b.sign_ == -1)  max_top = -(min - max_top);
	else if (a.sign_ == -1 && b.sign_ == -1) max_top.sign_ = -1;
	if (d == 1) return max_top;
	else return max_top / d;
}
dog_torch::math::number::BigInteger dog_torch::math::number::operator/(BigInteger a, BigInteger b)
{
	return BigInteger::divideKnuth(a, b);
}

dog_torch::math::number::BigInteger dog_torch::math::number::BigInteger::gcdSubtract(BigInteger a, BigInteger b)
{
	if (a.sign_ == -1 || b.sign_ == -1) throw NumberException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_NEGATIVE_NUMBER));
	if (a.sign_ == 0 || b.sign_ == 0) throw NumberException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_ZERO));
	if (a.sign_ == 0) return b;
	if (b.sign_ == 0) return a;
	if (*(a.crend() - 1) % 2 == 0 && *(b.crend() - 1) % 2 == 0)
	{
		a = divideKnuth(a, 2);
		b = divideKnuth(b, 2);
	}
	BigInteger& max = a, min = b;
	switch (abs_compare(a, b))
	{
	case -1:
	{
		max = b;
		min = a;
		break;
	}
	case 0:
	{
		return a;
	}
	}
	BigInteger dur;
	while (dur != min)
	{
		dur = max - min;
		max = min;
		min = dur;
	}
	return dur;
}


const dog_torch::math::number::BigInteger dog_torch::math::number::ZERO = "0";
const dog_torch::math::number::BigInteger dog_torch::math::number::BIG_UINT32_MAX = "4294967295";
const dog_torch::math::number::BigInteger dog_torch::math::number::BIG_UINT64_MAX = "18446744073709551615";
const dog_torch::math::number::BigInteger dog_torch::math::number::BIG_UINT128_MAX = "340282366920938463463374607431768211455";

#undef DOG_ERROR_MINUS_SIGN_ERROR
#undef DOG_ERROR_WRONG_CHAR_HEX
#undef DOG_ERROR_WRONG_CHAR_DEC
#undef DOG_ERROR_WRONG_CHAR_OCT
#undef DOG_ERROR_WRONG_CHAR_BIN

#undef DOG_ERROR_WRONG_RADIX

#undef DOG_ERROR_NO_SUPPORT

#undef DOG_ERROR_DIVIDE_BY_ZERO
#undef DOG_ERROR_NEGATIVE_NUMBER
#undef DOG_ERROR_ZERO