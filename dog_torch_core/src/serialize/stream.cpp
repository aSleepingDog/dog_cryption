#include "serialize/stream.h"

#define NSROOT dog_torch::serialize::stream
#define DOG_DATA dog_torch::serialize::BinaryData

#define DOG_ERROR_INVAILD_MODE "Error:invalid open mode"

std::pair<DOG_DATA, uint64_t> NSROOT::utils::read_bytes(std::istream& input, uint64_t size, uint64_t& total)
{
	BinaryData buf(size);
	input.read((char*)buf.data(), size);
	uint64_t read_byte_size = input.gcount();
	total += read_byte_size;
	for (uint64_t i = read_byte_size; i < size; i++)
	{
		buf.pop_back();
	}
	return { buf, read_byte_size };
}
uint64_t NSROOT::utils::read_bytes_size(std::istream& input, BinaryData& buf, uint64_t size, uint64_t& total)
{
	input.read((char*)buf.data(), size);
	uint64_t read_byte_size = input.gcount();
	total += read_byte_size;
	for (uint64_t i = read_byte_size; i < size; i++)
	{
		buf.pop_back();
	}
	return read_byte_size;
}

std::pair<DOG_DATA, uint64_t> NSROOT::utils::read_bits(std::istream& input, uint64_t size, uint64_t& now, uint64_t& now_bit_pos, uint64_t& max)
{
	BinaryData temp_block1;temp_block1.reserve((size / 8) + 1);
	uint8_t fill_byte = 0, fill_bit_pos = 0;
	uint8_t temp_byte = 0x00;
	uint64_t i = 0;
	for (; i < size; i++)
	{
		temp_byte = input.peek();
		fill_byte |= ((temp_byte >> (7 - now_bit_pos)) & 0x01) << (7 - i % 8);
		now++;
		fill_bit_pos++;
		if (i % 8 == 7)
		{
			temp_block1.push_back(fill_byte);
			fill_byte = 0;
			fill_bit_pos = 0;
		}
		if (now_bit_pos == 8)
		{
			now_bit_pos = 0;
			input.get();
			now++;
		}
		if (now == max)
		{
			break;
		}
	}
	if (fill_bit_pos != 0)
	{
		temp_block1.push_back(fill_byte);
	}
	return { temp_block1,i };
}
uint64_t NSROOT::utils::read_bits_size(std::istream& input, BinaryData& buf, uint64_t size, uint64_t& now, uint64_t& now_bit_pos, uint64_t& max)
{
	uint8_t fill_byte = 0, fill_bit_pos = 0;
	uint8_t temp_byte = 0x00;
	uint64_t i = 0;
	for (; i < size; i++)
	{
		temp_byte = input.peek();
		fill_byte |= ((temp_byte >> (7 - now_bit_pos)) & 0x01) << (7 - i % 8);
		now++;
		fill_bit_pos++;
		if (i % 8 == 7)
		{
			buf.push_back(fill_byte);
			fill_byte = 0;
			fill_bit_pos = 0;
		}
		if (now_bit_pos == 8)
		{
			now_bit_pos = 0;
			input.get();
			now++;
		}
		if (now == max)
		{
			break;
		}
	}
	if (fill_bit_pos != 0)
	{
		buf.push_back(fill_byte);
	}
	return i;
}



NSROOT::BinaryDataStreamBuf::BinaryDataStreamBuf(const BinaryData& data, std::ios_base::openmode mode)
{
	this->data_ = data;
	if (mode & (~(std::ios::in | std::ios::out | std::ios::binary)))
	{
		throw DOG_EXCEPTION(DOG_ERROR_INVAILD_MODE);
	}
	this->mode_ = mode;
	this->rbuf_start_ = this->data_.data();
	this->rbuf_end_ = this->rbuf_start_ + this->data_.size();
	this->rbuf_pos_ = this->rbuf_start_;
	this->wbuf_start_ = this->data_.data();
	this->wbuf_end_ = this->wbuf_start_ + this->data_.size();
	this->wbuf_pos_ = this->wbuf_start_;
}

NSROOT::BinaryDataStreamBuf::pos_type NSROOT::BinaryDataStreamBuf::seekoff(off_type off, std::ios_base::seekdir dir, std::ios_base::openmode which)
{
	if (!(which & mode_))
	{
		return pos_type(off_type(-1));
	}
	if (which & std::ios::in && which & std::ios::out)
	{
		return pos_type(off_type(-1));
	}
	auto move_read = [&]()->NSROOT::BinaryDataStreamBuf::pos_type
		{
			switch (dir)
			{
				case std::ios_base::beg:
				{
					if (this->rbuf_start_ + off > this->rbuf_end_ || off < 0)
					{
						return pos_type(off_type(-1));
					}
					this->rbuf_pos_ = this->rbuf_start_ + off;
					break;
				}
				case std::ios_base::cur:
				{
					if (this->rbuf_pos_ + off > this->rbuf_end_ || this->rbuf_pos_ + off < this->rbuf_start_)
					{
						return pos_type(off_type(-1));
					}
					this->rbuf_pos_ += off;
				}
				case std::ios_base::end:
				{
					if (off > 0 || this->rbuf_end_ + off < this->rbuf_start_)
					{
						return pos_type(off_type(-1));
					}
					this->rbuf_pos_ = this->rbuf_end_ + off;
				}
			}
			return this->rbuf_pos_ - this->rbuf_start_;
		};
	auto move_write = [&]()->NSROOT::BinaryDataStreamBuf::pos_type
		{
			switch (dir)
			{
			case std::ios_base::beg:
			{
				if (this->wbuf_start_ + off > this->wbuf_end_ || off < 0)
				{
					return pos_type(off_type(-1));
				}
				this->wbuf_pos_ = this->wbuf_start_ + off;
				break;
			}
			case std::ios_base::cur:
			{
				if (this->wbuf_pos_ + off > this->wbuf_end_ || this->wbuf_pos_ + off < this->wbuf_start_)
				{
					return pos_type(off_type(-1));
				}
				this->wbuf_pos_ += off;
			}
			case std::ios_base::end:
			{
				if (off > 0 || this->wbuf_end_ + off < this->wbuf_start_)
				{
					return pos_type(off_type(-1));
				}
				this->wbuf_pos_ = this->wbuf_end_ + off;
			}
			}
			return this->wbuf_pos_ - this->wbuf_start_;
		};
	switch (which)
	{
	case std::ios_base::in:
	{
		return move_read();
	}
	case std::ios_base::out:
	{
		return move_write();
	}
	}
}

NSROOT::BinaryDataStreamBuf::pos_type NSROOT::BinaryDataStreamBuf::seekpos(pos_type pos, std::ios_base::openmode which)
{
	if (!(which & mode_))
	{
		return pos_type(off_type(-1));
	}
	if (which & std::ios::in && which & std::ios::out)
	{
		return pos_type(off_type(-1));
	}
	switch (which)
	{
	case std::ios_base::in:
	{
		this->rbuf_pos_ = this->rbuf_start_ + pos;
		return pos;
	}
	case std::ios_base::out:
	{
		this->wbuf_pos_ = this->wbuf_start_ + pos;
		return pos;
	}
	}
}

int NSROOT::BinaryDataStreamBuf::sync()
{
	return 0;
}

std::streamsize NSROOT::BinaryDataStreamBuf::showmanyc()
{
	return this->rbuf_end_ - this->rbuf_pos_;
}

NSROOT::BinaryDataStreamBuf::int_type NSROOT::BinaryDataStreamBuf::underflow()
{
	return traits_type::eof();
}

NSROOT::BinaryDataStreamBuf::int_type NSROOT::BinaryDataStreamBuf::uflow()
{
	return traits_type::eof();
}

std::streamsize NSROOT::BinaryDataStreamBuf::xsgetn(char_type* s, std::streamsize count)
{
	for (uint64_t i = 0;i < count;i++)
	{
		s[i] = this->rbuf_pos_[i];
		this->rbuf_pos_++;
		if (this->rbuf_pos_ == this->rbuf_end_)
		{
			return i + 1;
		}
	}
	return count;
}

std::streamsize NSROOT::BinaryDataStreamBuf::xsputn(const char_type* s, std::streamsize count)
{
	for (uint64_t i = 0;i < count;i++)
	{
		this->wbuf_pos_[i] = s[i];
		this->wbuf_pos_++;
		if (this->wbuf_pos_ == this->wbuf_end_)
		{
			return i + 1;
		}
	}
	return count;
}

NSROOT::BinaryDataStreamBuf::int_type NSROOT::BinaryDataStreamBuf::overflow(int_type ch)
{
	return int_type();
}

NSROOT::BinaryDataStreamBuf::int_type NSROOT::BinaryDataStreamBuf::pbackfail(int_type c)
{
	return int_type();
}

#undef DOG_DATA
#undef NSROOT

#undef DOG_ERROR_INVAILD_MODE