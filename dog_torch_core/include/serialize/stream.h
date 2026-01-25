#pragma once
#ifdef SHARED
#include "export.h"
#else
#define DOG_CRYPTION_API
#endif
#include <any>
#include <map>
#include <array>
#include <vector>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <variant>
#include <iostream>
#include <unordered_map>

#include "BinaryData.h"
#include "utils/Exception.h"

namespace dog_torch::serialize::stream
{
	namespace utils
	{
		std::pair<BinaryData, uint64_t> read_bytes(std::istream& input, uint64_t size, uint64_t& total);
		uint64_t read_bytes_size(std::istream& input, BinaryData& buf, uint64_t size, uint64_t& total);

		std::pair<BinaryData, uint64_t> read_bits(std::istream& input, uint64_t size, uint64_t& now, uint64_t& now_bit_pos, uint64_t& max);
		uint64_t read_bits_size(std::istream& input, BinaryData& buf, uint64_t size, uint64_t& now, uint64_t& now_bit_pos, uint64_t& max);
	};


	//未实现
	class DOG_CRYPTION_API BinaryDataStreamBuf : public std::basic_streambuf<uint8_t>
	{
	private:
		BinaryData data_;
		std::ios_base::openmode mode_;
		uint8_t* rbuf_start_ = nullptr;
		uint8_t* rbuf_end_ = nullptr;
		uint8_t* rbuf_pos_ = nullptr;

		uint8_t* wbuf_start_ = nullptr;
		uint8_t* wbuf_end_ = nullptr;
		uint8_t* wbuf_pos_ = nullptr;

	public:
		BinaryDataStreamBuf(const BinaryData& data, std::ios_base::openmode mode);

		pos_type seekoff(off_type off, std::ios_base::seekdir dir,
			std::ios_base::openmode which = std::ios_base::in | std::ios_base::out) override;
		pos_type seekpos(pos_type pos,
			std::ios_base::openmode which = std::ios_base::in | std::ios_base::out) override;
		int sync() override;
		std::streamsize showmanyc() override;
		int_type underflow() override;
		int_type uflow() override;
		std::streamsize xsgetn(char_type* s, std::streamsize count) override;
		std::streamsize xsputn(const char_type* s, std::streamsize count) override;
		int_type overflow(int_type ch) override;
		int_type pbackfail(int_type c) override;

	};
}
/*
#include <streambuf>
#include <vector>
#include <cstdint>
#include <cstring>
#include <algorithm>

class StreamBuf : public std::basic_streambuf<uint8_t>
{
public:
    using char_type = uint8_t;
    using traits_type = std::char_traits<uint8_t>;
    using int_type = typename traits_type::int_type;
    using pos_type = typename traits_type::pos_type;
    using off_type = typename traits_type::off_type;

    // 构造函数
    explicit StreamBuf(std::ios_base::openmode mode = std::ios_base::in | std::ios_base::out)
        : mode_(mode)
    {
        // 如果模式包含写入，初始化输出缓冲区
        if (mode_ & std::ios_base::out) {
            // 初始时没有输出缓冲区，overflow 时会创建
            setp(nullptr, nullptr);
        }

        // 如果模式包含读取，设置读取缓冲区
        if (mode_ & std::ios_base::in && !data_.empty()) {
            setup_read_buffer();
        }
    }

    // 从现有数据构造
    StreamBuf(const std::vector<uint8_t>& data, std::ios_base::openmode mode = std::ios_base::in | std::ios_base::out)
        : data_(data), mode_(mode)
    {
        if (mode_ & std::ios_base::out) {
            setp(nullptr, nullptr);
        }

        if (mode_ & std::ios_base::in && !data_.empty()) {
            setup_read_buffer();
        }
    }

    // 移动构造
    StreamBuf(std::vector<uint8_t>&& data, std::ios_base::openmode mode = std::ios_base::in | std::ios_base::out)
        : data_(std::move(data)), mode_(mode)
    {
        if (mode_ & std::ios_base::out) {
            setp(nullptr, nullptr);
        }

        if (mode_ & std::ios_base::in && !data_.empty()) {
            setup_read_buffer();
        }
    }

    // 获取底层数据
    const std::vector<uint8_t>& data() const { return data_; }
    std::vector<uint8_t>&& take_data() { return std::move(data_); }

    // 设置数据（会重置缓冲区状态）
    void set_data(const std::vector<uint8_t>& new_data) {
        data_ = new_data;
        if (mode_ & std::ios_base::in) {
            setup_read_buffer();
        }
        if (mode_ & std::ios_base::out) {
            setup_write_buffer();
        }
    }

    void set_data(std::vector<uint8_t>&& new_data) {
        data_ = std::move(new_data);
        if (mode_ & std::ios_base::in) {
            setup_read_buffer();
        }
        if (mode_ & std::ios_base::out) {
            setup_write_buffer();
        }
    }

    // 清空数据
    void clear() {
        data_.clear();
        if (mode_ & std::ios_base::in) {
            setup_read_buffer();
        }
        if (mode_ & std::ios_base::out) {
            setup_write_buffer();
        }
    }

protected:
    // 当输出缓冲区满时调用
    int_type overflow(int_type c = traits_type::eof()) override {
        if (!(mode_ & std::ios_base::out)) {
            return traits_type::eof();
        }

        // 如果有字符要写入（不是 EOF）
        if (!traits_type::eq_int_type(c, traits_type::eof())) {
            // 将当前输出缓冲区的内容写入 vector
            if (pptr() > pbase()) {
                auto n = pptr() - pbase();
                data_.insert(data_.end(), pbase(), pptr());
            }

            // 写入当前字符
            data_.push_back(static_cast<uint8_t>(c));

            // 设置新的输出缓冲区
            setup_write_buffer();
        } else {
            // 只是刷新缓冲区
            if (pptr() > pbase()) {
                auto n = pptr() - pbase();
                data_.insert(data_.end(), pbase(), pptr());
                setup_write_buffer();
            }
        }

        return traits_type::not_eof(c);
    }

    // 刷新输出缓冲区
    int sync() override {
        if (!(mode_ & std::ios_base::out)) {
            return -1;
        }

        // 将输出缓冲区的内容写入 vector
        if (pptr() > pbase()) {
            auto n = pptr() - pbase();
            data_.insert(data_.end(), pbase(), pptr());
            setup_write_buffer();
        }

        return 0;
    }

    // 当输入缓冲区为空时调用
    int_type underflow() override {
        if (!(mode_ & std::ios_base::in)) {
            return traits_type::eof();
        }

        // 计算剩余可读取的数据
        size_t remaining = data_.size() - (rbuf_pos_ - rbuf_start_);
        if (remaining == 0) {
            return traits_type::eof();
        }

        // 设置读取缓冲区指向剩余数据
        rbuf_start_ = rbuf_pos_;
        rbuf_end_ = data_.data() + data_.size();
        rbuf_pos_ = rbuf_start_;

        // 设置基类的读取缓冲区指针
        setg(reinterpret_cast<char_type*>(rbuf_start_),
             reinterpret_cast<char_type*>(rbuf_pos_),
             reinterpret_cast<char_type*>(rbuf_end_));

        return traits_type::to_int_type(*rbuf_start_);
    }

    // 获取区域
    std::streamsize showmanyc() override {
        if (!(mode_ & std::ios_base::in)) {
            return -1;
        }

        // 计算剩余可读取的字节数
        size_t remaining = data_.size() - (rbuf_pos_ - rbuf_start_);
        return static_cast<std::streamsize>(remaining);
    }

    // 寻址函数
    pos_type seekoff(off_type off, std::ios_base::seekdir dir,
                     std::ios_base::openmode which = std::ios_base::in | std::ios_base::out) override {
        // 处理读位置
        if (which & std::ios_base::in && (mode_ & std::ios_base::in)) {
            char_type* new_pos = nullptr;

            switch (dir) {
                case std::ios_base::beg:
                    new_pos = reinterpret_cast<char_type*>(data_.data()) + off;
                    break;
                case std::ios_base::cur:
                    new_pos = gptr() + off;
                    break;
                case std::ios_base::end:
                    new_pos = reinterpret_cast<char_type*>(data_.data() + data_.size()) + off;
                    break;
                default:
                    return pos_type(off_type(-1));
            }

            // 检查边界
            if (new_pos < reinterpret_cast<char_type*>(data_.data()) ||
                new_pos > reinterpret_cast<char_type*>(data_.data() + data_.size())) {
                return pos_type(off_type(-1));
            }

            // 更新读取指针
            rbuf_pos_ = reinterpret_cast<uint8_t*>(new_pos);
            setg(reinterpret_cast<char_type*>(rbuf_start_),
                 new_pos,
                 reinterpret_cast<char_type*>(rbuf_end_));
        }

        // 处理写位置
        if (which & std::ios_base::out && (mode_ & std::ios_base::out)) {
            char_type* new_pos = nullptr;

            switch (dir) {
                case std::ios_base::beg:
                    new_pos = reinterpret_cast<char_type*>(data_.data()) + off;
                    break;
                case std::ios_base::cur:
                    new_pos = pptr() + off;
                    break;
                case std::ios_base::end:
                    new_pos = reinterpret_cast<char_type*>(data_.data() + data_.size()) + off;
                    break;
                default:
                    return pos_type(off_type(-1));
            }

            // 检查边界
            if (new_pos < reinterpret_cast<char_type*>(data_.data()) ||
                new_pos > reinterpret_cast<char_type*>(data_.data() + data_.capacity())) {
                return pos_type(off_type(-1));
            }

            // 更新写入指针
            wbuf_pos_ = reinterpret_cast<uint8_t*>(new_pos);
            setp(reinterpret_cast<char_type*>(wbuf_start_),
                 reinterpret_cast<char_type*>(wbuf_end_));
            pbump(static_cast<int>(wbuf_pos_ - wbuf_start_));
        }

        return pos_type(reinterpret_cast<uint8_t*>(gptr()) - data_.data());
    }

    pos_type seekpos(pos_type pos,
                     std::ios_base::openmode which = std::ios_base::in | std::ios_base::out) override {
        return seekoff(off_type(pos), std::ios_base::beg, which);
    }

private:
    // 设置读取缓冲区
    void setup_read_buffer() {
        rbuf_start_ = data_.data();
        rbuf_end_ = data_.data() + data_.size();
        rbuf_pos_ = rbuf_start_;

        setg(reinterpret_cast<char_type*>(rbuf_start_),
             reinterpret_cast<char_type*>(rbuf_pos_),
             reinterpret_cast<char_type*>(rbuf_end_));
    }

    // 设置写入缓冲区
    void setup_write_buffer() {
        // 确保 vector 有足够的容量
        if (data_.capacity() - data_.size() == 0) {
            // 扩容策略：至少增加 256 字节，或者翻倍
            size_t new_capacity = std::max(data_.capacity() * 2, data_.capacity() + 256);
            data_.reserve(new_capacity);
        }

        wbuf_start_ = data_.data() + data_.size();
        wbuf_end_ = data_.data() + data_.capacity();
        wbuf_pos_ = wbuf_start_;

        setp(reinterpret_cast<char_type*>(wbuf_start_),
             reinterpret_cast<char_type*>(wbuf_end_));
    }

    std::vector<uint8_t> data_;
    std::ios_base::openmode mode_;
    uint8_t* rbuf_start_ = nullptr;
    uint8_t* rbuf_end_ = nullptr;
    uint8_t* rbuf_pos_ = nullptr;
    uint8_t* wbuf_start_ = nullptr;
    uint8_t* wbuf_end_ = nullptr;
    uint8_t* wbuf_pos_ = nullptr;
};
*/