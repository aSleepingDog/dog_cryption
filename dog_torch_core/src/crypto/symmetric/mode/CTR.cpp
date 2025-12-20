#include "crypto/symmetric/mode/CTR.h"
#define NSROOT dog_torch::crypto::symmetric //NSROOT = namespace root
#define DOG_DATA dog_torch::serialize::Data

DOG_DATA NSROOT::mode::CTR::encrypt(const Data& plain, const Data& iv, Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
	Data tempBlock0 = iv;
	uint64_t endNum = 0;
	for (uint64_t i0 = 0; i0 < 8; i0++)
	{
		endNum += (uint64_t)tempBlock0[i0 + 8] << (8 * (7 - i0));
	}
	Data tempBlock1;
	Data tempBlock2;
	for (uint64_t i0 = 0; i0 <= plain.size(); i0 += block_size)
	{
		tempBlock2 = tempBlock0;
		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = plain.sub_by_len(i0, block_size);
		if (tempBlock1.size() < block_size && cryptor.get_using_padding()) { cryptor.get_padding()(tempBlock1, block_size); }
		res = res + NSROOT::utils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size());
		tempBlock1.rm_pos();
		endNum++;
		for (int i1 = 0; i1 < 8; i1++)
		{
			tempBlock2[i1 + 8] = (uint8_t)(endNum >> (8 * (7 - i1)));
		}
		tempBlock0 = tempBlock2;
	}
	return res;
}
DOG_DATA NSROOT::mode::CTR::decrypt(const Data& crypt, const Data& iv, Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	Data res; res.reserve(((crypt.size() / block_size) + 1) * block_size);
	Data tempBlock0 = iv;
	uint64_t endNum = 0;
	for (uint64_t i0 = 0; i0 < 8; i0++)
	{
		endNum += (uint64_t)tempBlock0[i0 + 8] << (8 * (7 - i0));
	}
	Data tempBlock1;
	Data tempBlock2;
	for (uint64_t i0 = 0; i0 < crypt.size(); i0 += block_size)
	{
		tempBlock2 = tempBlock0;
		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = crypt.sub_by_pos(i0, i0 + block_size);
		res = res + NSROOT::utils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size());
		endNum++;
		for (int i1 = 0; i1 < 8; i1++)
		{
			tempBlock2[i1 + 8] = (uint8_t)(endNum >> (8 * (7 - i1)));
		}
		tempBlock0 = tempBlock2;
	}
	if (cryptor.get_using_padding()) { cryptor.get_unpadding()(res, block_size); }
	return res;
}
void NSROOT::mode::CTR::encrypt_stream(std::istream& plain, const Data& iv, std::ostream& crypt, Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	Data tempBlock0 = iv;
	uint64_t endNum = 0;
	for (uint64_t i0 = 0; i0 < 8; i0++)
	{
		endNum += (uint64_t)tempBlock0[i0 + 8] << (8 * (7 - i0));
	}
	Data tempBlock1(block_size);
	Data tempBlock2(block_size);
	while (plain.tellg() <= file_size - block_size)
	{
		tempBlock2 = tempBlock0;
		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		plain.read((char*)tempBlock1.data(), block_size);
		crypt.write((char*)NSROOT::utils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
		endNum++;
		for (int i1 = 0; i1 < 8; i1++)
		{
			tempBlock2[i1 + 8] = (uint8_t)(endNum >> (8 * (7 - i1)));
		}
		tempBlock0 = tempBlock2;
	}
	tempBlock2 = tempBlock0;
	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	plain.read((char*)tempBlock1.data(), block_size);
	for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock1.pop_back(); }
	if (cryptor.get_using_padding() && plain.gcount() < block_size)
	{
		cryptor.get_padding()(tempBlock1, block_size);
	}
	crypt.write((char*)NSROOT::utils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size()).data(), tempBlock1.size());
	crypt.flush();
}
void NSROOT::mode::CTR::decrypt_stream(std::istream& crypt, const Data& iv, std::ostream& plain, Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	Data tempBlock0 = iv;
	uint64_t endNum = 0;
	for (uint64_t i0 = 0; i0 < 8; i0++)
	{
		endNum += (uint64_t)tempBlock0[i0 + 8] << (8 * (7 - i0));
	}
	Data tempBlock1(block_size);
	Data tempBlock2(block_size);
	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		tempBlock2 = tempBlock0;
		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.read((char*)tempBlock1.data(), block_size);
		plain.write((char*)NSROOT::utils::squareXOR(tempBlock1, tempBlock0, block_size).data(), block_size);
		endNum++;
		for (int i1 = 0; i1 < 8; i1++)
		{
			tempBlock2[i1 + 8] = (uint8_t)(endNum >> (8 * (7 - i1)));
		}
		tempBlock0 = tempBlock2;
	}
	tempBlock2 = tempBlock0;
	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.read((char*)tempBlock1.data(), block_size);
	for (uint64_t i = 0; i < block_size - crypt.gcount(); ++i) { tempBlock1.pop_back(); }
	NSROOT::utils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
	if (cryptor.get_using_padding())
	{
		cryptor.get_unpadding()(tempBlock1, block_size);
	}
	plain.write((char*)tempBlock1.data(), tempBlock1.size());
	plain.flush();
}
void NSROOT::mode::CTR::encrypt_streamp(std::istream& plain, const Data& iv, std::ostream& crypt, Cryptor& cryptor,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	Data tempBlock0 = iv;
	uint64_t endNum = 0;
	for (uint64_t i0 = 0; i0 < 8; i0++)
	{
		endNum += (uint64_t)tempBlock0[i0 + 8] << (8 * (7 - i0));
	}
	Data tempBlock1(block_size);
	Data tempBlock2(block_size);
	while (plain.tellg() <= file_size - block_size)
	{
		tempBlock2 = tempBlock0;
		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		plain.read((char*)tempBlock1.data(), block_size);
		crypt.write((char*)NSROOT::utils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
		std::unique_lock<std::mutex> lock(*mutex_);
		while (*paused_ && !*stop_) { cond_->wait(lock); }
		if (*stop_) return;
		lock.unlock();
		progress_->store(NSROOT::mode::update_progress(progress_->load(), block_size, file_size));
		endNum++;
		for (int i1 = 0; i1 < 8; i1++)
		{
			tempBlock2[i1 + 8] = (uint8_t)(endNum >> (8 * (7 - i1)));
		}
		tempBlock0 = tempBlock2;
	}
	tempBlock2 = tempBlock0;
	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	plain.read((char*)tempBlock1.data(), block_size);
	for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock1.pop_back(); }
	if (cryptor.get_using_padding() && plain.gcount() < block_size)
	{
		cryptor.get_padding()(tempBlock1, block_size);
	}
	crypt.write((char*)NSROOT::utils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size()).data(), tempBlock1.size());
	crypt.flush();
	progress_->store(1.0);
}
void NSROOT::mode::CTR::decrypt_streamp(std::istream& crypt, const Data& iv, std::ostream& plain, Cryptor& cryptor,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	Data tempBlock0 = iv;
	uint64_t endNum = 0;
	for (uint64_t i0 = 0; i0 < 8; i0++)
	{
		endNum += (uint64_t)tempBlock0[i0 + 8] << (8 * (7 - i0));
	}
	Data tempBlock1(block_size);
	Data tempBlock2(block_size);
	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		tempBlock2 = tempBlock0;
		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.read((char*)tempBlock1.data(), block_size);
		plain.write((char*)NSROOT::utils::squareXOR(tempBlock1, tempBlock0, block_size).data(), block_size);
		std::unique_lock<std::mutex> lock(*mutex_);
		while (*paused_ && !*stop_) { cond_->wait(lock); }
		if (*stop_) return;
		lock.unlock();
		progress_->store(update_progress(progress_->load(), block_size, file_size));
		endNum++;
		for (int i1 = 0; i1 < 8; i1++)
		{
			tempBlock2[i1 + 8] = (uint8_t)(endNum >> (8 * (7 - i1)));
		}
		tempBlock0 = tempBlock2;
	}
	tempBlock2 = tempBlock0;
	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.read((char*)tempBlock1.data(), block_size);
	for (uint64_t i = 0; i < block_size - crypt.gcount(); ++i) { tempBlock1.pop_back(); }
	NSROOT::utils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
	if (cryptor.get_using_padding())
	{
		cryptor.get_unpadding()(tempBlock1, block_size);
	}
	plain.write((char*)tempBlock1.data(), tempBlock1.size());
	progress_->store(update_progress(progress_->load(), block_size, file_size));
	plain.flush();
	progress_->store(1.0);
}

NSROOT::mode::crypt_func NSROOT::mode::CTR::get_mult_encrypt() const
{
	return encrypt;
}
NSROOT::mode::crypt_func NSROOT::mode::CTR::get_mult_decrypt() const
{
	return decrypt;
}
NSROOT::mode::stream_crypt_func NSROOT::mode::CTR::get_stream_encrypt() const
{
	return encrypt_stream;
}
NSROOT::mode::stream_crypt_func NSROOT::mode::CTR::get_stream_decrypt() const
{
	return decrypt_stream;
}
NSROOT::mode::stream_cryptp_func NSROOT::mode::CTR::get_stream_encryptp() const
{
	return encrypt_streamp;
}
NSROOT::mode::stream_cryptp_func NSROOT::mode::CTR::get_stream_decryptp() const
{
	return decrypt_streamp;
}

#undef NSROOT
#undef DOG_DATA