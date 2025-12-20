#include "crypto/symmetric/mode/CFB.h"

#define NSROOT dog_torch::crypto::symmetric //NSROOT = namespace root
#define DOG_DATA dog_torch::serialize::Data

DOG_DATA NSROOT::mode::CFBB::encrypt(const Data& plain, const Data& iv, Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	//反馈字节数
	uint64_t nbyte = typeid(cryptor.get_mode()) == typeid(NSROOT::mode::CFBB) ? ((const CFBB&)cryptor.get_mode()).get_shift() : ((const CFBb&)cryptor.get_mode()).get_shift();

	dog_torch::serialize::Data res; res.reserve(((plain.size() / nbyte) + 1) * nbyte);
	dog_torch::serialize::Data tempBlock0 = iv;
	dog_torch::serialize::Data tempBlock1(nbyte);
	dog_torch::serialize::Data tempBlock2(nbyte);
	uint64_t i = 0;
	for (i = 0; i < plain.size(); i += nbyte)
	{
		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = plain.sub_by_len(i, nbyte);
		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
		NSROOT::utils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
		res += tempBlock1;
		tempBlock0 = tempBlock0.sub_by_len(nbyte, block_size - nbyte) + tempBlock1;
	}
	return res;
}
DOG_DATA NSROOT::mode::CFBB::decrypt(const Data& crypt, const Data& iv, Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t nbyte = typeid(cryptor.get_mode()) == typeid(NSROOT::mode::CFBB) ? ((const CFBB&)cryptor.get_mode()).get_shift() : ((const CFBb&)cryptor.get_mode()).get_shift();


	dog_torch::serialize::Data res; res.reserve(((crypt.size() / nbyte) + 1) * nbyte);
	dog_torch::serialize::Data tempBlock0 = iv;
	dog_torch::serialize::Data tempBlock1(nbyte);
	dog_torch::serialize::Data tempBlock2(nbyte);
	uint64_t i = 0;
	for (i = 0; i < crypt.size(); i += nbyte)
	{
		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = crypt.sub_by_len(i, nbyte);
		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
		res += NSROOT::utils::squareXOR(tempBlock1, tempBlock2, tempBlock1.size());
		tempBlock0 = tempBlock0.sub_by_len(nbyte, block_size - nbyte) + tempBlock1;
	}
	return res;
}
void NSROOT::mode::CFBB::encrypt_stream(std::istream& plain, const Data& iv, std::ostream& crypt, Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);
	//反馈字节数
	uint64_t nbyte = typeid(cryptor.get_mode()) == typeid(NSROOT::mode::CFBB) ? ((const CFBB&)cryptor.get_mode()).get_shift() : ((const CFBb&)cryptor.get_mode()).get_shift();

	dog_torch::serialize::Data tempBlock0 = iv;
	dog_torch::serialize::Data tempBlock1(nbyte);
	dog_torch::serialize::Data tempBlock2(nbyte);
	while (plain.tellg() <= file_size - nbyte)
	{
		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		plain.read((char*)tempBlock1.data(), nbyte);
		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
		NSROOT::utils::squareXOR_self(tempBlock1, tempBlock2, nbyte);
		crypt.write((char*)tempBlock1.data(), nbyte);
		tempBlock0 = tempBlock0.sub_by_len(nbyte, block_size - nbyte) + tempBlock1;
	}
	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	plain.read((char*)tempBlock1.data(), nbyte);
	tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
	for (int i = 0; i < nbyte - plain.gcount(); ++i) { tempBlock1.pop_back(); }
	if (cryptor.get_using_padding() && plain.gcount() < nbyte) { cryptor.get_padding()(tempBlock1, nbyte); }
	NSROOT::utils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
	crypt.write((char*)tempBlock1.data(), nbyte);
	crypt.flush();
}
void NSROOT::mode::CFBB::decrypt_stream(std::istream& crypt, const Data& iv, std::ostream& plain, NSROOT::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	//反馈字节数
	uint64_t nbyte = typeid(cryptor.get_mode()) == typeid(NSROOT::mode::CFBB) ? ((const CFBB&)cryptor.get_mode()).get_shift() : ((const CFBb&)cryptor.get_mode()).get_shift();


	dog_torch::serialize::Data tempBlock0 = iv;
	dog_torch::serialize::Data tempBlock1(nbyte);
	dog_torch::serialize::Data tempBlock2(nbyte);
	while (crypt.tellg() < file_size - nbyte)
	{
		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.read((char*)tempBlock1.data(), nbyte);
		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
		NSROOT::utils::squareXOR_self(tempBlock2, tempBlock1, nbyte);
		plain.write((char*)tempBlock2.data(), nbyte);
		tempBlock0 = tempBlock0.sub_by_len(nbyte, block_size - nbyte) + tempBlock1;
	}
	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.read((char*)tempBlock1.data(), nbyte);
	tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
	NSROOT::utils::squareXOR_self(tempBlock2, tempBlock1, nbyte);
	plain.write((char*)tempBlock2.data(), nbyte);
	plain.flush();
}
void NSROOT::mode::CFBB::encrypt_streamp(std::istream& plain, const Data& iv, std::ostream& crypt, NSROOT::Cryptor& cryptor,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);
	//反馈字节数
	uint64_t nbyte = typeid(cryptor.get_mode()) == typeid(NSROOT::mode::CFBB) ? ((const CFBB&)cryptor.get_mode()).get_shift() : ((const CFBb&)cryptor.get_mode()).get_shift();

	dog_torch::serialize::Data tempBlock0 = iv;
	dog_torch::serialize::Data tempBlock1(nbyte);
	dog_torch::serialize::Data tempBlock2(nbyte);
	while (plain.tellg() <= file_size - nbyte)
	{
		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		plain.read((char*)tempBlock1.data(), nbyte);
		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
		NSROOT::utils::squareXOR_self(tempBlock1, tempBlock2, nbyte);
		crypt.write((char*)tempBlock1.data(), nbyte);
		std::unique_lock<std::mutex> lock(*mutex_);
		while (*paused_ && !*stop_) { cond_->wait(lock); }
		if (*stop_) return;
		lock.unlock();
		progress_->store(NSROOT::mode::update_progress(progress_->load(), nbyte, file_size));
		tempBlock0 = tempBlock0.sub_by_len(nbyte, block_size - nbyte) + tempBlock1;
	}
	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	plain.read((char*)tempBlock1.data(), nbyte);
	tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
	for (int i = 0; i < nbyte - plain.gcount(); ++i) { tempBlock1.pop_back(); }
	if (cryptor.get_using_padding() && plain.gcount() < nbyte) { cryptor.get_padding()(tempBlock1, nbyte); }
	NSROOT::utils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
	crypt.write((char*)tempBlock1.data(), nbyte);
	progress_->store(update_progress(progress_->load(), nbyte, file_size));
	crypt.flush();
	progress_->store(1.0);
}
void NSROOT::mode::CFBB::decrypt_streamp(std::istream& crypt, const Data& iv, std::ostream& plain, NSROOT::Cryptor& cryptor,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	//反馈字节数
	uint64_t nbyte = typeid(cryptor.get_mode()) == typeid(NSROOT::mode::CFBB) ? ((const CFBB&)cryptor.get_mode()).get_shift() : ((const CFBb&)cryptor.get_mode()).get_shift();

	dog_torch::serialize::Data tempBlock0 = iv;
	dog_torch::serialize::Data tempBlock1(nbyte);
	dog_torch::serialize::Data tempBlock2(nbyte);
	while (crypt.tellg() < file_size - nbyte)
	{
		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.read((char*)tempBlock1.data(), nbyte);
		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
		NSROOT::utils::squareXOR_self(tempBlock1, tempBlock2, nbyte);
		plain.write((char*)tempBlock1.data(), nbyte);
		std::unique_lock<std::mutex> lock(*mutex_);
		while (*paused_ && !*stop_) { cond_->wait(lock); }
		if (*stop_) return;
		lock.unlock();
		progress_->store(update_progress(progress_->load(), nbyte, file_size));
		tempBlock0 = tempBlock0.sub_by_len(nbyte, block_size - nbyte) + tempBlock1;
	}
	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.read((char*)tempBlock1.data(), nbyte);
	tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
	NSROOT::utils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
	if (cryptor.get_using_padding()) { cryptor.get_unpadding()(tempBlock1, nbyte); }
	plain.write((char*)tempBlock1.data(), nbyte);
	progress_->store(update_progress(progress_->load(), nbyte, file_size));
	plain.flush();
	progress_->store(1.0);
}

DOG_DATA NSROOT::mode::CFBB::encrypt_CFB8(const Data& plain, const Data& iv, Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	dog_torch::serialize::Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
	dog_torch::serialize::Data tempBlock0 = iv;
	dog_torch::serialize::Data tempBlock1; tempBlock1.reserve(block_size);
	for (uint64_t i0 = 0; i0 < plain.size(); i0++)
	{
		tempBlock1 = tempBlock0;
		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		uint8_t b = plain[i0] ^ tempBlock0[0];
		res.push_back(b);
		tempBlock1.push_back(b);
	}
	return res;
}
DOG_DATA NSROOT::mode::CFBB::decrypt_CFB8(const Data& crypt, const Data& iv, Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	dog_torch::serialize::Data res; res.reserve(((crypt.size() / block_size) + 1) * block_size);
	dog_torch::serialize::Data tempBlock0 = iv;
	dog_torch::serialize::Data tempBlock1; tempBlock1.reserve(block_size);
	for (uint64_t i0 = 0; i0 < crypt.size(); i0++)
	{
		tempBlock1 = tempBlock0;
		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		uint8_t b = crypt[i0] ^ tempBlock0[0];
		res.push_back(b);
		tempBlock0.push_back(crypt[i0]);
	}
	return res;
}
void NSROOT::mode::CFBB::encrypt_CFB8_stream(std::istream& plain, const Data& iv, std::ostream& crypt, Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	dog_torch::serialize::Data tempBlock0 = iv;
	dog_torch::serialize::Data tempBlock1(block_size);
	dog_torch::serialize::Data middleResult; middleResult.reserve(block_size);
	while (plain.tellg() < file_size)
	{
		tempBlock1 = tempBlock0;
		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		uint8_t b = plain.get() ^ tempBlock0[0];
		middleResult.push_back(b);
		if (middleResult.size() == block_size)
		{
			crypt.write((char*)middleResult.data(), block_size);
			middleResult.rm_pos();
		}
		tempBlock1.push_back(b);
	}
	crypt.write((char*)middleResult.data(), middleResult.size());
	crypt.flush();
}
void NSROOT::mode::CFBB::decrypt_CFB8_stream(std::istream& crypt, const Data& iv, std::ostream& plain, NSROOT::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	dog_torch::serialize::Data tempBlock0 = iv;
	dog_torch::serialize::Data tempBlock1; tempBlock1.reserve(block_size);
	dog_torch::serialize::Data middleResult; middleResult.reserve(block_size);
	while (crypt.tellg() < file_size)
	{
		tempBlock1 = tempBlock0;
		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		uint8_t b = crypt.peek() ^ tempBlock0[0];
		middleResult.push_back(b);
		if (middleResult.size() == block_size)
		{
			plain.write((char*)middleResult.data(), block_size);
			//DogData::print::block(middleResult);
			middleResult.rm_pos();
		}
		tempBlock0.push_back(crypt.get());
	}
	plain.write((char*)middleResult.data(), middleResult.size());
	//DogData::print::block(middleResult);
	plain.flush();
}
void NSROOT::mode::CFBB::encrypt_CFB8_streamp(std::istream& plain, const Data& iv, std::ostream& crypt, NSROOT::Cryptor& cryptor,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	dog_torch::serialize::Data tempBlock0 = iv;
	dog_torch::serialize::Data tempBlock1(block_size);
	dog_torch::serialize::Data middleResult; middleResult.reserve(block_size);
	while (plain.tellg() < file_size)
	{
		tempBlock1 = tempBlock0;
		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		uint8_t b = plain.get() ^ tempBlock0[0];
		middleResult.push_back(b);
		if (middleResult.size() == block_size)
		{
			crypt.write((char*)middleResult.data(), block_size);
			std::unique_lock<std::mutex> lock(*mutex_);
			while (*paused_ && !*stop_) { cond_->wait(lock); }
			if (*stop_) return;
			lock.unlock();
			middleResult.rm_pos();
		}
		tempBlock1.push_back(b);
		progress_->store(NSROOT::mode::update_progress(progress_->load(), 1, file_size));
	}
	crypt.write((char*)middleResult.data(), middleResult.size());
	progress_->store(update_progress(progress_->load(), middleResult.size(), file_size));
	crypt.flush();
	progress_->store(1.0);
}
void NSROOT::mode::CFBB::decrypt_CFB8_streamp(std::istream& crypt, const Data& iv, std::ostream& plain, NSROOT::Cryptor& cryptor,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	dog_torch::serialize::Data tempBlock0 = iv;
	dog_torch::serialize::Data tempBlock1; tempBlock1.reserve(block_size);
	dog_torch::serialize::Data middleResult; middleResult.reserve(block_size);
	while (crypt.tellg() < file_size)
	{
		tempBlock1 = tempBlock0;
		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		uint8_t b = crypt.peek() ^ tempBlock0[0];
		middleResult.push_back(b);
		if (middleResult.size() == block_size)
		{
			plain.write((char*)middleResult.data(), block_size);
			std::unique_lock<std::mutex> lock(*mutex_);
			while (*paused_ && !*stop_) { cond_->wait(lock); }
			if (*stop_) return;
			lock.unlock();
			progress_->store(update_progress(progress_->load(), block_size, file_size));
			middleResult.rm_pos();
		}
		tempBlock0.push_back(crypt.get());
	}
	plain.write((char*)middleResult.data(), middleResult.size());
	progress_->store(update_progress(progress_->load(), middleResult.size(), file_size));
	plain.flush();
	progress_->store(1.0);
}

DOG_DATA NSROOT::mode::CFBB::encrypt_CFB128(const Data& plain, const Data& iv, Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	dog_torch::serialize::Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
	dog_torch::serialize::Data tempBlock0 = iv;
	dog_torch::serialize::Data tempBlock1(block_size);
	uint64_t i0 = 0;
	for (i0 = 0; i0 <= plain.size() - 16 && plain.size() >= 16; i0 += 16)
	{
		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = plain.sub_by_len(i0, block_size);
		NSROOT::utils::squareXOR_self(tempBlock1, tempBlock0, 16);
		res = res + tempBlock1;
		tempBlock0 = tempBlock1;
	}
	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	tempBlock1 = plain.sub_by_len(i0, block_size);
	if (tempBlock1.size() < 16 && cryptor.get_using_padding()) { cryptor.get_padding()(tempBlock1, 16); }
	NSROOT::utils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
	res += tempBlock1;
	return res;
}
DOG_DATA NSROOT::mode::CFBB::decrypt_CFB128(const Data& crypt, const Data& iv, Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	dog_torch::serialize::Data res; res.reserve(((crypt.size() / block_size) + 1) * block_size);
	dog_torch::serialize::Data tempBlock0 = iv;
	dog_torch::serialize::Data tempBlock1(block_size);
	uint64_t i0 = 0;
	for (i0 = 0; i0 < crypt.size() - 16 && crypt.size() > 16; i0 += 16)
	{
		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = crypt.sub_by_pos(i0, i0 + 16);
		res = res + NSROOT::utils::squareXOR(tempBlock0, tempBlock1, block_size);
		tempBlock0 = tempBlock1;
	}
	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	tempBlock1 = crypt.sub_by_pos(i0, i0 + 16);
	NSROOT::utils::squareXOR_self(tempBlock1, tempBlock0, tempBlock0.size());
	if (cryptor.get_using_padding())
	{
		cryptor.get_unpadding()(tempBlock1, 16);
	}
	res += tempBlock1;
	return res;
}
void NSROOT::mode::CFBB::encrypt_CFB128_stream(std::istream& plain, const Data& iv, std::ostream& crypt, Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	dog_torch::serialize::Data tempBlock0 = iv;
	dog_torch::serialize::Data tempBlock1(block_size);
	while (plain.tellg() <= file_size - block_size)
	{
		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		plain.read((char*)tempBlock1.data(), 16);
		NSROOT::utils::squareXOR_self(tempBlock0, tempBlock1, block_size);
		crypt.write((char*)tempBlock0.data(), 16);
	}
	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	plain.read((char*)tempBlock1.data(), 16);
	for (int i = 0; i < 16 - plain.gcount(); i++) { tempBlock1.pop_back(); }
	if (cryptor.get_using_padding() && plain.gcount() < 16) { cryptor.get_padding()(tempBlock1, 16); }
	NSROOT::utils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
	crypt.write((char*)tempBlock1.data(), tempBlock1.size());
	crypt.flush();
}
void NSROOT::mode::CFBB::decrypt_CFB128_stream(std::istream& crypt, const Data& iv, std::ostream& plain, NSROOT::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	dog_torch::serialize::Data tempBlock0 = iv;
	dog_torch::serialize::Data tempBlock1(block_size);
	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.read((char*)tempBlock1.data(), block_size);
		plain.write((char*)NSROOT::utils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
		tempBlock0 = tempBlock1;
	}
	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.read((char*)tempBlock1.data(), block_size);
	for (int i = 0; i < 16 - crypt.gcount(); i++) { tempBlock1.pop_back(); }
	NSROOT::utils::squareXOR_self(tempBlock1, tempBlock0, block_size);
	cryptor.get_unpadding()(tempBlock1, block_size);
	plain.write((char*)tempBlock1.data(), tempBlock1.size());
	plain.flush();
}
void NSROOT::mode::CFBB::encrypt_CFB128_streamp(std::istream& plain, const Data& iv, std::ostream& crypt, NSROOT::Cryptor& cryptor,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	dog_torch::serialize::Data tempBlock0 = iv;
	dog_torch::serialize::Data tempBlock1(block_size);
	while (plain.tellg() <= file_size - block_size)
	{
		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		plain.read((char*)tempBlock1.data(), 16);
		NSROOT::utils::squareXOR_self(tempBlock0, tempBlock1, block_size);
		crypt.write((char*)tempBlock0.data(), 16);
		std::unique_lock<std::mutex> lock(*mutex_);
		while (*paused_ && !*stop_)
		{
			cond_->wait(lock);
		}
		if (*stop_) return;
		lock.unlock();
		progress_->store(NSROOT::mode::update_progress(progress_->load(), 16, file_size));
	}
	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	plain.read((char*)tempBlock1.data(), 16);
	for (int i = 0; i < 16 - plain.gcount(); i++) { tempBlock1.pop_back(); }
	if (cryptor.get_using_padding() && plain.gcount() < 16) { cryptor.get_padding()(tempBlock1, 16); }
	NSROOT::utils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
	crypt.write((char*)tempBlock1.data(), tempBlock1.size());
	progress_->store(update_progress(progress_->load(), 16, file_size));
	crypt.flush();
	progress_->store(1.0);

}
void NSROOT::mode::CFBB::decrypt_CFB128_streamp(std::istream& crypt, const Data& iv, std::ostream& plain, NSROOT::Cryptor& cryptor,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	dog_torch::serialize::Data tempBlock0 = iv;
	dog_torch::serialize::Data tempBlock1(block_size);
	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.read((char*)tempBlock1.data(), block_size);
		plain.write((char*)NSROOT::utils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
		std::unique_lock<std::mutex> lock(*mutex_);
		while (*paused_ && !*stop_) { cond_->wait(lock); }
		if (*stop_) return;
		lock.unlock();
		progress_->store(update_progress(progress_->load(), 16, file_size));
		tempBlock0 = tempBlock1;
	}
	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.read((char*)tempBlock1.data(), block_size);
	for (int i = 0; i < 16 - crypt.gcount(); i++) { tempBlock1.pop_back(); }
	NSROOT::utils::squareXOR_self(tempBlock1, tempBlock0, block_size);
	cryptor.get_unpadding()(tempBlock1, block_size);
	plain.write((char*)tempBlock1.data(), tempBlock1.size());
	progress_->store(update_progress(progress_->load(), 16, file_size));
	plain.flush();
	progress_->store(1.0);
}

dog_torch::crypto::symmetric::mode::CFBB::CFBB(uint64_t shitf, bool using_padding) : Mode("CFBB", true, using_padding)
{
	if (shift == 0)
	{
		throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error: shift is 0\n错误：位移为0"));
	}
	this->shift = shitf;
}

uint64_t NSROOT::mode::CFBB::get_shift() const
{
	return this->shift;
}

NSROOT::mode::crypt_func NSROOT::mode::CFBB::get_mult_encrypt() const
{
	if (this->shift == 1)
	{
		return encrypt_CFB8;
	}
	else if (this->shift == 16)
	{
		return encrypt_CFB128;
	}
	else
	{
		return encrypt;
	}
}
NSROOT::mode::crypt_func NSROOT::mode::CFBB::get_mult_decrypt() const
{
	if (this->shift == 1)
	{
		return decrypt_CFB8;
	}
	else if (this->shift == 16)
	{
		return decrypt_CFB128;
	}
	else
	{
		return decrypt;
	}
}
NSROOT::mode::stream_crypt_func NSROOT::mode::CFBB::get_stream_encrypt() const
{
	if (this->shift == 1)
	{
		return encrypt_CFB8_stream;
	}
	else if (this->shift == 16)
	{
		return encrypt_CFB128_stream;
	}
	else
	{
		return encrypt_stream;
	}
}
NSROOT::mode::stream_crypt_func NSROOT::mode::CFBB::get_stream_decrypt() const
{
	if (this->shift == 1)
	{
		return decrypt_CFB8_stream;
	}
	else if (this->shift == 16)
	{
		return decrypt_CFB128_stream;
	}
	else
	{
		return decrypt_stream;
	}
}
NSROOT::mode::stream_cryptp_func NSROOT::mode::CFBB::get_stream_encryptp() const
{
	if (this->shift == 1)
	{
		return encrypt_CFB8_streamp;
	}
	else if (this->shift == 16)
	{
		return encrypt_CFB128_streamp;
	}
	else
	{
		return encrypt_streamp;
	}
}
NSROOT::mode::stream_cryptp_func NSROOT::mode::CFBB::get_stream_decryptp() const
{
	if (this->shift == 1)
	{
		return decrypt_CFB8_streamp;
	}
	else if (this->shift == 16)
	{
		return decrypt_CFB128_streamp;
	}
	else
	{
		return decrypt_streamp;
	}
}

DOG_DATA NSROOT::mode::CFBb::encrypt(const Data& plain, const Data& iv, Cryptor& cryptor)
{
	dog_torch::serialize::Data crypt; crypt.reserve(plain.size());
	uint64_t shift = typeid(cryptor.get_mode()) == typeid(NSROOT::mode::CFBB) ? ((const CFBB&)cryptor.get_mode()).get_shift() : ((const CFBb&)cryptor.get_mode()).get_shift() , read_byte_pos = 0;
	int8_t read_bit_pos = 0;
	dog_torch::serialize::Data tempBlock0 = iv, tempBlock1;
	auto pick_shift = [&plain, &shift, &read_byte_pos, &read_bit_pos]()->dog_torch::serialize::Data
		{
			dog_torch::serialize::Data res; res.reserve((shift / 8) + 1);
			uint8_t fill_byte = 0x00;
			uint8_t temp_byte = 0x00;
			for (uint64_t i = 0; i < shift; i++)
			{
				temp_byte = plain[read_byte_pos];
				fill_byte |= ((temp_byte >> (7 - read_bit_pos)) & 0x01) << (7 - (i % 8));
				read_bit_pos++;
				if (i % 8 == 7)
				{
					res.push_back(fill_byte);
					fill_byte = 0x00;
				}
				if (read_bit_pos == 8)
				{
					read_bit_pos = 0;
					read_byte_pos++;
				}
				if (read_byte_pos == plain.size())
				{
					break;
				}
			}
			if (shift % 8 != 0)
			{
				res.push_back(fill_byte);
			}
			return res;
		};
	int8_t waiting_byte = 0x00; int8_t write_bit_pos = 0;
	auto add_block = [&plain, &crypt, &shift, &waiting_byte, &write_bit_pos](dog_torch::serialize::Data& tempBlock)->void
		{
			uint8_t temp_byte = 0x00;
			for (uint64_t i = 0; i < shift; i++)
			{
				if (i / 8 == tempBlock.size()) { break; }
				temp_byte = tempBlock[i / 8];
				waiting_byte |= ((temp_byte >> (7 - i % 8)) & 0x01) << (7 - (write_bit_pos % 8));
				write_bit_pos++;
				if (write_bit_pos == 8)
				{
					crypt.push_back(waiting_byte);
					if (crypt.size() == plain.size()) { break; }
					waiting_byte = 0x00;
					write_bit_pos = 0;
				}
			}
		};
	for (; read_byte_pos < plain.size();)
	{
		cryptor.get_block_self_encryption()(tempBlock0, cryptor.get_block_size(), cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = pick_shift();
		while (tempBlock1.size() < cryptor.get_block_size()) { tempBlock1.push_back(0x00); }
		NSROOT::utils::squareXOR_self(tempBlock1, tempBlock0, cryptor.get_block_size());
		add_block(tempBlock1);
		tempBlock0 = tempBlock0.bit_left_move_norise(shift) | tempBlock1.bit_right_move_norise(cryptor.get_block_size() * 8 - shift);
	}
	return crypt;
}
DOG_DATA NSROOT::mode::CFBb::decrypt(const Data& crypt, const Data& iv, Cryptor& cryptor)
{
	dog_torch::serialize::Data plain; plain.reserve(crypt.size());
	uint64_t shift = typeid(cryptor.get_mode()) == typeid(NSROOT::mode::CFBB) ? ((const CFBB&)cryptor.get_mode()).get_shift() : ((const CFBb&)cryptor.get_mode()).get_shift();
	uint64_t read_byte_pos = 0;
	int8_t read_bit_pos = 0;
	dog_torch::serialize::Data tempBlock0 = iv, tempBlock1, tempBlock2;
	auto pick_shift = [&crypt, &shift, &read_byte_pos, &read_bit_pos]()->dog_torch::serialize::Data
		{
			dog_torch::serialize::Data res; res.reserve((shift / 8) + 1);
			uint8_t fill_byte = 0x00;
			uint8_t temp_byte = 0x00;
			for (uint64_t i = 0; i < shift; i++)
			{
				temp_byte = crypt[read_byte_pos];
				fill_byte |= ((temp_byte >> (7 - read_bit_pos)) & 0x01) << (7 - (i % 8));
				read_bit_pos++;
				if (i % 8 == 7)
				{
					res.push_back(fill_byte);
					fill_byte = 0x00;
				}
				if (read_bit_pos == 8)
				{
					read_bit_pos = 0;
					read_byte_pos++;
				}
				if (read_byte_pos == crypt.size())
				{
					break;
				}
			}
			if (shift % 8 != 0)
			{
				res.push_back(fill_byte);
			}
			return res;
		};
	int8_t waiting_byte = 0x00; int8_t write_bit_pos = 0;
	auto add_block = [&crypt, &plain, &shift, &waiting_byte, &write_bit_pos](dog_torch::serialize::Data& tempBlock)->void
		{
			uint8_t temp_byte = 0x00;
			for (uint64_t i = 0; i < shift; i++)
			{
				if (i / 8 == tempBlock.size()) { break; }
				temp_byte = tempBlock[i / 8];
				waiting_byte |= ((temp_byte >> (7 - i % 8)) & 0x01) << (7 - (write_bit_pos % 8));
				write_bit_pos++;
				if (write_bit_pos == 8)
				{
					plain.push_back(waiting_byte);
					if (plain.size() == crypt.size()) { break; }
					waiting_byte = 0x00;
					write_bit_pos = 0;
				}
			}
		};
	for (; read_byte_pos < crypt.size();)
	{
		cryptor.get_block_self_encryption()(tempBlock0, cryptor.get_block_size(), cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = pick_shift();
		while (tempBlock1.size() < cryptor.get_block_size()) { tempBlock1.push_back(0x00); }
		tempBlock2 = NSROOT::utils::squareXOR(tempBlock1, tempBlock0, cryptor.get_block_size());
		add_block(tempBlock2);
		tempBlock0 = tempBlock0.bit_left_move_norise(shift) | tempBlock1.bit_right_move_norise(cryptor.get_block_size() * 8 - shift);
	}
	return plain;
}
void NSROOT::mode::CFBb::encrypt_stream(std::istream& plain, const Data& iv, std::ostream& crypt, Cryptor& cryptor)
{
	//throw CryptionException(DOG_EXCEPTION_MSG_OPINION("not using"));
	uint64_t shift = typeid(cryptor.get_mode()) == typeid(NSROOT::mode::CFBB) ? ((const CFBB&)cryptor.get_mode()).get_shift() : ((const CFBb&)cryptor.get_mode()).get_shift();
	int8_t read_bit_pos = 0;
	dog_torch::serialize::Data tempBlock0 = iv, tempBlock1;
	auto pick_shift = [&plain, &shift, &read_bit_pos]()->dog_torch::serialize::Data
		{
			dog_torch::serialize::Data res; res.reserve((shift / 8) + 1);
			uint8_t fill_byte = 0x00;
			uint8_t temp_byte = 0x00;
			for (uint64_t i = 0; i < shift; i++)
			{
				temp_byte = plain.peek();
				fill_byte |= ((temp_byte >> (7 - read_bit_pos)) & 0x01) << (7 - (i % 8));
				read_bit_pos++;
				if (i % 8 == 7)
				{
					res.push_back(fill_byte);
					fill_byte = 0x00;
				}
				if (read_bit_pos == 8)
				{
					read_bit_pos = 0;
					plain.get();
				}
				if (plain.eof())
				{
					break;
				}
			}
			if (shift % 8 != 0)
			{
				res.push_back(fill_byte);
			}
			return res;
		};
	int8_t waiting_byte = 0x00; int8_t write_bit_pos = 0;
	auto add_block = [&crypt, &shift, &waiting_byte, &write_bit_pos](dog_torch::serialize::Data& tempBlock)->void
		{
			uint8_t temp_byte = 0x00;
			for (uint64_t i = 0; i < shift; i++)
			{
				if (i / 8 == tempBlock.size()) { break; }
				temp_byte = tempBlock[i / 8];
				waiting_byte |= ((temp_byte >> (7 - i % 8)) & 0x01) << (7 - (write_bit_pos % 8));
				write_bit_pos++;
				if (write_bit_pos == 8)
				{
					crypt.put(waiting_byte);
					waiting_byte = 0x00;
					write_bit_pos = 0;
				}
			}
		};
	while (plain.eof())
	{
		cryptor.get_block_self_encryption()(tempBlock0, cryptor.get_block_size(), cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = pick_shift();
		while (tempBlock1.size() < cryptor.get_block_size()) { tempBlock1.push_back(0x00); }
		NSROOT::utils::squareXOR_self(tempBlock1, tempBlock0, cryptor.get_block_size());
		add_block(tempBlock1);
		tempBlock0 = tempBlock0.bit_left_move_norise(shift) | tempBlock1.bit_right_move_norise(cryptor.get_block_size() * 8 - shift);
	}
	crypt.flush();
}
void NSROOT::mode::CFBb::decrypt_stream(std::istream& crypt, const Data& iv, std::ostream& plain, NSROOT::Cryptor& cryptor)
{
	uint64_t shift = typeid(cryptor.get_mode()) == typeid(NSROOT::mode::CFBB) ? ((const CFBB&)cryptor.get_mode()).get_shift() : ((const CFBb&)cryptor.get_mode()).get_shift();
	int8_t read_bit_pos = 0;
	dog_torch::serialize::Data tempBlock0 = iv, tempBlock1, tempBlock2;
	auto pick_shift = [&crypt, &shift, &read_bit_pos]()->dog_torch::serialize::Data
		{
			dog_torch::serialize::Data res; res.reserve((shift / 8) + 1);
			uint8_t fill_byte = 0x00;
			uint8_t temp_byte = 0x00;
			for (uint64_t i = 0; i < shift; i++)
			{
				temp_byte = crypt.peek();
				fill_byte |= ((temp_byte >> (7 - read_bit_pos)) & 0x01) << (7 - (i % 8));
				read_bit_pos++;
				if (i % 8 == 7)
				{
					res.push_back(fill_byte);
					fill_byte = 0x00;
				}
				if (read_bit_pos == 8)
				{
					read_bit_pos = 0;
					crypt.get();
				}
				if (crypt.eof())
				{
					break;
				}
			}
			if (shift % 8 != 0)
			{
				res.push_back(fill_byte);
			}
			return res;
		};
	int8_t waiting_byte = 0x00; int8_t write_bit_pos = 0;
	auto add_block = [&plain, &shift, &waiting_byte, &write_bit_pos](dog_torch::serialize::Data& tempBlock)->void
		{
			uint8_t temp_byte = 0x00;
			for (uint64_t i = 0; i < shift; i++)
			{
				if (i / 8 == tempBlock.size()) { break; }
				temp_byte = tempBlock[i / 8];
				waiting_byte |= ((temp_byte >> (7 - i % 8)) & 0x01) << (7 - (write_bit_pos % 8));
				write_bit_pos++;
				if (write_bit_pos == 8)
				{
					plain.put(waiting_byte);
					waiting_byte = 0x00;
					write_bit_pos = 0;
				}
			}
		};
	while (plain.eof())
	{
		cryptor.get_block_self_encryption()(tempBlock0, cryptor.get_block_size(), cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = pick_shift();
		while (tempBlock1.size() < cryptor.get_block_size()) { tempBlock1.push_back(0x00); }
		tempBlock2 = NSROOT::utils::squareXOR(tempBlock1, tempBlock0, cryptor.get_block_size());
		add_block(tempBlock2);
		tempBlock0 = tempBlock0.bit_left_move_norise(shift) | tempBlock1.bit_right_move_norise(cryptor.get_block_size() * 8 - shift);
	}
	plain.flush();
}
void NSROOT::mode::CFBb::encrypt_streamp(std::istream& plain, const Data& iv, std::ostream& crypt, NSROOT::Cryptor& cryptor,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	uint64_t shift = typeid(cryptor.get_mode()) == typeid(NSROOT::mode::CFBB) ? ((const CFBB&)cryptor.get_mode()).get_shift() : ((const CFBb&)cryptor.get_mode()).get_shift();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);
	int8_t read_bit_pos = 0;
	dog_torch::serialize::Data tempBlock0 = iv, tempBlock1;
	auto pick_shift = [&plain, &shift, &read_bit_pos]()->dog_torch::serialize::Data
		{
			dog_torch::serialize::Data res; res.reserve((shift / 8) + 1);
			uint8_t fill_byte = 0x00;
			uint8_t temp_byte = 0x00;
			for (uint64_t i = 0; i < shift; i++)
			{
				temp_byte = plain.peek();
				fill_byte |= ((temp_byte >> (7 - read_bit_pos)) & 0x01) << (7 - (i % 8));
				read_bit_pos++;
				if (i % 8 == 7)
				{
					res.push_back(fill_byte);
					fill_byte = 0x00;
				}
				if (read_bit_pos == 8)
				{
					read_bit_pos = 0;
					plain.get();
				}
				if (plain.eof())
				{
					break;
				}
			}
			if (shift % 8 != 0)
			{
				res.push_back(fill_byte);
			}
			return res;
		};
	int8_t waiting_byte = 0x00; int8_t write_bit_pos = 0;
	auto add_block = [&crypt, &shift, &waiting_byte, &write_bit_pos](dog_torch::serialize::Data& tempBlock)->void
		{
			uint8_t temp_byte = 0x00;
			for (uint64_t i = 0; i < shift; i++)
			{
				if (i / 8 == tempBlock.size()) { break; }
				temp_byte = tempBlock[i / 8];
				waiting_byte |= ((temp_byte >> (7 - i % 8)) & 0x01) << (7 - (write_bit_pos % 8));
				write_bit_pos++;
				if (write_bit_pos == 8)
				{
					crypt.put(waiting_byte);
					waiting_byte = 0x00;
					write_bit_pos = 0;
				}
			}
		};
	while (plain.eof())
	{
		cryptor.get_block_self_encryption()(tempBlock0, cryptor.get_block_size(), cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = pick_shift();
		while (tempBlock1.size() < cryptor.get_block_size()) { tempBlock1.push_back(0x00); }
		NSROOT::utils::squareXOR_self(tempBlock1, tempBlock0, cryptor.get_block_size());
		add_block(tempBlock1);
		std::unique_lock<std::mutex> lock(*mutex_);
		while (*paused_ && !*stop_)
		{
			cond_->wait(lock);
		}
		if (*stop_) return;
		lock.unlock();
		progress_->store(update_progress(progress_->load(), shift / 8.0, file_size));
		tempBlock0 = tempBlock0.bit_left_move_norise(shift) | tempBlock1.bit_right_move_norise(cryptor.get_block_size() * 8 - shift);
	}
	crypt.flush();
}
void NSROOT::mode::CFBb::decrypt_streamp(std::istream& crypt, const Data& iv, std::ostream& plain, NSROOT::Cryptor& cryptor,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	uint64_t shift = typeid(cryptor.get_mode()) == typeid(NSROOT::mode::CFBB) ? ((const CFBB&)cryptor.get_mode()).get_shift() : ((const CFBb&)cryptor.get_mode()).get_shift();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);
	int8_t read_bit_pos = 0;
	dog_torch::serialize::Data tempBlock0 = iv, tempBlock1, tempBlock2;
	auto pick_shift = [&crypt, &shift, &read_bit_pos]()->dog_torch::serialize::Data
		{
			dog_torch::serialize::Data res; res.reserve((shift / 8) + 1);
			uint8_t fill_byte = 0x00;
			uint8_t temp_byte = 0x00;
			for (uint64_t i = 0; i < shift; i++)
			{
				temp_byte = crypt.peek();
				fill_byte |= ((temp_byte >> (7 - read_bit_pos)) & 0x01) << (7 - (i % 8));
				read_bit_pos++;
				if (i % 8 == 7)
				{
					res.push_back(fill_byte);
					fill_byte = 0x00;
				}
				if (read_bit_pos == 8)
				{
					read_bit_pos = 0;
					crypt.get();
				}
				if (crypt.eof())
				{
					break;
				}
			}
			if (shift % 8 != 0)
			{
				res.push_back(fill_byte);
			}
			return res;
		};
	int8_t waiting_byte = 0x00; int8_t write_bit_pos = 0;
	auto add_block = [&plain, &shift, &waiting_byte, &write_bit_pos](dog_torch::serialize::Data& tempBlock)->void
		{
			uint8_t temp_byte = 0x00;
			for (uint64_t i = 0; i < shift; i++)
			{
				if (i / 8 == tempBlock.size()) { break; }
				temp_byte = tempBlock[i / 8];
				waiting_byte |= ((temp_byte >> (7 - i % 8)) & 0x01) << (7 - (write_bit_pos % 8));
				write_bit_pos++;
				if (write_bit_pos == 8)
				{
					plain.put(waiting_byte);
					waiting_byte = 0x00;
					write_bit_pos = 0;
				}
			}
		};
	while (plain.eof())
	{
		cryptor.get_block_self_encryption()(tempBlock0, cryptor.get_block_size(), cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = pick_shift();
		while (tempBlock1.size() < cryptor.get_block_size()) { tempBlock1.push_back(0x00); }
		tempBlock2 = NSROOT::utils::squareXOR(tempBlock1, tempBlock0, cryptor.get_block_size());
		add_block(tempBlock2);
		std::unique_lock<std::mutex> lock(*mutex_);
		while (*paused_ && !*stop_) { cond_->wait(lock); }
		if (*stop_) return;
		lock.unlock();
		progress_->store(update_progress(progress_->load(), shift / 8.0, file_size));
		tempBlock0 = tempBlock0.bit_left_move_norise(shift) | tempBlock1.bit_right_move_norise(cryptor.get_block_size() * 8 - shift);
	}
	plain.flush();
}

DOG_DATA NSROOT::mode::CFBb::encrypt_CFB1(const Data& plain, const Data& iv, Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	dog_torch::serialize::Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
	dog_torch::serialize::Data tempBlock0 = iv;
	dog_torch::serialize::Data tempBlock1; tempBlock1.reserve(block_size);
	for (uint64_t i0 = 0; i0 < plain.size(); i0++)
	{
		uint8_t B = 0x00;
		for (int j = 0; j < 8; j++)
		{
			tempBlock1 = tempBlock0;
			cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
			uint8_t b = (plain[i0] >> (7 - j) & 0x01) ^ (tempBlock0[0] >> (7 - j) & 0x01);
			B += b << (7 - j);
			uint8_t c = b, d = 0x00;
			for (int i1 = 0; i1 < 16; i1++)
			{
				d = tempBlock1[15 - i1] >> 7;
				tempBlock1[15 - i1] = (tempBlock1[15 - i1] << 1) + c;
				c = d;
			}
		}
		res.push_back(B);
	}
	return res;
}
DOG_DATA NSROOT::mode::CFBb::decrypt_CFB1(const Data& crypt, const Data& iv, Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	dog_torch::serialize::Data res; res.reserve(((crypt.size() / block_size) + 1) * block_size);
	dog_torch::serialize::Data tempBlock0 = iv;
	dog_torch::serialize::Data tempBlock1; tempBlock1.reserve(block_size);
	for (uint64_t i0 = 0; i0 < crypt.size(); i0++)
	{
		uint8_t B = 0x00;
		for (int j = 0; j < 8; j++)
		{
			tempBlock1 = tempBlock0;
			cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
			uint8_t b = (crypt[i0] >> (7 - j) & 0x01) ^ (tempBlock0[0] >> (7 - j) & 0x01);
			B += b << (7 - j);
			uint8_t c = crypt[i0] >> (7 - j) & 0x01, d = 0x00;
			for (int i1 = 0; i1 < 16; i1++)
			{
				d = tempBlock1[15 - i1] >> 7;
				tempBlock1[15 - i1] = (tempBlock1[15 - i1] << 1) + c;
				c = d;
			}
		}
		res.push_back(B);
	}
	return res;

}
void NSROOT::mode::CFBb::encrypt_CFB1_stream(std::istream& plain, const Data& iv, std::ostream& crypt, Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	dog_torch::serialize::Data tempBlock0 = iv;
	dog_torch::serialize::Data tempBlock1(block_size);
	while (plain.tellg() < file_size)
	{
		//uint64_t s = plain.tellg();
		//printf("%llu\r", s);
		uint8_t B = 0x00;
		for (int j = 0; j < 8; j++)
		{
			tempBlock1 = tempBlock0;
			cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
			uint8_t b = (plain.peek() >> (7 - j) & 0x01) ^ (tempBlock0[0] >> (7 - j) & 0x01);
			B += b << (7 - j);
			uint8_t c = b, d = 0x00;
			for (int i1 = 0; i1 < 16; i1++)
			{
				d = tempBlock1[15 - i1] >> 7;
				tempBlock1[15 - i1] = (tempBlock1[15 - i1] << 1) + c;
				c = d;
			}
		}
		plain.get();
		crypt.put(B);
	}
	crypt.flush();
}
void NSROOT::mode::CFBb::decrypt_CFB1_stream(std::istream& crypt, const Data& iv, std::ostream& plain, NSROOT::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	dog_torch::serialize::Data tempBlock0 = iv;
	dog_torch::serialize::Data tempBlock1; tempBlock1.reserve(block_size);
	while (crypt.tellg() < file_size)
	{
		//uint64_t s = crypt.tellg();
		//printf("%llu\r", s);

		uint8_t B = 0x00;
		for (int j = 0; j < 8; j++)
		{
			tempBlock1 = tempBlock0;
			cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
			uint8_t b = (crypt.peek() >> (7 - j) & 0x01) ^ (tempBlock0[0] >> (7 - j) & 0x01);
			B += b << (7 - j);
			uint8_t c = crypt.peek() >> (7 - j) & 0x01, d = 0x00;
			for (int i1 = 0; i1 < 16; i1++)
			{
				d = tempBlock1[15 - i1] >> 7;
				tempBlock1[15 - i1] = (tempBlock1[15 - i1] << 1) + c;
				c = d;
			}
		}
		crypt.get();
		plain.put(B);
	}
	plain.flush();
}
void NSROOT::mode::CFBb::encrypt_CFB1_streamp(std::istream& plain, const Data& iv, std::ostream& crypt, NSROOT::Cryptor& cryptor,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	dog_torch::serialize::Data tempBlock0 = iv;
	dog_torch::serialize::Data tempBlock1(block_size);
	while (plain.tellg() < file_size)
	{
		//uint64_t s = plain.tellg();
		//printf("%llu\r", s);
		uint8_t B = 0x00;
		for (int j = 0; j < 8; j++)
		{
			tempBlock1 = tempBlock0;
			cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
			uint8_t b = (plain.peek() >> (7 - j) & 0x01) ^ (tempBlock0[0] >> (7 - j) & 0x01);
			B += b << (7 - j);
			uint8_t c = b, d = 0x00;
			for (int i1 = 0; i1 < 16; i1++)
			{
				d = tempBlock1[15 - i1] >> 7;
				tempBlock1[15 - i1] = (tempBlock1[15 - i1] << 1) + c;
				c = d;
			}
		}
		plain.get();
		crypt.put(B);
		std::unique_lock<std::mutex> lock(*mutex_);
		while (*paused_ && !*stop_)
		{
			cond_->wait(lock);
		}
		if (*stop_) return;
		lock.unlock();
		progress_->store(update_progress(progress_->load(), 1, file_size));
	}
	crypt.flush();
	progress_->store(1.0);
}
void NSROOT::mode::CFBb::decrypt_CFB1_streamp(std::istream& crypt, const Data& iv, std::ostream& plain, NSROOT::Cryptor& cryptor,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	dog_torch::serialize::Data tempBlock0 = iv;
	dog_torch::serialize::Data tempBlock1; tempBlock1.reserve(block_size);
	while (crypt.tellg() < file_size)
	{
		//uint64_t s = crypt.tellg();
		//printf("%llu\r", s);

		uint8_t B = 0x00;
		for (int j = 0; j < 8; j++)
		{
			tempBlock1 = tempBlock0;
			cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
			uint8_t b = (crypt.peek() >> (7 - j) & 0x01) ^ (tempBlock0[0] >> (7 - j) & 0x01);
			B += b << (7 - j);
			uint8_t c = crypt.peek() >> (7 - j) & 0x01, d = 0x00;
			for (int i1 = 0; i1 < 16; i1++)
			{
				d = tempBlock1[15 - i1] >> 7;
				tempBlock1[15 - i1] = (tempBlock1[15 - i1] << 1) + c;
				c = d;
			}
		}
		crypt.get();
		plain.put(B);
		std::unique_lock<std::mutex> lock(*mutex_);
		while (*paused_ && !*stop_) { cond_->wait(lock); }
		if (*stop_) return;
		lock.unlock();
		progress_->store(update_progress(progress_->load(), 1, file_size));
	}
	plain.flush();
	progress_->store(1.0);
}

dog_torch::crypto::symmetric::mode::CFBb::CFBb(uint64_t shitf, bool using_padding) : Mode("CFBb", true, using_padding)
{
	if (shift == 0)
	{
		throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error: shift is 0\n错误：位移为0"));
	}
	this->shift = shitf;
}

uint64_t NSROOT::mode::CFBb::get_shift() const
{
	return shift % 8 == 0 ? shift / 8 : shift;
}

NSROOT::mode::crypt_func NSROOT::mode::CFBb::get_mult_encrypt() const
{
	if (this->shift % 8 == 0)
	{
		if (this->shift == 8)
		{
			return CFBB::encrypt_CFB8;
		}
		else if (this->shift == 128)
		{
			return CFBB::encrypt_CFB128;
		}
		else
		{
			return CFBB::encrypt;
		}
	}
	else if (this->shift == 1)
	{
		return encrypt_CFB1;
	}
	else
	{
		return encrypt;
	}
}

NSROOT::mode::crypt_func NSROOT::mode::CFBb::get_mult_decrypt() const
{
	if (this->shift % 8 == 0)
	{
		if (this->shift == 8)
		{
			return CFBB::decrypt_CFB8;
		}
		else if (this->shift == 128)
		{
			return CFBB::decrypt_CFB128;
		}
		else
		{
			return CFBB::decrypt;
		}
	}
	else if (this->shift == 1)
	{
		return decrypt_CFB1;
	}
	else
	{
		return decrypt;
	}
}
NSROOT::mode::stream_crypt_func NSROOT::mode::CFBb::get_stream_encrypt() const
{
	if (this->shift % 8 == 0)
	{
		if (this->shift == 8)
		{
			return CFBB::encrypt_CFB8_stream;
		}
		else if (this->shift == 128)
		{
			return CFBB::encrypt_CFB128_stream;
		}
		else
		{
			return CFBB::encrypt_stream;
		}
	}
	else if (this->shift == 1)
	{
		return encrypt_CFB1_stream;
	}
	else
	{
		return encrypt_stream;
	}
}
NSROOT::mode::stream_crypt_func NSROOT::mode::CFBb::get_stream_decrypt() const
{
	if (this->shift % 8 == 0)
	{
		if (this->shift == 8)
		{
			return CFBB::decrypt_CFB8_stream;
		}
		else if (this->shift == 128)
		{
			return CFBB::decrypt_CFB128_stream;
		}
		else
		{
			return CFBB::decrypt_stream;
		}
	}
	else if (this->shift == 1)
	{
		return decrypt_CFB1_stream;
	}
	else
	{
		return decrypt_stream;
	}
}
NSROOT::mode::stream_cryptp_func NSROOT::mode::CFBb::get_stream_encryptp() const
{
	if (this->shift % 8 == 0)
	{
		if (this->shift == 8)
		{
			return CFBB::encrypt_CFB8_streamp;
		}
		else if (this->shift == 128)
		{
			return CFBB::encrypt_CFB128_streamp;
		}
		else
		{
			return CFBB::encrypt_streamp;
		}
	}
	else if (this->shift == 1)
	{
		return encrypt_CFB1_streamp;
	}
	else
	{
		return encrypt_streamp;
	}
}
NSROOT::mode::stream_cryptp_func NSROOT::mode::CFBb::get_stream_decryptp() const
{
	if (this->shift % 8 == 0)
	{
		if (this->shift == 8)
		{
			return CFBB::decrypt_CFB8_streamp;
		}
		else if (this->shift == 128)
		{
			return CFBB::decrypt_CFB128_streamp;
		}
		else
		{
			return CFBB::decrypt_streamp;
		}
	}
	else if (this->shift == 1)
	{
		return decrypt_CFB1_streamp;
	}
	else
	{
		return decrypt_streamp;
	}
}

#undef NSROOT
#undef DOG_DATA