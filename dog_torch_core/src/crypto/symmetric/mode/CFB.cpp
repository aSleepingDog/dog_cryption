#include "crypto/symmetric/mode/CFB.h"

#define NSROOT dog_torch::crypto::symmetric //NSROOT = namespace root
#define DOG_DATA dog_torch::serialize::Data

DOG_DATA NSROOT::mode::CFBB::encrypt(const Data& plain, const Cipher& cipher)
{
	padding::padding_func padding;
	uint64_t nbyte;
	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		nbyte = ((const CFBB&)cipher.get_mode()).get_shift();
		padding = ((const CFBB&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		nbyte = ((const CFBb&)cipher.get_mode()).get_shift();
		padding = ((const CFBb&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	uint64_t block_size = cipher.get_block_size();

	Data res; res.reserve(((plain.size() / nbyte) + 1) * nbyte);
	Data tempBlock1(nbyte);
	Data tempBlock2(nbyte);
	uint64_t i = 0;
	for (i = 0; i < plain.size(); i += nbyte)
	{
		block_self_encryption(tempBlock0, block_size, key, key_size);
		tempBlock1 = plain.sub_by_len(i, nbyte);
		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
		padding(tempBlock1, nbyte);
		NSROOT::utils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
		res += tempBlock1;
		tempBlock0 = tempBlock0.sub_by_len(nbyte, block_size - nbyte) + tempBlock1;
	}
	return res;
}
DOG_DATA NSROOT::mode::CFBB::decrypt(const Data& crypt, const Cipher& cipher)
{
	padding::padding_func unpadding;
	uint64_t nbyte;
	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		nbyte = ((const CFBB&)cipher.get_mode()).get_shift();
		unpadding = ((const CFBB&)cipher.get_mode()).get_padding().get_unpadding();
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		nbyte = ((const CFBb&)cipher.get_mode()).get_shift();
		unpadding = ((const CFBb&)cipher.get_mode()).get_padding().get_unpadding();
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	uint64_t block_size = cipher.get_block_size();

	Data res; res.reserve(((crypt.size() / nbyte) + 1) * nbyte);
	Data tempBlock1(nbyte);
	Data tempBlock2(nbyte);
	uint64_t i = 0;
	for (i = 0; i < crypt.size(); i += nbyte)
	{
		block_self_encryption(tempBlock0, block_size, key, key_size);
		tempBlock1 = crypt.sub_by_len(i, nbyte);
		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
		tempBlock1 = NSROOT::utils::squareXOR(tempBlock1, tempBlock2, tempBlock1.size());
		unpadding(tempBlock1, nbyte);
		res += tempBlock1;
		tempBlock0 = tempBlock0.sub_by_len(nbyte, block_size - nbyte) + tempBlock1;
	}
	return res;
}
void NSROOT::mode::CFBB::encrypt_stream(std::istream& plain, std::ostream& crypt, const NSROOT::Cipher& cipher)
{
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);
	
	padding::padding_func padding;
	uint64_t nbyte;
	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		nbyte = ((const CFBB&)cipher.get_mode()).get_shift();
		padding = ((const CFBB&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		nbyte = ((const CFBb&)cipher.get_mode()).get_shift();
		padding = ((const CFBb&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	uint64_t block_size = cipher.get_block_size();

	Data tempBlock1(nbyte);
	Data tempBlock2(nbyte);
	while (plain.tellg() <= file_size - nbyte)
	{
		block_self_encryption(tempBlock0, block_size, key, key_size);
		plain.read((char*)tempBlock1.data(), nbyte);
		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
		NSROOT::utils::squareXOR_self(tempBlock1, tempBlock2, nbyte);
		crypt.write((char*)tempBlock1.data(), nbyte);
		tempBlock0 = tempBlock0.sub_by_len(nbyte, block_size - nbyte) + tempBlock1;
	}
	block_self_encryption(tempBlock0, block_size, key, key_size);;
	plain.read((char*)tempBlock1.data(), nbyte);
	tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
	for (int i = 0; i < nbyte - plain.gcount(); ++i) { tempBlock1.pop_back(); }
	padding(tempBlock1, nbyte);
	NSROOT::utils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
	crypt.write((char*)tempBlock1.data(), nbyte);
	crypt.flush();
}
void NSROOT::mode::CFBB::decrypt_stream(std::istream& crypt, std::ostream& plain, const NSROOT::Cipher& cipher)
{
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(now_pos, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	padding::padding_func unpadding;
	uint64_t nbyte;
	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		nbyte = ((const CFBB&)cipher.get_mode()).get_shift();
		unpadding = ((const CFBB&)cipher.get_mode()).get_padding().get_unpadding();
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		nbyte = ((const CFBb&)cipher.get_mode()).get_shift();
		unpadding = ((const CFBb&)cipher.get_mode()).get_padding().get_unpadding();
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	uint64_t block_size = cipher.get_block_size();

	Data tempBlock1(nbyte);
	Data tempBlock2(nbyte);
	while (crypt.tellg() < file_size - nbyte)
	{
		block_self_encryption(tempBlock0, block_size, key, key_size);
		crypt.read((char*)tempBlock1.data(), nbyte);
		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
		NSROOT::utils::squareXOR_self(tempBlock2, tempBlock1, nbyte);
		plain.write((char*)tempBlock2.data(), nbyte);
		tempBlock0 = tempBlock0.sub_by_len(nbyte, block_size - nbyte) + tempBlock1;
	}
	block_self_encryption(tempBlock0, block_size, key, key_size);
	crypt.read((char*)tempBlock1.data(), nbyte);
	for (int i = 0; i < nbyte - crypt.gcount(); ++i) { tempBlock1.pop_back(); }
	tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
	NSROOT::utils::squareXOR_self(tempBlock1, tempBlock2, nbyte);
	unpadding(tempBlock1, nbyte);
	plain.write((char*)tempBlock1.data(), nbyte);
	plain.flush();
}
void NSROOT::mode::CFBB::encrypt_streamp(std::istream& plain, std::ostream& crypt, const NSROOT::Cipher& cipher,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);
	padding::padding_func padding;
	uint64_t nbyte;
	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		nbyte = ((const CFBB&)cipher.get_mode()).get_shift();
		padding = ((const CFBB&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		nbyte = ((const CFBb&)cipher.get_mode()).get_shift();
		padding = ((const CFBb&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	uint64_t block_size = cipher.get_block_size();

	Data tempBlock1(nbyte);
	Data tempBlock2(nbyte);
	while (plain.tellg() <= file_size - nbyte)
	{
		block_self_encryption(tempBlock0, block_size, key, key_size);
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
	block_self_encryption(tempBlock0, block_size, key, key_size);
	plain.read((char*)tempBlock1.data(), nbyte);
	tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
	for (int i = 0; i < nbyte - plain.gcount(); ++i) { tempBlock1.pop_back(); }
	padding(tempBlock1, nbyte);
	NSROOT::utils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
	crypt.write((char*)tempBlock1.data(), nbyte);
	crypt.flush();
	progress_->store(1.0);
}
void NSROOT::mode::CFBB::decrypt_streamp(std::istream& crypt, std::ostream& plain, const NSROOT::Cipher& cipher,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(now_pos, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	padding::padding_func unpadding;
	uint64_t nbyte;
	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		nbyte = ((const CFBB&)cipher.get_mode()).get_shift();
		unpadding = ((const CFBB&)cipher.get_mode()).get_padding().get_unpadding();
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		nbyte = ((const CFBb&)cipher.get_mode()).get_shift();
		unpadding = ((const CFBb&)cipher.get_mode()).get_padding().get_unpadding();
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	uint64_t block_size = cipher.get_block_size();

	Data tempBlock1(nbyte);
	Data tempBlock2(nbyte);
	while (crypt.tellg() < file_size - nbyte)
	{
		block_self_encryption(tempBlock0, block_size, key, key_size);
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
	block_self_encryption(tempBlock0, block_size, key, key_size);
	crypt.read((char*)tempBlock1.data(), nbyte);
	tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
	NSROOT::utils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
	unpadding(tempBlock1, nbyte);
	plain.write((char*)tempBlock1.data(), nbyte);
	plain.flush();
	progress_->store(1.0);
}

DOG_DATA NSROOT::mode::CFBB::encrypt_CFB8(const Data& plain, const Cipher& cipher)
{
	padding::padding_func padding;
	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		padding = ((const CFBB&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		padding = ((const CFBb&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
    algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	uint64_t block_size = cipher.get_block_size();
	
	Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
	Data tempBlock1; tempBlock1.reserve(block_size);
	for (uint64_t i0 = 0; i0 < plain.size(); i0++)
	{
		tempBlock1 = tempBlock0;
		block_self_encryption(tempBlock0, block_size, key, key_size);
		uint8_t b = plain[i0] ^ tempBlock0[0];
		res.push_back(b);
		tempBlock1.push_back(b);
	}
	return res;
}
DOG_DATA NSROOT::mode::CFBB::decrypt_CFB8(const Data& crypt, const Cipher& cipher)
{
	padding::padding_func unpadding;
	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		unpadding = ((const CFBB&)cipher.get_mode()).get_padding().get_unpadding();
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		unpadding = ((const CFBb&)cipher.get_mode()).get_padding().get_unpadding();
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	uint8_t block_size = cipher.get_block_size();

	Data res; res.reserve(((crypt.size() / block_size) + 1) * block_size);
	Data tempBlock1; tempBlock1.reserve(block_size);
	for (uint64_t i0 = 0; i0 < crypt.size(); i0++)
	{
		tempBlock1 = tempBlock0;
		block_self_encryption(tempBlock0, block_size, key, key_size);
		uint8_t b = crypt[i0] ^ tempBlock0[0];
		res.push_back(b);
		tempBlock0.push_back(crypt[i0]);
	}
	return res;
}
void NSROOT::mode::CFBB::encrypt_CFB8_stream(std::istream& plain, std::ostream& crypt, const NSROOT::Cipher& cipher)
{
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	padding::padding_func padding;
	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		padding = ((const CFBB&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		padding = ((const CFBb&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	algorithm::block_self_cryption_func block_self_cryption = cipher.get_block_self_encryption();
	uint64_t block_size = cipher.get_block_size();

	Data tempBlock1(block_size);
	Data middleResult; middleResult.reserve(block_size);
	while (plain.tellg() < file_size)
	{
		tempBlock1 = tempBlock0;
		block_self_cryption(tempBlock0, block_size, key, key_size);
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
void NSROOT::mode::CFBB::decrypt_CFB8_stream(std::istream& crypt, std::ostream& plain, const NSROOT::Cipher& cipher)
{
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	padding::padding_func padding;
	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		padding = ((const CFBB&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		padding = ((const CFBb&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	uint64_t block_size = cipher.get_block_size();

	Data tempBlock1; tempBlock1.reserve(block_size);
	Data middleResult; middleResult.reserve(block_size);
	while (crypt.tellg() < file_size)
	{
		tempBlock1 = tempBlock0;
		block_self_encryption(tempBlock0, block_size, key, key_size);
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
void NSROOT::mode::CFBB::encrypt_CFB8_streamp(std::istream& plain, std::ostream& crypt, const NSROOT::Cipher& cipher,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	padding::padding_func padding;
	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		padding = ((const CFBB&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		padding = ((const CFBb&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	uint64_t block_size = cipher.get_block_size();

	Data tempBlock1(block_size);
	Data middleResult; middleResult.reserve(block_size);
	while (plain.tellg() < file_size)
	{
		tempBlock1 = tempBlock0;
		block_self_encryption(tempBlock0, block_size, key, key_size);
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
void NSROOT::mode::CFBB::decrypt_CFB8_streamp(std::istream& crypt, std::ostream& plain, const NSROOT::Cipher& cipher,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(now_pos, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	padding::padding_func padding;
	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		padding = ((const CFBB&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		padding = ((const CFBb&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	uint64_t block_size = cipher.get_block_size();

	dog_torch::serialize::Data tempBlock1; tempBlock1.reserve(block_size);
	dog_torch::serialize::Data middleResult; middleResult.reserve(block_size);
	while (crypt.tellg() < file_size)
	{
		tempBlock1 = tempBlock0;
		block_self_encryption(tempBlock0, block_size, key, key_size);
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

DOG_DATA NSROOT::mode::CFBB::encrypt_CFB128(const Data& plain, const Cipher& cipher)
{
	padding::padding_func padding;
	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		padding = ((const CFBB&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		padding = ((const CFBb&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	uint64_t block_size = cipher.get_block_size();

	Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
	Data tempBlock1(block_size);
	uint64_t i0 = 0;
	for (i0 = 0; i0 <= plain.size() - 16 && plain.size() >= 16; i0 += 16)
	{
		block_self_encryption(tempBlock0, block_size, key, key_size);
		tempBlock1 = plain.sub_by_len(i0, block_size);
		NSROOT::utils::squareXOR_self(tempBlock1, tempBlock0, 16);
		res = res + tempBlock1;
		tempBlock0 = tempBlock1;
	}
	block_self_encryption(tempBlock0, block_size, key, key_size);
	tempBlock1 = plain.sub_by_len(i0, block_size);
	padding(tempBlock1, 16);
	NSROOT::utils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
	res += tempBlock1;
	return res;
}
DOG_DATA NSROOT::mode::CFBB::decrypt_CFB128(const Data& crypt, const Cipher& cipher)
{
	padding::padding_func padding;
	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		padding = ((const CFBB&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		padding = ((const CFBb&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	uint64_t block_size = cipher.get_block_size();

	Data res; res.reserve(((crypt.size() / block_size) + 1) * block_size);
	Data tempBlock1(block_size);
	uint64_t i0 = 0;
	for (; i0 < crypt.size() - 16 && crypt.size() > 16; i0 += 16)
	{
		block_self_encryption(tempBlock0, block_size, key, key_size);
		tempBlock1 = crypt.sub_by_pos(i0, i0 + 16);
		res = res + NSROOT::utils::squareXOR(tempBlock0, tempBlock1, block_size);
		tempBlock0 = tempBlock1;
	}
	block_self_encryption(tempBlock0, block_size, key, key_size);
	tempBlock1 = crypt.sub_by_pos(i0, i0 + 16);
	NSROOT::utils::squareXOR_self(tempBlock1, tempBlock0, tempBlock0.size());
	padding(tempBlock1, 16);
	res += tempBlock1;
	return res;
}
void NSROOT::mode::CFBB::encrypt_CFB128_stream(std::istream& plain, std::ostream& crypt, const NSROOT::Cipher& cipher)
{
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	padding::padding_func padding;
	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		padding = ((const CFBB&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		padding = ((const CFBb&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	uint64_t block_size = cipher.get_block_size();

	dog_torch::serialize::Data tempBlock1(block_size);
	while (plain.tellg() <= file_size - block_size)
	{
		block_self_encryption(tempBlock0, block_size, key, key_size);
		plain.read((char*)tempBlock1.data(), 16);
		NSROOT::utils::squareXOR_self(tempBlock0, tempBlock1, block_size);
		crypt.write((char*)tempBlock0.data(), 16);
	}
	block_self_encryption(tempBlock0, block_size, key, key_size); 
	plain.read((char*)tempBlock1.data(), 16);
	for (int i = 0; i < 16 - plain.gcount(); i++) { tempBlock1.pop_back(); }
	padding(tempBlock1, 16);
	NSROOT::utils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
	crypt.write((char*)tempBlock1.data(), tempBlock1.size());
	crypt.flush();
}
void NSROOT::mode::CFBB::decrypt_CFB128_stream(std::istream& crypt, std::ostream& plain, const NSROOT::Cipher& cipher)
{
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(now_pos, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	padding::padding_func unpadding;
	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		unpadding = ((const CFBB&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		unpadding = ((const CFBb&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	algorithm::block_self_cryption_func block_self_decryption = cipher.get_block_self_decryption();
	uint64_t block_size = cipher.get_block_size();

	Data tempBlock1(block_size);
	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		cipher.get_block_self_encryption()(tempBlock0, block_size, cipher.get_available_key(), cipher.get_key_size());
		crypt.read((char*)tempBlock1.data(), block_size);
		plain.write((char*)NSROOT::utils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
		tempBlock0 = tempBlock1;
	}
	cipher.get_block_self_encryption()(tempBlock0, block_size, cipher.get_available_key(), cipher.get_key_size());
	crypt.read((char*)tempBlock1.data(), block_size);
	for (int i = 0; i < 16 - crypt.gcount(); i++) { tempBlock1.pop_back(); }
	NSROOT::utils::squareXOR_self(tempBlock1, tempBlock0, block_size);
	unpadding(tempBlock1, block_size);
	plain.write((char*)tempBlock1.data(), tempBlock1.size());
	plain.flush();
}
void NSROOT::mode::CFBB::encrypt_CFB128_streamp(std::istream& plain, std::ostream& crypt, const NSROOT::Cipher& cipher,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	padding::padding_func padding;
	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		padding = ((const CFBB&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		padding = ((const CFBb&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	uint64_t block_size = cipher.get_block_size();

	dog_torch::serialize::Data tempBlock1(block_size);
	while (plain.tellg() <= file_size - block_size)
	{
		block_self_encryption(tempBlock0, block_size, key, key_size);
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
	block_self_encryption(tempBlock0, block_size, key, key_size);
	plain.read((char*)tempBlock1.data(), 16);
	for (int i = 0; i < 16 - plain.gcount(); i++) { tempBlock1.pop_back(); }
	padding(tempBlock1, 16);
	NSROOT::utils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
	crypt.write((char*)tempBlock1.data(), tempBlock1.size());
	progress_->store(update_progress(progress_->load(), 16, file_size));
	crypt.flush();
	progress_->store(1.0);

}
void NSROOT::mode::CFBB::decrypt_CFB128_streamp(std::istream& crypt, std::ostream& plain, const NSROOT::Cipher& cipher,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(now_pos, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	padding::padding_func unpadding;
	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		unpadding = ((const CFBB&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		unpadding = ((const CFBb&)cipher.get_mode()).get_padding().get_padding();
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	uint64_t block_size = cipher.get_block_size();

	dog_torch::serialize::Data tempBlock1(block_size);
	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		block_self_encryption(tempBlock0, block_size, key, key_size);
		crypt.read((char*)tempBlock1.data(), block_size);
		plain.write((char*)NSROOT::utils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
		std::unique_lock<std::mutex> lock(*mutex_);
		while (*paused_ && !*stop_) { cond_->wait(lock); }
		if (*stop_) return;
		lock.unlock();
		progress_->store(update_progress(progress_->load(), 16, file_size));
		tempBlock0 = tempBlock1;
	}
	block_self_encryption(tempBlock0, block_size, key, key_size);
	crypt.read((char*)tempBlock1.data(), block_size);
	for (int i = 0; i < 16 - crypt.gcount(); i++) { tempBlock1.pop_back(); }
	NSROOT::utils::squareXOR_self(tempBlock1, tempBlock0, block_size);
	unpadding(tempBlock1, 16);
	plain.write((char*)tempBlock1.data(), tempBlock1.size());
	progress_->store(update_progress(progress_->load(), 16, file_size));
	plain.flush();
	progress_->store(1.0);
}

NSROOT::mode::CFBB::CFBB(const padding::Padding& padding, const Data& iv, uint64_t shift) : Mode("CFBB")
{
	if (shift == 0)
	{
		throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error: shift is 0\n错误：位移为0"));
	}
	this->shift_ = shift;
	this->padding_ = padding.clone();
	this->iv_ = iv;
}
dog_torch::crypto::symmetric::mode::CFBB::CFBB(const CFBB& other) : Mode("CFBB")
{
	this->padding_ = other.padding_->clone();
	this->shift_ = other.shift_;
	this->iv_ = other.iv_;
}

std::unique_ptr<NSROOT::mode::Mode> NSROOT::mode::CFBB::clone() const
{
	return std::move(std::make_unique<CFBB>(*this));
}

uint64_t NSROOT::mode::CFBB::get_shift() const
{
	return this->shift_;
}

const DOG_DATA& NSROOT::mode::CFBB::get_iv() const
{
	return this->iv_;
}
const NSROOT::padding::Padding& NSROOT::mode::CFBB::get_padding() const
{
	return *this->padding_;
}

NSROOT::mode::crypt_func NSROOT::mode::CFBB::get_mult_encrypt() const
{
	if (this->shift_ == 1)
	{
		return encrypt_CFB8;
	}
	else if (this->shift_ == 16)
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
	if (this->shift_ == 1)
	{
		return decrypt_CFB8;
	}
	else if (this->shift_ == 16)
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
	if (this->shift_ == 1)
	{
		return encrypt_CFB8_stream;
	}
	else if (this->shift_ == 16)
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
	if (this->shift_ == 1)
	{
		return decrypt_CFB8_stream;
	}
	else if (this->shift_ == 16)
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
	if (this->shift_ == 1)
	{
		return encrypt_CFB8_streamp;
	}
	else if (this->shift_ == 16)
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
	if (this->shift_ == 1)
	{
		return decrypt_CFB8_streamp;
	}
	else if (this->shift_ == 16)
	{
		return decrypt_CFB128_streamp;
	}
	else
	{
		return decrypt_streamp;
	}
}

DOG_DATA NSROOT::mode::CFBb::encrypt(const Data& plain, const Cipher& cipher)
{
	uint64_t shift;
	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		shift = ((const CFBB&)cipher.get_mode()).get_shift();
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		shift = ((const CFBb&)cipher.get_mode()).get_shift();
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	uint64_t block_size = cipher.get_block_size();
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();

	uint64_t read_byte_pos = 0;
	dog_torch::serialize::Data crypt;
	crypt.reserve(plain.size());
	Data tempBlock1;
	int8_t read_bit_pos = 0;
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
		block_self_encryption(tempBlock0, block_size, key, key_size);
		tempBlock1 = pick_shift();
		while (tempBlock1.size() < block_size) { tempBlock1.push_back(0x00); }
		NSROOT::utils::squareXOR_self(tempBlock1, tempBlock0, block_size);
		add_block(tempBlock1);
		tempBlock0 = tempBlock0.bit_left_move_norise(shift) | tempBlock1.bit_right_move_norise(block_size * 8 - shift);
	}
	return crypt;
}
DOG_DATA NSROOT::mode::CFBb::decrypt(const Data& crypt, const Cipher& cipher)
{
	uint64_t shift;
	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		shift = ((const CFBB&)cipher.get_mode()).get_shift();
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		shift = ((const CFBb&)cipher.get_mode()).get_shift();
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	uint64_t block_size = cipher.get_block_size();
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();

	dog_torch::serialize::Data plain; plain.reserve(crypt.size());
	uint64_t read_byte_pos = 0;
	int8_t read_bit_pos = 0;
	dog_torch::serialize::Data tempBlock1, tempBlock2;
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
		block_self_encryption(tempBlock0, block_size, key, key_size);
		tempBlock1 = pick_shift();
		while (tempBlock1.size() < block_size) { tempBlock1.push_back(0x00); }
		tempBlock2 = NSROOT::utils::squareXOR(tempBlock1, tempBlock0, block_size);
		add_block(tempBlock2);
		tempBlock0 = tempBlock0.bit_left_move_norise(shift) | tempBlock1.bit_right_move_norise(block_size * 8 - shift);
	}
	return plain;
}
void NSROOT::mode::CFBb::encrypt_stream(std::istream& plain, std::ostream& crypt, const NSROOT::Cipher& cipher)
{
	//throw CryptionException(DOG_EXCEPTION_MSG_OPINION("not using"));
	uint64_t shift;
	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		shift = ((const CFBB&)cipher.get_mode()).get_shift();
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		shift = ((const CFBb&)cipher.get_mode()).get_shift();
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	uint64_t block_size = cipher.get_block_size();
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size(); 
	
	int8_t read_bit_pos = 0;
	Data tempBlock1;
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
		block_self_encryption(tempBlock0, block_size, key, key_size);
		tempBlock1 = pick_shift();
		while (tempBlock1.size() < block_size) { tempBlock1.push_back(0x00); }
		NSROOT::utils::squareXOR_self(tempBlock1, tempBlock0, block_size);
		add_block(tempBlock1);
		tempBlock0 = tempBlock0.bit_left_move_norise(shift) | tempBlock1.bit_right_move_norise(block_size * 8 - shift);
	}
	crypt.flush();
}
void NSROOT::mode::CFBb::decrypt_stream(std::istream& crypt, std::ostream& plain, const NSROOT::Cipher& cipher)
{
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(now_pos, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	uint64_t shift;
	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		shift = ((const CFBB&)cipher.get_mode()).get_shift();
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		shift = ((const CFBb&)cipher.get_mode()).get_shift();
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	uint64_t block_size = cipher.get_block_size();
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size(); 
	
	int8_t read_bit_pos = 0;
	Data tempBlock1, tempBlock2;
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
		block_self_encryption(tempBlock0, block_size, key, key_size);
		tempBlock1 = pick_shift();
		while (tempBlock1.size() < block_size) { tempBlock1.push_back(0x00); }
		tempBlock2 = NSROOT::utils::squareXOR(tempBlock1, tempBlock0, block_size);
		add_block(tempBlock2);
		tempBlock0 = tempBlock0.bit_left_move_norise(shift) | tempBlock1.bit_right_move_norise(block_size * 8 - shift);
	}
	plain.flush();
}
void NSROOT::mode::CFBb::encrypt_streamp(std::istream& plain, std::ostream& crypt, const NSROOT::Cipher& cipher,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);
	
	uint64_t shift;
	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		shift = ((const CFBB&)cipher.get_mode()).get_shift();
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		shift = ((const CFBb&)cipher.get_mode()).get_shift();
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	uint64_t block_size = cipher.get_block_size();
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();

	int8_t read_bit_pos = 0;
	Data tempBlock1;
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
		block_self_encryption(tempBlock0, block_size, key, key_size);
		tempBlock1 = pick_shift();
		while (tempBlock1.size() < block_size) { tempBlock1.push_back(0x00); }
		NSROOT::utils::squareXOR_self(tempBlock1, tempBlock0, block_size);
		add_block(tempBlock1);
		std::unique_lock<std::mutex> lock(*mutex_);
		while (*paused_ && !*stop_)
		{
			cond_->wait(lock);
		}
		if (*stop_) return;
		lock.unlock();
		progress_->store(update_progress(progress_->load(), shift / 8.0, file_size));
		tempBlock0 = tempBlock0.bit_left_move_norise(shift) | tempBlock1.bit_right_move_norise(block_size * 8 - shift);
	}
	progress_->store(1.0);
	crypt.flush();
}
void NSROOT::mode::CFBb::decrypt_streamp(std::istream& crypt, std::ostream& plain, const NSROOT::Cipher& cipher,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(now_pos, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	uint64_t shift;
	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		shift = ((const CFBB&)cipher.get_mode()).get_shift();
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		shift = ((const CFBb&)cipher.get_mode()).get_shift();
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	uint64_t block_size = cipher.get_block_size();
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();

	int8_t read_bit_pos = 0;
	Data tempBlock1, tempBlock2;
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
		block_self_encryption(tempBlock0, block_size, key, key_size);
		tempBlock1 = pick_shift();
		while (tempBlock1.size() < block_size) { tempBlock1.push_back(0x00); }
		tempBlock2 = NSROOT::utils::squareXOR(tempBlock1, tempBlock0, block_size);
		add_block(tempBlock2);
		std::unique_lock<std::mutex> lock(*mutex_);
		while (*paused_ && !*stop_) { cond_->wait(lock); }
		if (*stop_) return;
		lock.unlock();
		progress_->store(update_progress(progress_->load(), shift / 8.0, file_size));
		tempBlock0 = tempBlock0.bit_left_move_norise(shift) | tempBlock1.bit_right_move_norise(block_size * 8 - shift);
	}
	progress_->store(1.0);
	plain.flush();
}

DOG_DATA NSROOT::mode::CFBb::encrypt_CFB1(const Data& plain, const Cipher& cipher)
{
	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	uint8_t block_size = cipher.get_block_size();

	Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
	
	Data tempBlock1; tempBlock1.reserve(block_size);
	for (uint64_t i0 = 0; i0 < plain.size(); i0++)
	{
		uint8_t B = 0x00;
		for (int j = 0; j < 8; j++)
		{
			tempBlock1 = tempBlock0;
			block_self_encryption(tempBlock0, block_size, key, key_size);
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
DOG_DATA NSROOT::mode::CFBb::decrypt_CFB1(const Data& crypt, const Cipher& cipher)
{
	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	uint8_t block_size = cipher.get_block_size();

	Data res; res.reserve(((crypt.size() / block_size) + 1) * block_size);
	Data tempBlock1; tempBlock1.reserve(block_size);
	for (uint64_t i0 = 0; i0 < crypt.size(); i0++)
	{
		uint8_t B = 0x00;
		for (int j = 0; j < 8; j++)
		{
			tempBlock1 = tempBlock0;
			block_self_encryption(tempBlock0, block_size, key, key_size);
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
void NSROOT::mode::CFBb::encrypt_CFB1_stream(std::istream& plain, std::ostream& crypt, const NSROOT::Cipher& cipher)
{
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	uint8_t block_size = cipher.get_block_size();

	Data tempBlock1(block_size);
	while (plain.tellg() < file_size)
	{
		//uint64_t s = plain.tellg();
		//printf("%llu\r", s);
		uint8_t B = 0x00;
		for (int j = 0; j < 8; j++)
		{
			tempBlock1 = tempBlock0;
			block_self_encryption(tempBlock0, block_size, key, key_size);
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
void NSROOT::mode::CFBb::decrypt_CFB1_stream(std::istream& crypt, std::ostream& plain, const NSROOT::Cipher& cipher)
{
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(now_pos, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	uint8_t block_size = cipher.get_block_size();

	Data tempBlock1; tempBlock1.reserve(block_size);
	while (crypt.tellg() < file_size)
	{
		//uint64_t s = crypt.tellg();
		//printf("%llu\r", s);

		uint8_t B = 0x00;
		for (int j = 0; j < 8; j++)
		{
			tempBlock1 = tempBlock0;
			block_self_encryption(tempBlock0, block_size, key, key_size);
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
void NSROOT::mode::CFBb::encrypt_CFB1_streamp(std::istream& plain, std::ostream& crypt, const NSROOT::Cipher& cipher,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	uint8_t block_size = cipher.get_block_size();

	Data tempBlock1(block_size);
	while (plain.tellg() < file_size)
	{
		//uint64_t s = plain.tellg();
		//printf("%llu\r", s);
		uint8_t B = 0x00;
		for (int j = 0; j < 8; j++)
		{
			tempBlock1 = tempBlock0;
			block_self_encryption(tempBlock0, block_size, key, key_size);
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
void NSROOT::mode::CFBb::decrypt_CFB1_streamp(std::istream& crypt, std::ostream& plain, const NSROOT::Cipher& cipher,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(now_pos, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	Data tempBlock0;
	if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBB))
	{
		tempBlock0 = ((const CFBB&)cipher.get_mode()).get_iv();
	}
	else if (typeid(cipher.get_mode()) == typeid(NSROOT::mode::CFBb))
	{
		tempBlock0 = ((const CFBb&)cipher.get_mode()).get_iv();
	}
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	uint8_t block_size = cipher.get_block_size();

	Data tempBlock1; tempBlock1.reserve(block_size);
	while (crypt.tellg() < file_size)
	{
		//uint64_t s = crypt.tellg();
		//printf("%llu\r", s);

		uint8_t B = 0x00;
		for (int j = 0; j < 8; j++)
		{
			tempBlock1 = tempBlock0;
			block_self_encryption(tempBlock0, block_size, key, key_size);
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

NSROOT::mode::CFBb::CFBb(const padding::Padding& padding, const Data& iv, uint64_t shift) : Mode("CFBb")
{
	if (shift == 0)
	{
		throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error: shift is 0\n错误：位移为0"));
	}
	this->shift_ = shift;
	this->padding_ = padding.clone();
	this->iv_ = iv;
}
dog_torch::crypto::symmetric::mode::CFBb::CFBb(const CFBb& other) : Mode("CFBb")
{
	this->padding_ = other.padding_->clone();
	this->shift_ = other.shift_;
	this->iv_ = other.iv_;
}

uint64_t NSROOT::mode::CFBb::get_shift() const
{
	return shift_ % 8 == 0 ? shift_ / 8 : shift_;
}

const DOG_DATA& NSROOT::mode::CFBb::get_iv() const
{
	return this->iv_;
}
const NSROOT::padding::Padding& NSROOT::mode::CFBb::get_padding() const
{
	return *this->padding_;
}

std::unique_ptr<NSROOT::mode::Mode> NSROOT::mode::CFBb::clone() const
{
	return std::move(std::make_unique<CFBb>(*this));
}

NSROOT::mode::crypt_func NSROOT::mode::CFBb::get_mult_encrypt() const
{
	if (this->shift_ % 8 == 0)
	{
		if (this->shift_ == 8)
		{
			return CFBB::encrypt_CFB8;
		}
		else if (this->shift_ == 128)
		{
			return CFBB::encrypt_CFB128;
		}
		else
		{
			return CFBB::encrypt;
		}
	}
	else if (this->shift_ == 1)
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
	if (this->shift_ % 8 == 0)
	{
		if (this->shift_ == 8)
		{
			return CFBB::decrypt_CFB8;
		}
		else if (this->shift_ == 128)
		{
			return CFBB::decrypt_CFB128;
		}
		else
		{
			return CFBB::decrypt;
		}
	}
	else if (this->shift_ == 1)
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
	if (this->shift_ % 8 == 0)
	{
		if (this->shift_ == 8)
		{
			return CFBB::encrypt_CFB8_stream;
		}
		else if (this->shift_ == 128)
		{
			return CFBB::encrypt_CFB128_stream;
		}
		else
		{
			return CFBB::encrypt_stream;
		}
	}
	else if (this->shift_ == 1)
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
	if (this->shift_ % 8 == 0)
	{
		if (this->shift_ == 8)
		{
			return CFBB::decrypt_CFB8_stream;
		}
		else if (this->shift_ == 128)
		{
			return CFBB::decrypt_CFB128_stream;
		}
		else
		{
			return CFBB::decrypt_stream;
		}
	}
	else if (this->shift_ == 1)
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
	if (this->shift_ % 8 == 0)
	{
		if (this->shift_ == 8)
		{
			return CFBB::encrypt_CFB8_streamp;
		}
		else if (this->shift_ == 128)
		{
			return CFBB::encrypt_CFB128_streamp;
		}
		else
		{
			return CFBB::encrypt_streamp;
		}
	}
	else if (this->shift_ == 1)
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
	if (this->shift_ % 8 == 0)
	{
		if (this->shift_ == 8)
		{
			return CFBB::decrypt_CFB8_streamp;
		}
		else if (this->shift_ == 128)
		{
			return CFBB::decrypt_CFB128_streamp;
		}
		else
		{
			return CFBB::decrypt_streamp;
		}
	}
	else if (this->shift_ == 1)
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