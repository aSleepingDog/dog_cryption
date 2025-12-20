// #include "crypto/symmetric/cryptor.h"

// #define NSROOT dog_torch::crypto::symmetric //NSROOT = namespace root

// double NSROOT::mode::update_progress(double progress, double progress_step, double progress_max)
// {
// 	return progress + progress_step * 1.0 / progress_max;
// 

// const NSROOT::mode::Config NSROOT::mode::ECB::CONFIG = Config("ECB", 0, false, true, false);
// dog_torch::serialize::Data NSROOT::mode::ECB::encrypt(dog_torch::serialize::Data plain, dog_torch::serialize::Data iv, NSROOT::algorithmCryptor& cryptor)
// {
// 	dog_torch::serialize::Data res; uint8_t block_size = cryptor.get_block_size();
// 	res.reserve(((plain.size() / block_size) + 1) * block_size);
// 	dog_torch::serialize::Data tempBlock;
// 	for (uint64_t i0 = 0; i0 <= plain.size(); i0 += block_size)
// 	{
// 		tempBlock = plain.sub_by_pos(i0, i0 + block_size);
// 		if (tempBlock.size() < block_size) { cryptor.get_padding()(tempBlock, block_size); }
// 		cryptor.get_block_self_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		res += tempBlock;
// 		tempBlock.rm_pos();
// 	}
// 	return res;
// }
// dog_torch::serialize::Data NSROOT::mode::ECB::decrypt(dog_torch::serialize::Data crypt, dog_torch::serialize::Data iv, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	dog_torch::serialize::Data res; res.reserve(crypt.size());
// 	dog_torch::serialize::Data tempBlock(block_size);
// 	for (uint64_t i0 = 0; i0 < crypt.size(); i0 += block_size)
// 	{
// 		tempBlock = crypt.sub_by_pos(i0, i0 + block_size);
// 		cryptor.get_block_self_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		res += tempBlock;
// 	}
// 	cryptor.get_unpadding()(res, block_size);
// 	return res;
// }
// void NSROOT::mode::ECB::encrypt_stream(std::istream& plain, dog_torch::serialize::Data iv, std::ostream& crypt, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	plain.seekg(0, std::ios::end);
// 	uint64_t file_size = plain.tellg();
// 	plain.seekg(0, std::ios::beg);

// 	dog_torch::serialize::Data tempBlock(block_size);
// 	while (plain.tellg() <= file_size - block_size)
// 	{
// 		plain.read((char*)tempBlock.data(), block_size);
// 		cryptor.get_block_self_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		crypt.write((char*)tempBlock.data(), block_size);
// 		//printf("%03ull%%\r", plain.tellg() * 100 / file_size);
// 	}
// 	plain.read((char*)tempBlock.data(), block_size);
// 	if (plain.gcount() < block_size)
// 	{
// 		for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock.pop_back(); }
// 		cryptor.get_padding()(tempBlock, block_size);

// 	}
// 	cryptor.get_block_self_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	crypt.write((char*)tempBlock.data(), block_size);
// 	crypt.flush();
// 	//printf("100%%\r");
// }
// void NSROOT::mode::ECB::decrypt_stream(std::istream& crypt, dog_torch::serialize::Data iv, std::ostream& plain, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	uint64_t now_pos = crypt.tellg();
// 	crypt.seekg(0, std::ios::end);
// 	uint64_t file_size = crypt.tellg();
// 	crypt.seekg(now_pos);

// 	dog_torch::serialize::Data tempBlock(block_size);

// 	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
// 	{
// 		crypt.read((char*)tempBlock.data(), block_size);
// 		cryptor.get_block_self_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		plain.write((char*)tempBlock.data(), block_size);
// 		//printf("%03ull%%\r", crypt.tellg() * 100 / file_size);
// 	}
// 	crypt.read((char*)tempBlock.data(), block_size);
// 	cryptor.get_block_self_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	cryptor.get_unpadding()(tempBlock, block_size);
// 	plain.write((char*)tempBlock.data(), tempBlock.size());
// 	plain.flush();
// 	//printf("100%%\r");
// }
// void NSROOT::mode::ECB::encrypt_streamp(std::istream& plain, dog_torch::serialize::Data iv, std::ostream& crypt, NSROOT::algorithmCryptor& cryptor,
// 	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	plain.seekg(0, std::ios::end);
// 	uint64_t file_size = plain.tellg();
// 	plain.seekg(0, std::ios::beg);

// 	dog_torch::serialize::Data tempBlock(block_size);
// 	while (plain.tellg() <= file_size - block_size)
// 	{
// 		plain.read((char*)tempBlock.data(), block_size);
// 		cryptor.get_block_self_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		crypt.write((char*)tempBlock.data(), block_size);

// 		std::unique_lock<std::mutex> lock(*mutex_);
// 		while (*paused_ && !*stop_) { cond_->wait(lock); }
// 		if (*stop_) return;
// 		lock.unlock();

// 		progress->store(NSROOT::mode::update_progress(progress->load(), block_size, file_size));
// 	}
// 	plain.read((char*)tempBlock.data(), block_size);
// 	if (plain.gcount() < block_size)
// 	{
// 		for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock.pop_back(); }
// 		cryptor.get_padding()(tempBlock, block_size);
// 	}
// 	cryptor.get_block_self_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	progress->store(NSROOT::mode::update_progress(progress->load(), block_size, file_size));
// 	crypt.write((char*)tempBlock.data(), block_size);
// 	crypt.flush();
// 	progress->store(1.0);
// }
// void NSROOT::mode::ECB::decrypt_streamp(std::istream& crypt, dog_torch::serialize::Data iv, std::ostream& plain, NSROOT::algorithmCryptor& cryptor,
// 	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	uint64_t now_pos = crypt.tellg();
// 	crypt.seekg(0, std::ios::end);
// 	uint64_t file_size = crypt.tellg();
// 	crypt.seekg(now_pos);

// 	dog_torch::serialize::Data tempBlock(block_size);

// 	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
// 	{
// 		crypt.read((char*)tempBlock.data(), block_size);
// 		cryptor.get_block_self_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		plain.write((char*)tempBlock.data(), block_size);

// 		std::unique_lock<std::mutex> lock(*mutex_);
// 		while (*paused_ && !*stop_) { cond_->wait(lock); }
// 		if (*stop_) return;
// 		lock.unlock();
// 		progress->store(NSROOT::mode::update_progress(progress->load(), block_size, file_size));
// 	}
// 	crypt.read((char*)tempBlock.data(), block_size);
// 	cryptor.get_block_self_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	cryptor.get_unpadding()(tempBlock, block_size);
// 	plain.write((char*)tempBlock.data(), tempBlock.size());
// 	progress->store(update_progress(progress->load(), block_size, file_size));
// 	plain.flush();
// 	progress->store(1.0);
// }

// const NSROOT::mode::Config NSROOT::mode::CBC::CONFIG = Config("CBC", 1, true, true, false);
// dog_torch::serialize::Data NSROOT::mode::CBC::encrypt(dog_torch::serialize::Data plain, dog_torch::serialize::Data iv, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	dog_torch::serialize::Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
// 	dog_torch::serialize::Data tempBlock; tempBlock.reserve(block_size);
// 	dog_torch::serialize::Data tempKey = iv;
// 	for (uint64_t i0 = 0; i0 <= plain.size(); i0 += block_size)
// 	{
// 		tempBlock = plain.sub_by_pos(i0, i0 + block_size);
// 		if (tempBlock.size() < block_size) { cryptor.get_padding()(tempBlock, block_size); }
// 		NSROOT::algorithmutils::squareXOR_self(tempBlock, tempKey, block_size);
// 		cryptor.get_block_self_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		res += tempBlock;
// 		tempKey = tempBlock;
// 	}
// 	return res;
// }
// dog_torch::serialize::Data NSROOT::mode::CBC::decrypt(dog_torch::serialize::Data crypt, dog_torch::serialize::Data iv, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	dog_torch::serialize::Data res; res.reserve(((crypt.size() / block_size) + 1) * block_size);
// 	dog_torch::serialize::Data tempBlock(block_size);
// 	dog_torch::serialize::Data tempKey = iv;
// 	for (uint64_t i0 = 0; i0 < crypt.size(); i0 += block_size)
// 	{
// 		tempBlock = crypt.sub_by_pos(i0, i0 + block_size);
// 		cryptor.get_block_self_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		NSROOT::algorithmutils::squareXOR_self(tempBlock, tempKey, block_size);
// 		res += tempBlock;
// 		tempKey = crypt.sub_by_pos(i0, i0 + block_size);
// 	}
// 	cryptor.get_unpadding()(res, block_size);
// 	return res;
// }
// void NSROOT::mode::CBC::encrypt_stream(std::istream& plain, dog_torch::serialize::Data iv, std::ostream& crypt, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	plain.seekg(0, std::ios::end);
// 	uint64_t file_size = plain.tellg();
// 	plain.seekg(0, std::ios::beg);

// 	dog_torch::serialize::Data tempBlock(block_size);
// 	dog_torch::serialize::Data tempKey = iv;
// 	while (plain.tellg() <= file_size - block_size)
// 	{
// 		plain.read((char*)tempBlock.data(), block_size);
// 		NSROOT::algorithmutils::squareXOR_self(tempBlock, tempKey, block_size);
// 		cryptor.get_block_self_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		crypt.write((char*)tempBlock.data(), block_size);
// 		tempKey = tempBlock;
// 	}
// 	plain.read((char*)tempBlock.data(), block_size);
// 	if (plain.gcount() < block_size)
// 	{
// 		for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock.pop_back(); }
// 		cryptor.get_padding()(tempBlock, block_size);
// 	}
// 	NSROOT::algorithmutils::squareXOR_self(tempBlock, tempKey, block_size);
// 	cryptor.get_block_self_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	crypt.write((char*)tempBlock.data(), block_size);
// 	crypt.flush();
// }
// void NSROOT::mode::CBC::decrypt_stream(std::istream& crypt, dog_torch::serialize::Data iv, std::ostream& plain, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	uint64_t now_pos = crypt.tellg();
// 	crypt.seekg(0, std::ios::end);
// 	uint64_t file_size = crypt.tellg();
// 	crypt.seekg(now_pos);

// 	dog_torch::serialize::Data tempBlock(block_size);
// 	dog_torch::serialize::Data tempKey = iv;
// 	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
// 	{
// 		crypt.read((char*)tempBlock.data(), block_size);
// 		cryptor.get_block_self_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		NSROOT::algorithmutils::squareXOR_self(tempBlock, tempKey, block_size);
// 		plain.write((char*)tempBlock.data(), block_size);
// 		for (uint64_t i = 0; i < block_size; ++i) { crypt.unget(); }
// 		crypt.read((char*)tempKey.data(), block_size);
// 	}
// 	crypt.read((char*)tempBlock.data(), block_size);
// 	cryptor.get_block_self_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	NSROOT::algorithmutils::squareXOR_self(tempBlock, tempKey, block_size);
// 	cryptor.get_unpadding()(tempBlock, block_size);
// 	plain.write((char*)tempBlock.data(), tempBlock.size());
// 	plain.flush();
// }
// void NSROOT::mode::CBC::encrypt_streamp(std::istream& plain, dog_torch::serialize::Data iv, std::ostream& crypt, NSROOT::algorithmCryptor& cryptor,
// 	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	plain.seekg(0, std::ios::end);
// 	uint64_t file_size = plain.tellg();
// 	plain.seekg(0, std::ios::beg);

// 	dog_torch::serialize::Data tempBlock(block_size);
// 	dog_torch::serialize::Data tempKey = iv;
// 	while (plain.tellg() <= file_size - block_size)
// 	{
// 		plain.read((char*)tempBlock.data(), block_size);
// 		NSROOT::algorithmutils::squareXOR_self(tempBlock, tempKey, block_size);
// 		cryptor.get_block_self_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		crypt.write((char*)tempBlock.data(), block_size);
// 		std::unique_lock<std::mutex> lock(*mutex_);
// 		while (*paused_ && !*stop_) { cond_->wait(lock); }
// 		if (*stop_) return;
// 		lock.unlock();
// 		progress->store(NSROOT::mode::update_progress(progress->load(), block_size, file_size));
// 		tempKey = tempBlock;
// 	}
// 	plain.read((char*)tempBlock.data(), block_size);
// 	if (plain.gcount() < block_size)
// 	{
// 		for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock.pop_back(); }
// 		cryptor.get_padding()(tempBlock, block_size);
// 	}
// 	NSROOT::algorithmutils::squareXOR_self(tempBlock, tempKey, block_size);
// 	cryptor.get_block_self_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	crypt.write((char*)tempBlock.data(), block_size);
// 	crypt.flush();
// 	progress->store(1.0);
// }
// void NSROOT::mode::CBC::decrypt_streamp(std::istream& crypt, dog_torch::serialize::Data iv, std::ostream& plain, NSROOT::algorithmCryptor& cryptor,
// 	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	uint64_t now_pos = crypt.tellg();
// 	crypt.seekg(0, std::ios::end);
// 	uint64_t file_size = crypt.tellg();
// 	crypt.seekg(now_pos);

// 	dog_torch::serialize::Data tempBlock(block_size);
// 	dog_torch::serialize::Data tempKey = iv;
// 	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
// 	{
// 		crypt.read((char*)tempBlock.data(), block_size);
// 		cryptor.get_block_self_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		NSROOT::algorithmutils::squareXOR_self(tempBlock, tempKey, block_size);
// 		plain.write((char*)tempBlock.data(), block_size);
// 		for (uint64_t i = 0; i < block_size; ++i) { crypt.unget(); }
// 		crypt.read((char*)tempKey.data(), block_size);
// 		std::unique_lock<std::mutex> lock(*mutex_);
// 		while (*paused_ && !*stop_) { cond_->wait(lock); }
// 		if (*stop_) return;
// 		lock.unlock();
// 		progress->store(NSROOT::mode::update_progress(progress->load(), block_size, file_size));
// 	}
// 	crypt.read((char*)tempBlock.data(), block_size);
// 	cryptor.get_block_self_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	NSROOT::algorithmutils::squareXOR_self(tempBlock, tempKey, block_size);
// 	cryptor.get_unpadding()(tempBlock, block_size);
// 	plain.write((char*)tempBlock.data(), tempBlock.size());
// 	progress->store(update_progress(progress->load(), block_size, file_size));
// 	plain.flush();
// 	progress->store(1.0);
// }

// const NSROOT::mode::Config NSROOT::mode::PCBC::CONFIG = Config("PCBC", 2, true, true, false);
// dog_torch::serialize::Data NSROOT::mode::PCBC::encrypt(dog_torch::serialize::Data plain, dog_torch::serialize::Data iv, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	dog_torch::serialize::Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
// 	dog_torch::serialize::Data tempBlock0, tempBlock1 = iv, tempBlock2;
// 	for (uint64_t i0 = 0; i0 <= plain.size(); i0 += block_size)
// 	{
// 		tempBlock0 = plain.sub_by_len(i0, block_size);
// 		if (tempBlock0.size() < block_size) { cryptor.get_padding()(tempBlock0, block_size); }
// 		tempBlock2 = NSROOT::algorithmutils::squareXOR(tempBlock1, tempBlock0, tempBlock0.size());
// 		cryptor.get_block_self_encryption()(tempBlock2, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		res += tempBlock2;
// 		tempBlock1 = NSROOT::algorithmutils::squareXOR(tempBlock2, tempBlock0, tempBlock0.size());
// 	}
// 	return res;
// }
// dog_torch::serialize::Data NSROOT::mode::PCBC::decrypt(dog_torch::serialize::Data crypt, dog_torch::serialize::Data iv, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	dog_torch::serialize::Data res; res.reserve(((crypt.size() / block_size) + 1) * block_size);
// 	dog_torch::serialize::Data tempBlock0, tempBlock1 = iv, tempBlock2;
// 	for (uint64_t i0 = 0; i0 < crypt.size(); i0 += block_size)
// 	{
// 		tempBlock0 = crypt.sub_by_len(i0, block_size);
// 		tempBlock2 = cryptor.get_block_decryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		NSROOT::algorithmutils::squareXOR_self(tempBlock2, tempBlock1, tempBlock1.size());
// 		res += tempBlock2;
// 		tempBlock1 = NSROOT::algorithmutils::squareXOR(tempBlock2, tempBlock0, tempBlock0.size());
// 	}
// 	cryptor.get_unpadding()(res, block_size);
// 	return res;
// }
// void NSROOT::mode::PCBC::encrypt_stream(std::istream& plain, dog_torch::serialize::Data iv, std::ostream& crypt, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	plain.seekg(0, std::ios::end);
// 	uint64_t file_size = plain.tellg();
// 	plain.seekg(0, std::ios::beg);

// 	dog_torch::serialize::Data tempBlock0(block_size), tempBlock1 = iv, tempBlock2(block_size);
// 	while (plain.tellg() <= file_size - block_size)
// 	{
// 		plain.read((char*)tempBlock0.data(), block_size);
// 		tempBlock2 = NSROOT::algorithmutils::squareXOR(tempBlock1, tempBlock0, tempBlock0.size());
// 		cryptor.get_block_self_encryption()(tempBlock2, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		crypt.write((char*)tempBlock2.data(), block_size);
// 		tempBlock1 = NSROOT::algorithmutils::squareXOR(tempBlock2, tempBlock0, tempBlock0.size());
// 	}
// 	plain.read((char*)tempBlock0.data(), block_size);
// 	if (plain.gcount() < block_size)
// 	{
// 		for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock0.pop_back(); }
// 		cryptor.get_padding()(tempBlock0, block_size);
// 	}
// 	tempBlock2 = NSROOT::algorithmutils::squareXOR(tempBlock1, tempBlock0, tempBlock0.size());
// 	cryptor.get_block_self_encryption()(tempBlock2, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	crypt.write((char*)tempBlock2.data(), block_size);
// 	tempBlock1 = NSROOT::algorithmutils::squareXOR(tempBlock2, tempBlock0, tempBlock0.size());
// }
// void NSROOT::mode::PCBC::decrypt_stream(std::istream& crypt, dog_torch::serialize::Data iv, std::ostream& plain, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	uint64_t now_pos = crypt.tellg();
// 	crypt.seekg(0, std::ios::end);
// 	uint64_t file_size = crypt.tellg();
// 	crypt.seekg(now_pos);

// 	dog_torch::serialize::Data tempBlock0(block_size), tempBlock1 = iv, tempBlock2;
// 	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
// 	{
// 		crypt.read((char*)tempBlock0.data(), block_size);
// 		tempBlock2 = cryptor.get_block_decryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		NSROOT::algorithmutils::squareXOR_self(tempBlock2, tempBlock1, tempBlock1.size());
// 		plain.write((char*)tempBlock2.data(), block_size);
// 		tempBlock1 = NSROOT::algorithmutils::squareXOR(tempBlock2, tempBlock0, tempBlock0.size());
// 	}
// 	crypt.read((char*)tempBlock0.data(), block_size);
// 	tempBlock2 = cryptor.get_block_decryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	NSROOT::algorithmutils::squareXOR_self(tempBlock2, tempBlock1, tempBlock1.size());
// 	cryptor.get_unpadding()(tempBlock2, block_size);
// 	plain.write((char*)tempBlock2.data(), tempBlock2.size());
// 	plain.flush();
// }
// void NSROOT::mode::PCBC::encrypt_streamp(std::istream& plain, dog_torch::serialize::Data iv, std::ostream& crypt, NSROOT::algorithmCryptor& cryptor,
// 	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)

// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	plain.seekg(0, std::ios::end);
// 	uint64_t file_size = plain.tellg();
// 	plain.seekg(0, std::ios::beg);

// 	dog_torch::serialize::Data tempBlock0(block_size), tempBlock1 = iv, tempBlock2(block_size);
// 	while (plain.tellg() <= file_size - block_size)
// 	{
// 		plain.read((char*)tempBlock0.data(), block_size);
// 		tempBlock2 = NSROOT::algorithmutils::squareXOR(tempBlock1, tempBlock0, tempBlock0.size());
// 		cryptor.get_block_self_encryption()(tempBlock2, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		crypt.write((char*)tempBlock2.data(), block_size);
// 		std::unique_lock<std::mutex> lock(*mutex_);
// 		while (*paused_ && !*stop_) { cond_->wait(lock); }
// 		if (*stop_) return;
// 		lock.unlock();
// 		progress->store(NSROOT::mode::update_progress(progress->load(), block_size, file_size));
// 		tempBlock1 = NSROOT::algorithmutils::squareXOR(tempBlock2, tempBlock0, tempBlock0.size());
// 	}
// 	plain.read((char*)tempBlock0.data(), block_size);
// 	if (plain.gcount() < block_size)
// 	{
// 		for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock0.pop_back(); }
// 		cryptor.get_padding()(tempBlock0, block_size);
// 	}
// 	tempBlock2 = NSROOT::algorithmutils::squareXOR(tempBlock1, tempBlock0, tempBlock0.size());
// 	cryptor.get_block_self_encryption()(tempBlock2, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	crypt.write((char*)tempBlock2.data(), block_size);
// 	tempBlock1 = NSROOT::algorithmutils::squareXOR(tempBlock2, tempBlock0, tempBlock0.size());
// 	progress->store(1.0);
// }
// void NSROOT::mode::PCBC::decrypt_streamp(std::istream& crypt, dog_torch::serialize::Data iv, std::ostream& plain, NSROOT::algorithmCryptor& cryptor,
// 	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	uint64_t now_pos = crypt.tellg();
// 	crypt.seekg(0, std::ios::end);
// 	uint64_t file_size = crypt.tellg();
// 	crypt.seekg(now_pos);

// 	dog_torch::serialize::Data tempBlock0(block_size), tempBlock1 = iv, tempBlock2;
// 	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
// 	{
// 		crypt.read((char*)tempBlock0.data(), block_size);
// 		tempBlock2 = cryptor.get_block_decryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		NSROOT::algorithmutils::squareXOR_self(tempBlock2, tempBlock1, tempBlock1.size());
// 		plain.write((char*)tempBlock2.data(), block_size);
// 		std::unique_lock<std::mutex> lock(*mutex_);
// 		while (*paused_ && !*stop_) { cond_->wait(lock); }
// 		if (*stop_) return;
// 		lock.unlock();
// 		progress->store(NSROOT::mode::update_progress(progress->load(), block_size, file_size));
// 		progress->store(update_progress(progress->load(), block_size, file_size));
// 		tempBlock1 = NSROOT::algorithmutils::squareXOR(tempBlock2, tempBlock0, tempBlock0.size());
// 	}
// 	crypt.read((char*)tempBlock0.data(), block_size);
// 	tempBlock2 = cryptor.get_block_decryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	NSROOT::algorithmutils::squareXOR_self(tempBlock2, tempBlock1, tempBlock1.size());
// 	cryptor.get_unpadding()(tempBlock2, block_size);
// 	plain.write((char*)tempBlock2.data(), tempBlock2.size());
// 	plain.flush();
// 	progress->store(1.0);
// }

// const NSROOT::mode::Config NSROOT::mode::OFB::CONFIG = Config("OFB", 3, true, false, false);
// dog_torch::serialize::Data NSROOT::mode::OFB::encrypt(dog_torch::serialize::Data plain, dog_torch::serialize::Data iv, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	dog_torch::serialize::Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1;
// 	for (uint64_t i0 = 0; i0 <= plain.size(); i0 += block_size)
// 	{
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		tempBlock1 = plain.sub_by_pos(i0, i0 + block_size);
// 		if (tempBlock1.size() <= block_size && cryptor.get_using_padding()) { cryptor.get_padding()(tempBlock1, block_size); }
// 		res = res + NSROOT::algorithmutils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size());
// 	}
// 	return res;
// }
// dog_torch::serialize::Data NSROOT::mode::OFB::decrypt(dog_torch::serialize::Data crypt, dog_torch::serialize::Data iv, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	dog_torch::serialize::Data res; res.reserve(crypt.size());
// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1; tempBlock1.reserve(block_size);
// 	for (uint64_t i0 = 0; i0 < crypt.size(); i0 += block_size)
// 	{
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		tempBlock1 = crypt.sub_by_len(i0, block_size);
// 		res = res + NSROOT::algorithmutils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size());
// 		tempBlock1.rm_pos();
// 	}
// 	if (cryptor.get_using_padding())
// 	{
// 		cryptor.get_unpadding()(res, block_size);
// 	}
// 	return res;
// }
// void NSROOT::mode::OFB::encrypt_stream(std::istream& plain, dog_torch::serialize::Data iv, std::ostream& crypt, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	plain.seekg(0, std::ios::end);
// 	uint64_t file_size = plain.tellg();
// 	plain.seekg(0, std::ios::beg);
// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1(block_size);
// 	while (plain.tellg() <= file_size - block_size)
// 	{
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		plain.read((char*)tempBlock1.data(), block_size);
// 		crypt.write((char*)NSROOT::algorithmutils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
// 	}
// 	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	plain.read((char*)tempBlock1.data(), block_size);
// 	for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock1.pop_back(); }
// 	if (cryptor.get_using_padding() && plain.gcount() < block_size)
// 	{
// 		cryptor.get_padding()(tempBlock1, block_size);
// 	}
// 	crypt.write((char*)NSROOT::algorithmutils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size()).data(), tempBlock1.size());
// 	crypt.flush();
// }
// void NSROOT::mode::OFB::decrypt_stream(std::istream& crypt, dog_torch::serialize::Data iv, std::ostream& plain, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	uint64_t now_pos = crypt.tellg();
// 	crypt.seekg(0, std::ios::end);
// 	uint64_t file_size = crypt.tellg();
// 	crypt.seekg(now_pos);

// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1(block_size);
// 	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
// 	{
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		crypt.read((char*)tempBlock1.data(), block_size);
// 		plain.write((char*)NSROOT::algorithmutils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
// 	}
// 	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	crypt.read((char*)tempBlock1.data(), block_size);
// 	uint64_t s = crypt.gcount();
// 	for (uint64_t i = 0; i < block_size - crypt.gcount(); ++i) { tempBlock1.pop_back(); }
// 	NSROOT::algorithmutils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
// 	if (cryptor.get_using_padding())
// 	{
// 		cryptor.get_unpadding()(tempBlock1, block_size);
// 	}
// 	plain.write((char*)tempBlock1.data(), tempBlock1.size());
// 	plain.flush();
// }
// void NSROOT::mode::OFB::encrypt_streamp(std::istream& plain, dog_torch::serialize::Data iv, std::ostream& crypt, NSROOT::algorithmCryptor& cryptor,
// 	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	plain.seekg(0, std::ios::end);
// 	uint64_t file_size = plain.tellg();
// 	plain.seekg(0, std::ios::beg);
// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1(block_size);
// 	while (plain.tellg() <= file_size - block_size)
// 	{
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		plain.read((char*)tempBlock1.data(), block_size);
// 		crypt.write((char*)NSROOT::algorithmutils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
// 		std::unique_lock<std::mutex> lock(*mutex_);
// 		while (*paused_ && !*stop_) { cond_->wait(lock); }
// 		if (*stop_) return;
// 		lock.unlock();
// 		progress->store(NSROOT::mode::update_progress(progress->load(), block_size, file_size));
// 	}
// 	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	plain.read((char*)tempBlock1.data(), block_size);
// 	for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock1.pop_back(); }
// 	if (cryptor.get_using_padding() && plain.gcount() < block_size)
// 	{
// 		cryptor.get_padding()(tempBlock1, block_size);
// 	}
// 	crypt.write((char*)NSROOT::algorithmutils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size()).data(), tempBlock1.size());
// 	crypt.flush();
// 	progress->store(1.0);
// }
// void NSROOT::mode::OFB::decrypt_streamp(std::istream& crypt, dog_torch::serialize::Data iv, std::ostream& plain, NSROOT::algorithmCryptor& cryptor,
// 	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	uint64_t now_pos = crypt.tellg();
// 	crypt.seekg(0, std::ios::end);
// 	uint64_t file_size = crypt.tellg();
// 	crypt.seekg(now_pos);

// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1(block_size);
// 	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
// 	{
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		crypt.read((char*)tempBlock1.data(), block_size);
// 		plain.write((char*)NSROOT::algorithmutils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
// 		std::unique_lock<std::mutex> lock(*mutex_);
// 		while (*paused_ && !*stop_) { cond_->wait(lock); }
// 		if (*stop_) return;
// 		lock.unlock();
// 		progress->store(update_progress(progress->load(), block_size, file_size));
// 	}
// 	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	crypt.read((char*)tempBlock1.data(), block_size);
// 	uint64_t s = crypt.gcount();
// 	for (uint64_t i = 0; i < block_size - crypt.gcount(); ++i) { tempBlock1.pop_back(); }
// 	NSROOT::algorithmutils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
// 	if (cryptor.get_using_padding())
// 	{
// 		cryptor.get_unpadding()(tempBlock1, block_size);
// 	}
// 	plain.write((char*)tempBlock1.data(), tempBlock1.size());
// 	if (progress->load() < 0) { return; }progress->store(update_progress(progress->load(), block_size, file_size));
// 	plain.flush();
// 	progress->store(1.0);
// }

// const NSROOT::mode::Config NSROOT::mode::CTR::CONFIG = Config("CTR", 4, true, false, false);
// dog_torch::serialize::Data NSROOT::mode::CTR::encrypt(dog_torch::serialize::Data plain, dog_torch::serialize::Data iv, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	dog_torch::serialize::Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	uint64_t endNum = 0;
// 	for (uint64_t i0 = 0; i0 < 8; i0++)
// 	{
// 		endNum += (uint64_t)tempBlock0[i0 + 8] << (8 * (7 - i0));
// 	}
// 	dog_torch::serialize::Data tempBlock1;
// 	dog_torch::serialize::Data tempBlock2;
// 	for (uint64_t i0 = 0; i0 <= plain.size(); i0 += block_size)
// 	{
// 		tempBlock2 = tempBlock0;
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		tempBlock1 = plain.sub_by_len(i0, block_size);
// 		if (tempBlock1.size() < block_size && cryptor.get_using_padding()) { cryptor.get_padding()(tempBlock1, block_size); }
// 		res = res + NSROOT::algorithmutils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size());
// 		tempBlock1.rm_pos();
// 		endNum++;
// 		for (int i1 = 0; i1 < 8; i1++)
// 		{
// 			tempBlock2[i1 + 8] = (uint8_t)(endNum >> (8 * (7 - i1)));
// 		}
// 		tempBlock0 = tempBlock2;
// 	}
// 	return res;
// }
// dog_torch::serialize::Data NSROOT::mode::CTR::decrypt(dog_torch::serialize::Data crypt, dog_torch::serialize::Data iv, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	dog_torch::serialize::Data res; res.reserve(((crypt.size() / block_size) + 1) * block_size);
// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	uint64_t endNum = 0;
// 	for (uint64_t i0 = 0; i0 < 8; i0++)
// 	{
// 		endNum += (uint64_t)tempBlock0[i0 + 8] << (8 * (7 - i0));
// 	}
// 	dog_torch::serialize::Data tempBlock1;
// 	dog_torch::serialize::Data tempBlock2;
// 	for (uint64_t i0 = 0; i0 < crypt.size(); i0 += block_size)
// 	{
// 		tempBlock2 = tempBlock0;
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		tempBlock1 = crypt.sub_by_pos(i0, i0 + block_size);
// 		res = res + NSROOT::algorithmutils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size());
// 		endNum++;
// 		for (int i1 = 0; i1 < 8; i1++)
// 		{
// 			tempBlock2[i1 + 8] = (uint8_t)(endNum >> (8 * (7 - i1)));
// 		}
// 		tempBlock0 = tempBlock2;
// 	}
// 	if (cryptor.get_using_padding()) { cryptor.get_unpadding()(res, block_size); }
// 	return res;
// }
// void NSROOT::mode::CTR::encrypt_stream(std::istream& plain, dog_torch::serialize::Data iv, std::ostream& crypt, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	plain.seekg(0, std::ios::end);
// 	uint64_t file_size = plain.tellg();
// 	plain.seekg(0, std::ios::beg);

// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	uint64_t endNum = 0;
// 	for (uint64_t i0 = 0; i0 < 8; i0++)
// 	{
// 		endNum += (uint64_t)tempBlock0[i0 + 8] << (8 * (7 - i0));
// 	}
// 	dog_torch::serialize::Data tempBlock1(block_size);
// 	dog_torch::serialize::Data tempBlock2(block_size);
// 	while (plain.tellg() <= file_size - block_size)
// 	{
// 		tempBlock2 = tempBlock0;
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		plain.read((char*)tempBlock1.data(), block_size);
// 		crypt.write((char*)NSROOT::algorithmutils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
// 		endNum++;
// 		for (int i1 = 0; i1 < 8; i1++)
// 		{
// 			tempBlock2[i1 + 8] = (uint8_t)(endNum >> (8 * (7 - i1)));
// 		}
// 		tempBlock0 = tempBlock2;
// 	}
// 	tempBlock2 = tempBlock0;
// 	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	plain.read((char*)tempBlock1.data(), block_size);
// 	for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock1.pop_back(); }
// 	if (cryptor.get_using_padding() && plain.gcount() < block_size)
// 	{
// 		cryptor.get_padding()(tempBlock1, block_size);
// 	}
// 	crypt.write((char*)NSROOT::algorithmutils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size()).data(), tempBlock1.size());
// 	crypt.flush();
// }
// void NSROOT::mode::CTR::decrypt_stream(std::istream& crypt, dog_torch::serialize::Data iv, std::ostream& plain, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	uint64_t now_pos = crypt.tellg();
// 	crypt.seekg(0, std::ios::end);
// 	uint64_t file_size = crypt.tellg();
// 	crypt.seekg(now_pos);

// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	uint64_t endNum = 0;
// 	for (uint64_t i0 = 0; i0 < 8; i0++)
// 	{
// 		endNum += (uint64_t)tempBlock0[i0 + 8] << (8 * (7 - i0));
// 	}
// 	dog_torch::serialize::Data tempBlock1(block_size);
// 	dog_torch::serialize::Data tempBlock2(block_size);
// 	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
// 	{
// 		tempBlock2 = tempBlock0;
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		crypt.read((char*)tempBlock1.data(), block_size);
// 		plain.write((char*)NSROOT::algorithmutils::squareXOR(tempBlock1, tempBlock0, block_size).data(), block_size);
// 		endNum++;
// 		for (int i1 = 0; i1 < 8; i1++)
// 		{
// 			tempBlock2[i1 + 8] = (uint8_t)(endNum >> (8 * (7 - i1)));
// 		}
// 		tempBlock0 = tempBlock2;
// 	}
// 	tempBlock2 = tempBlock0;
// 	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	crypt.read((char*)tempBlock1.data(), block_size);
// 	for (uint64_t i = 0; i < block_size - crypt.gcount(); ++i) { tempBlock1.pop_back(); }
// 	NSROOT::algorithmutils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
// 	if (cryptor.get_using_padding())
// 	{
// 		cryptor.get_unpadding()(tempBlock1, block_size);
// 	}
// 	plain.write((char*)tempBlock1.data(), tempBlock1.size());
// 	plain.flush();
// }
// void NSROOT::mode::CTR::encrypt_streamp(std::istream& plain, dog_torch::serialize::Data iv, std::ostream& crypt, NSROOT::algorithmCryptor& cryptor,
// 	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	plain.seekg(0, std::ios::end);
// 	uint64_t file_size = plain.tellg();
// 	plain.seekg(0, std::ios::beg);

// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	uint64_t endNum = 0;
// 	for (uint64_t i0 = 0; i0 < 8; i0++)
// 	{
// 		endNum += (uint64_t)tempBlock0[i0 + 8] << (8 * (7 - i0));
// 	}
// 	dog_torch::serialize::Data tempBlock1(block_size);
// 	dog_torch::serialize::Data tempBlock2(block_size);
// 	while (plain.tellg() <= file_size - block_size)
// 	{
// 		tempBlock2 = tempBlock0;
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		plain.read((char*)tempBlock1.data(), block_size);
// 		crypt.write((char*)NSROOT::algorithmutils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
// 		std::unique_lock<std::mutex> lock(*mutex_);
// 		while (*paused_ && !*stop_) { cond_->wait(lock); }
// 		if (*stop_) return;
// 		lock.unlock();
// 		progress->store(NSROOT::mode::update_progress(progress->load(), block_size, file_size));
// 		endNum++;
// 		for (int i1 = 0; i1 < 8; i1++)
// 		{
// 			tempBlock2[i1 + 8] = (uint8_t)(endNum >> (8 * (7 - i1)));
// 		}
// 		tempBlock0 = tempBlock2;
// 	}
// 	tempBlock2 = tempBlock0;
// 	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	plain.read((char*)tempBlock1.data(), block_size);
// 	for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock1.pop_back(); }
// 	if (cryptor.get_using_padding() && plain.gcount() < block_size)
// 	{
// 		cryptor.get_padding()(tempBlock1, block_size);
// 	}
// 	crypt.write((char*)NSROOT::algorithmutils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size()).data(), tempBlock1.size());
// 	crypt.flush();
// 	progress->store(1.0);
// }
// void NSROOT::mode::CTR::decrypt_streamp(std::istream& crypt, dog_torch::serialize::Data iv, std::ostream& plain, NSROOT::algorithmCryptor& cryptor,
// 	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	uint64_t now_pos = crypt.tellg();
// 	crypt.seekg(0, std::ios::end);
// 	uint64_t file_size = crypt.tellg();
// 	crypt.seekg(now_pos);

// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	uint64_t endNum = 0;
// 	for (uint64_t i0 = 0; i0 < 8; i0++)
// 	{
// 		endNum += (uint64_t)tempBlock0[i0 + 8] << (8 * (7 - i0));
// 	}
// 	dog_torch::serialize::Data tempBlock1(block_size);
// 	dog_torch::serialize::Data tempBlock2(block_size);
// 	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
// 	{
// 		tempBlock2 = tempBlock0;
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		crypt.read((char*)tempBlock1.data(), block_size);
// 		plain.write((char*)NSROOT::algorithmutils::squareXOR(tempBlock1, tempBlock0, block_size).data(), block_size);
// 		std::unique_lock<std::mutex> lock(*mutex_);
// 		while (*paused_ && !*stop_) { cond_->wait(lock); }
// 		if (*stop_) return;
// 		lock.unlock();
// 		progress->store(update_progress(progress->load(), block_size, file_size));
// 		endNum++;
// 		for (int i1 = 0; i1 < 8; i1++)
// 		{
// 			tempBlock2[i1 + 8] = (uint8_t)(endNum >> (8 * (7 - i1)));
// 		}
// 		tempBlock0 = tempBlock2;
// 	}
// 	tempBlock2 = tempBlock0;
// 	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	crypt.read((char*)tempBlock1.data(), block_size);
// 	for (uint64_t i = 0; i < block_size - crypt.gcount(); ++i) { tempBlock1.pop_back(); }
// 	NSROOT::algorithmutils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
// 	if (cryptor.get_using_padding())
// 	{
// 		cryptor.get_unpadding()(tempBlock1, block_size);
// 	}
// 	plain.write((char*)tempBlock1.data(), tempBlock1.size());
// 	if (progress->load() < 0) { return; }progress->store(update_progress(progress->load(), block_size, file_size));
// 	plain.flush();
// 	progress->store(1.0);
// }

// const NSROOT::mode::Config NSROOT::mode::CFBB::CONFIG = Config("CFBB", 5, true, false, true);
// dog_torch::serialize::Data NSROOT::mode::CFBB::encrypt(dog_torch::serialize::Data plain, dog_torch::serialize::Data iv, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	//反馈字节数
// 	uint64_t nbyte = cryptor.get_reback_size();

// 	dog_torch::serialize::Data res; res.reserve(((plain.size() / nbyte) + 1) * nbyte);
// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1(nbyte);
// 	dog_torch::serialize::Data tempBlock2(nbyte);
// 	uint64_t i = 0;
// 	for (i = 0; i < plain.size(); i += nbyte)
// 	{
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		tempBlock1 = plain.sub_by_len(i, nbyte);
// 		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
// 		NSROOT::algorithmutils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
// 		res += tempBlock1;
// 		tempBlock0 = tempBlock0.sub_by_len(nbyte, block_size - nbyte) + tempBlock1;
// 	}
// 	return res;
// }
// dog_torch::serialize::Data NSROOT::mode::CFBB::decrypt(dog_torch::serialize::Data crypt, dog_torch::serialize::Data iv, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	uint64_t nbyte = cryptor.get_reback_size();

// 	dog_torch::serialize::Data res; res.reserve(((crypt.size() / nbyte) + 1) * nbyte);
// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1(nbyte);
// 	dog_torch::serialize::Data tempBlock2(nbyte);
// 	uint64_t i = 0;
// 	for (i = 0; i < crypt.size(); i += nbyte)
// 	{
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		tempBlock1 = crypt.sub_by_len(i, nbyte);
// 		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
// 		res += NSROOT::algorithmutils::squareXOR(tempBlock1, tempBlock2, tempBlock1.size());
// 		tempBlock0 = tempBlock0.sub_by_len(nbyte, block_size - nbyte) + tempBlock1;
// 	}
// 	return res;
// }
// void NSROOT::mode::CFBB::encrypt_stream(std::istream& plain, dog_torch::serialize::Data iv, std::ostream& crypt, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	plain.seekg(0, std::ios::end);
// 	uint64_t file_size = plain.tellg();
// 	plain.seekg(0, std::ios::beg);
// 	//反馈字节数
// 	uint64_t nbyte = cryptor.get_reback_size();

// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1(nbyte);
// 	dog_torch::serialize::Data tempBlock2(nbyte);
// 	while (plain.tellg() <= file_size - nbyte)
// 	{
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		plain.read((char*)tempBlock1.data(), nbyte);
// 		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
// 		NSROOT::algorithmutils::squareXOR_self(tempBlock1, tempBlock2, nbyte);
// 		crypt.write((char*)tempBlock1.data(), nbyte);
// 		tempBlock0 = tempBlock0.sub_by_len(nbyte, block_size - nbyte) + tempBlock1;
// 	}
// 	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	plain.read((char*)tempBlock1.data(), nbyte);
// 	tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
// 	for (int i = 0; i < nbyte - plain.gcount(); ++i) { tempBlock1.pop_back(); }
// 	if (cryptor.get_using_padding() && plain.gcount() < nbyte) { cryptor.get_padding()(tempBlock1, nbyte); }
// 	NSROOT::algorithmutils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
// 	crypt.write((char*)tempBlock1.data(), nbyte);
// 	crypt.flush();
// }
// void NSROOT::mode::CFBB::decrypt_stream(std::istream& crypt, dog_torch::serialize::Data iv, std::ostream& plain, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	uint64_t now_pos = crypt.tellg();
// 	crypt.seekg(0, std::ios::end);
// 	uint64_t file_size = crypt.tellg();
// 	crypt.seekg(now_pos);

// 	//反馈字节数
// 	uint64_t nbyte = cryptor.get_reback_size();

// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1(nbyte);
// 	dog_torch::serialize::Data tempBlock2(nbyte);
// 	while (crypt.tellg() < file_size - nbyte)
// 	{
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		crypt.read((char*)tempBlock1.data(), nbyte);
// 		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
// 		NSROOT::algorithmutils::squareXOR_self(tempBlock2, tempBlock1, nbyte);
// 		plain.write((char*)tempBlock2.data(), nbyte);
// 		tempBlock0 = tempBlock0.sub_by_len(nbyte, block_size - nbyte) + tempBlock1;
// 	}
// 	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	crypt.read((char*)tempBlock1.data(), nbyte);
// 	tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
// 	NSROOT::algorithmutils::squareXOR_self(tempBlock2, tempBlock1, nbyte);
// 	plain.write((char*)tempBlock2.data(), nbyte);
// 	plain.flush();
// }
// void NSROOT::mode::CFBB::encrypt_streamp(std::istream& plain, dog_torch::serialize::Data iv, std::ostream& crypt, NSROOT::algorithmCryptor& cryptor,
// 	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	plain.seekg(0, std::ios::end);
// 	uint64_t file_size = plain.tellg();
// 	plain.seekg(0, std::ios::beg);
// 	//反馈字节数
// 	uint64_t nbyte = cryptor.get_reback_size();

// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1(nbyte);
// 	dog_torch::serialize::Data tempBlock2(nbyte);
// 	while (plain.tellg() <= file_size - nbyte)
// 	{
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		plain.read((char*)tempBlock1.data(), nbyte);
// 		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
// 		NSROOT::algorithmutils::squareXOR_self(tempBlock1, tempBlock2, nbyte);
// 		crypt.write((char*)tempBlock1.data(), nbyte);
// 		std::unique_lock<std::mutex> lock(*mutex_);
// 		while (*paused_ && !*stop_) { cond_->wait(lock); }
// 		if (*stop_) return;
// 		lock.unlock();
// 		progress->store(NSROOT::mode::update_progress(progress->load(), nbyte, file_size));
// 		tempBlock0 = tempBlock0.sub_by_len(nbyte, block_size - nbyte) + tempBlock1;
// 	}
// 	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	plain.read((char*)tempBlock1.data(), nbyte);
// 	tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
// 	for (int i = 0; i < nbyte - plain.gcount(); ++i) { tempBlock1.pop_back(); }
// 	if (cryptor.get_using_padding() && plain.gcount() < nbyte) { cryptor.get_padding()(tempBlock1, nbyte); }
// 	NSROOT::algorithmutils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
// 	crypt.write((char*)tempBlock1.data(), nbyte);
// 	if (progress->load() < 0) { return; }progress->store(update_progress(progress->load(), nbyte, file_size));
// 	crypt.flush();
// 	progress->store(1.0);
// }
// void NSROOT::mode::CFBB::decrypt_streamp(std::istream& crypt, dog_torch::serialize::Data iv, std::ostream& plain, NSROOT::algorithmCryptor& cryptor,
// 	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	uint64_t now_pos = crypt.tellg();
// 	crypt.seekg(0, std::ios::end);
// 	uint64_t file_size = crypt.tellg();
// 	crypt.seekg(now_pos);

// 	//反馈字节数
// 	uint64_t nbyte = cryptor.get_reback_size();

// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1(nbyte);
// 	dog_torch::serialize::Data tempBlock2(nbyte);
// 	while (crypt.tellg() < file_size - nbyte)
// 	{
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		crypt.read((char*)tempBlock1.data(), nbyte);
// 		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
// 		NSROOT::algorithmutils::squareXOR_self(tempBlock1, tempBlock2, nbyte);
// 		plain.write((char*)tempBlock1.data(), nbyte);
// 		std::unique_lock<std::mutex> lock(*mutex_);
// 		while (*paused_ && !*stop_) { cond_->wait(lock); }
// 		if (*stop_) return;
// 		lock.unlock();
// 		progress->store(update_progress(progress->load(), nbyte, file_size));
// 		tempBlock0 = tempBlock0.sub_by_len(nbyte, block_size - nbyte) + tempBlock1;
// 	}
// 	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	crypt.read((char*)tempBlock1.data(), nbyte);
// 	tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
// 	NSROOT::algorithmutils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
// 	if (cryptor.get_using_padding()) { cryptor.get_unpadding()(tempBlock1, nbyte); }
// 	plain.write((char*)tempBlock1.data(), nbyte);
// 	if (progress->load() < 0) { return; }progress->store(update_progress(progress->load(), nbyte, file_size));
// 	plain.flush();
// 	progress->store(1.0);
// }

// dog_torch::serialize::Data NSROOT::mode::CFBB::encrypt_CFB8(dog_torch::serialize::Data plain, dog_torch::serialize::Data iv, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	dog_torch::serialize::Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1; tempBlock1.reserve(block_size);
// 	for (uint64_t i0 = 0; i0 < plain.size(); i0++)
// 	{
// 		tempBlock1 = tempBlock0;
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		uint8_t b = plain[i0] ^ tempBlock0[0];
// 		res.push_back(b);
// 		tempBlock1.push_back(b);
// 	}
// 	return res;
// }
// dog_torch::serialize::Data NSROOT::mode::CFBB::decrypt_CFB8(dog_torch::serialize::Data crypt, dog_torch::serialize::Data iv, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	dog_torch::serialize::Data res; res.reserve(((crypt.size() / block_size) + 1) * block_size);
// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1; tempBlock1.reserve(block_size);
// 	for (uint64_t i0 = 0; i0 < crypt.size(); i0++)
// 	{
// 		tempBlock1 = tempBlock0;
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		uint8_t b = crypt[i0] ^ tempBlock0[0];
// 		res.push_back(b);
// 		tempBlock0.push_back(crypt[i0]);
// 	}
// 	return res;
// }
// void NSROOT::mode::CFBB::encrypt_CFB8_stream(std::istream& plain, dog_torch::serialize::Data iv, std::ostream& crypt, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	plain.seekg(0, std::ios::end);
// 	uint64_t file_size = plain.tellg();
// 	plain.seekg(0, std::ios::beg);

// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1(block_size);
// 	dog_torch::serialize::Data middleResult; middleResult.reserve(block_size);
// 	while (plain.tellg() < file_size)
// 	{
// 		tempBlock1 = tempBlock0;
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		uint8_t b = plain.get() ^ tempBlock0[0];
// 		middleResult.push_back(b);
// 		if (middleResult.size() == block_size)
// 		{
// 			crypt.write((char*)middleResult.data(), block_size);
// 			middleResult.rm_pos();
// 		}
// 		tempBlock1.push_back(b);
// 	}
// 	crypt.write((char*)middleResult.data(), middleResult.size());
// 	crypt.flush();
// }
// void NSROOT::mode::CFBB::decrypt_CFB8_stream(std::istream& crypt, dog_torch::serialize::Data iv, std::ostream& plain, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	uint64_t now_pos = crypt.tellg();
// 	crypt.seekg(0, std::ios::end);
// 	uint64_t file_size = crypt.tellg();
// 	crypt.seekg(now_pos);

// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1; tempBlock1.reserve(block_size);
// 	dog_torch::serialize::Data middleResult; middleResult.reserve(block_size);
// 	while (crypt.tellg() < file_size)
// 	{
// 		tempBlock1 = tempBlock0;
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		uint8_t b = crypt.peek() ^ tempBlock0[0];
// 		middleResult.push_back(b);
// 		if (middleResult.size() == block_size)
// 		{
// 			plain.write((char*)middleResult.data(), block_size);
// 			//DogData::print::block(middleResult);
// 			middleResult.rm_pos();
// 		}
// 		tempBlock0.push_back(crypt.get());
// 	}
// 	plain.write((char*)middleResult.data(), middleResult.size());
// 	//DogData::print::block(middleResult);
// 	plain.flush();
// }
// void NSROOT::mode::CFBB::encrypt_CFB8_streamp(std::istream& plain, dog_torch::serialize::Data iv, std::ostream& crypt, NSROOT::algorithmCryptor& cryptor,
// 	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	plain.seekg(0, std::ios::end);
// 	uint64_t file_size = plain.tellg();
// 	plain.seekg(0, std::ios::beg);

// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1(block_size);
// 	dog_torch::serialize::Data middleResult; middleResult.reserve(block_size);
// 	while (plain.tellg() < file_size)
// 	{
// 		tempBlock1 = tempBlock0;
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		uint8_t b = plain.get() ^ tempBlock0[0];
// 		middleResult.push_back(b);
// 		if (middleResult.size() == block_size)
// 		{
// 			crypt.write((char*)middleResult.data(), block_size);
// 			std::unique_lock<std::mutex> lock(*mutex_);
// 			while (*paused_ && !*stop_) { cond_->wait(lock); }
// 			if (*stop_) return;
// 			lock.unlock();
// 			middleResult.rm_pos();
// 		}
// 		tempBlock1.push_back(b);
// 		progress->store(NSROOT::mode::update_progress(progress->load(), 1, file_size));
// 	}
// 	crypt.write((char*)middleResult.data(), middleResult.size());
// 	if (progress->load() < 0) { return; }progress->store(update_progress(progress->load(), middleResult.size(), file_size));
// 	crypt.flush();
// 	progress->store(1.0);
// }
// void NSROOT::mode::CFBB::decrypt_CFB8_streamp(std::istream& crypt, dog_torch::serialize::Data iv, std::ostream& plain, NSROOT::algorithmCryptor& cryptor,
// 	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	uint64_t now_pos = crypt.tellg();
// 	crypt.seekg(0, std::ios::end);
// 	uint64_t file_size = crypt.tellg();
// 	crypt.seekg(now_pos);

// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1; tempBlock1.reserve(block_size);
// 	dog_torch::serialize::Data middleResult; middleResult.reserve(block_size);
// 	while (crypt.tellg() < file_size)
// 	{
// 		tempBlock1 = tempBlock0;
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		uint8_t b = crypt.peek() ^ tempBlock0[0];
// 		middleResult.push_back(b);
// 		if (middleResult.size() == block_size)
// 		{
// 			plain.write((char*)middleResult.data(), block_size);
// 			std::unique_lock<std::mutex> lock(*mutex_);
// 			while (*paused_ && !*stop_) { cond_->wait(lock); }
// 			if (*stop_) return;
// 			lock.unlock();
// 			progress->store(update_progress(progress->load(), block_size, file_size));
// 			middleResult.rm_pos();
// 		}
// 		tempBlock0.push_back(crypt.get());
// 	}
// 	plain.write((char*)middleResult.data(), middleResult.size());
// 	if (progress->load() < 0) { return; }progress->store(update_progress(progress->load(), middleResult.size(), file_size));
// 	plain.flush();
// 	progress->store(1.0);
// }

// const NSROOT::mode::Config NSROOT::mode::CFBb::CONFIG = Config("CFBb", 6, true, false, true);
// dog_torch::serialize::Data NSROOT::mode::CFBb::encrypt(dog_torch::serialize::Data plain, dog_torch::serialize::Data iv, NSROOT::algorithmCryptor& cryptor)
// {
// 	dog_torch::serialize::Data crypt; crypt.reserve(plain.size());
// 	uint64_t shift = cryptor.get_reback_size(), read_byte_pos = 0;
// 	int8_t read_bit_pos = 0;
// 	dog_torch::serialize::Data tempBlock0 = iv, tempBlock1;
// 	auto pick_shift = [&plain, &shift, &read_byte_pos, &read_bit_pos]()->dog_torch::serialize::Data
// 		{
// 			dog_torch::serialize::Data res; res.reserve((shift / 8) + 1);
// 			uint8_t fill_byte = 0x00;
// 			uint8_t temp_byte = 0x00;
// 			for (uint64_t i = 0; i < shift; i++)
// 			{
// 				temp_byte = plain[read_byte_pos];
// 				fill_byte |= ((temp_byte >> (7 - read_bit_pos)) & 0x01) << (7 - (i % 8));
// 				read_bit_pos++;
// 				if (i % 8 == 7)
// 				{
// 					res.push_back(fill_byte);
// 					fill_byte = 0x00;
// 				}
// 				if (read_bit_pos == 8)
// 				{
// 					read_bit_pos = 0;
// 					read_byte_pos++;
// 				}
// 				if (read_byte_pos == plain.size())
// 				{
// 					break;
// 				}
// 			}
// 			if (shift % 8 != 0)
// 			{
// 				res.push_back(fill_byte);
// 			}
// 			return res;
// 		};
// 	int8_t waiting_byte = 0x00; int8_t write_bit_pos = 0;
// 	auto add_block = [&plain, &crypt, &shift, &waiting_byte, &write_bit_pos](dog_torch::serialize::Data& tempBlock)->void
// 		{
// 			uint8_t temp_byte = 0x00;
// 			for (uint64_t i = 0; i < shift; i++)
// 			{
// 				if (i / 8 == tempBlock.size()) { break; }
// 				temp_byte = tempBlock[i / 8];
// 				waiting_byte |= ((temp_byte >> (7 - i % 8)) & 0x01) << (7 - (write_bit_pos % 8));
// 				write_bit_pos++;
// 				if (write_bit_pos == 8)
// 				{
// 					crypt.push_back(waiting_byte);
// 					if (crypt.size() == plain.size()) { break; }
// 					waiting_byte = 0x00;
// 					write_bit_pos = 0;
// 				}
// 			}
// 		};
// 	for (; read_byte_pos < plain.size();)
// 	{
// 		cryptor.get_block_self_encryption()(tempBlock0, cryptor.get_block_size(), cryptor.get_available_key(), cryptor.get_key_size());
// 		tempBlock1 = pick_shift();
// 		while (tempBlock1.size() < cryptor.get_block_size()) { tempBlock1.push_back(0x00); }
// 		NSROOT::algorithmutils::squareXOR_self(tempBlock1, tempBlock0, cryptor.get_block_size());
// 		add_block(tempBlock1);
// 		tempBlock0 = tempBlock0.bit_left_move_norise(shift) | tempBlock1.bit_right_move_norise(cryptor.get_block_size() * 8 - shift);
// 	}
// 	return crypt;
// }
// dog_torch::serialize::Data NSROOT::mode::CFBb::decrypt(dog_torch::serialize::Data crypt, dog_torch::serialize::Data iv, NSROOT::algorithmCryptor& cryptor)
// {
// 	dog_torch::serialize::Data plain; crypt.reserve(crypt.size());
// 	uint64_t shift = cryptor.get_reback_size(), read_byte_pos = 0;
// 	int8_t read_bit_pos = 0;
// 	dog_torch::serialize::Data tempBlock0 = iv, tempBlock1, tempBlock2;
// 	auto pick_shift = [&crypt, &shift, &read_byte_pos, &read_bit_pos]()->dog_torch::serialize::Data
// 		{
// 			dog_torch::serialize::Data res; res.reserve((shift / 8) + 1);
// 			uint8_t fill_byte = 0x00;
// 			uint8_t temp_byte = 0x00;
// 			for (uint64_t i = 0; i < shift; i++)
// 			{
// 				temp_byte = crypt[read_byte_pos];
// 				fill_byte |= ((temp_byte >> (7 - read_bit_pos)) & 0x01) << (7 - (i % 8));
// 				read_bit_pos++;
// 				if (i % 8 == 7)
// 				{
// 					res.push_back(fill_byte);
// 					fill_byte = 0x00;
// 				}
// 				if (read_bit_pos == 8)
// 				{
// 					read_bit_pos = 0;
// 					read_byte_pos++;
// 				}
// 				if (read_byte_pos == crypt.size())
// 				{
// 					break;
// 				}
// 			}
// 			if (shift % 8 != 0)
// 			{
// 				res.push_back(fill_byte);
// 			}
// 			return res;
// 		};
// 	int8_t waiting_byte = 0x00; int8_t write_bit_pos = 0;
// 	auto add_block = [&crypt, &plain, &shift, &waiting_byte, &write_bit_pos](dog_torch::serialize::Data& tempBlock)->void
// 		{
// 			uint8_t temp_byte = 0x00;
// 			for (uint64_t i = 0; i < shift; i++)
// 			{
// 				if (i / 8 == tempBlock.size()) { break; }
// 				temp_byte = tempBlock[i / 8];
// 				waiting_byte |= ((temp_byte >> (7 - i % 8)) & 0x01) << (7 - (write_bit_pos % 8));
// 				write_bit_pos++;
// 				if (write_bit_pos == 8)
// 				{
// 					plain.push_back(waiting_byte);
// 					if (plain.size() == crypt.size()) { break; }
// 					waiting_byte = 0x00;
// 					write_bit_pos = 0;
// 				}
// 			}
// 		};
// 	for (; read_byte_pos < crypt.size();)
// 	{
// 		cryptor.get_block_self_encryption()(tempBlock0, cryptor.get_block_size(), cryptor.get_available_key(), cryptor.get_key_size());
// 		tempBlock1 = pick_shift();
// 		while (tempBlock1.size() < cryptor.get_block_size()) { tempBlock1.push_back(0x00); }
// 		tempBlock2 = NSROOT::algorithmutils::squareXOR(tempBlock1, tempBlock0, cryptor.get_block_size());
// 		add_block(tempBlock2);
// 		tempBlock0 = tempBlock0.bit_left_move_norise(shift) | tempBlock1.bit_right_move_norise(cryptor.get_block_size() * 8 - shift);
// 	}
// 	return plain;
// }
// void NSROOT::mode::CFBb::encrypt_stream(std::istream& plain, dog_torch::serialize::Data iv, std::ostream& crypt, NSROOT::algorithmCryptor& cryptor)
// {
// 	//throw CryptionException(DOG_EXCEPTION_MSG_OPINION("not using"));
// 	uint64_t shift = cryptor.get_reback_size();
// 	int8_t read_bit_pos = 0;
// 	dog_torch::serialize::Data tempBlock0 = iv, tempBlock1;
// 	auto pick_shift = [&plain, &shift, &read_bit_pos]()->dog_torch::serialize::Data
// 		{
// 			dog_torch::serialize::Data res; res.reserve((shift / 8) + 1);
// 			uint8_t fill_byte = 0x00;
// 			uint8_t temp_byte = 0x00;
// 			for (uint64_t i = 0; i < shift; i++)
// 			{
// 				temp_byte = plain.peek();
// 				fill_byte |= ((temp_byte >> (7 - read_bit_pos)) & 0x01) << (7 - (i % 8));
// 				read_bit_pos++;
// 				if (i % 8 == 7)
// 				{
// 					res.push_back(fill_byte);
// 					fill_byte = 0x00;
// 				}
// 				if (read_bit_pos == 8)
// 				{
// 					read_bit_pos = 0;
// 					plain.get();
// 				}
// 				if (plain.eof())
// 				{
// 					break;
// 				}
// 			}
// 			if (shift % 8 != 0)
// 			{
// 				res.push_back(fill_byte);
// 			}
// 			return res;
// 		};
// 	int8_t waiting_byte = 0x00; int8_t write_bit_pos = 0;
// 	auto add_block = [&crypt, &shift, &waiting_byte, &write_bit_pos](dog_torch::serialize::Data& tempBlock)->void
// 		{
// 			uint8_t temp_byte = 0x00;
// 			for (uint64_t i = 0; i < shift; i++)
// 			{
// 				if (i / 8 == tempBlock.size()) { break; }
// 				temp_byte = tempBlock[i / 8];
// 				waiting_byte |= ((temp_byte >> (7 - i % 8)) & 0x01) << (7 - (write_bit_pos % 8));
// 				write_bit_pos++;
// 				if (write_bit_pos == 8)
// 				{
// 					crypt.put(waiting_byte);
// 					waiting_byte = 0x00;
// 					write_bit_pos = 0;
// 				}
// 			}
// 		};
// 	while (plain.eof())
// 	{
// 		cryptor.get_block_self_encryption()(tempBlock0, cryptor.get_block_size(), cryptor.get_available_key(), cryptor.get_key_size());
// 		tempBlock1 = pick_shift();
// 		while (tempBlock1.size() < cryptor.get_block_size()) { tempBlock1.push_back(0x00); }
// 		NSROOT::algorithmutils::squareXOR_self(tempBlock1, tempBlock0, cryptor.get_block_size());
// 		add_block(tempBlock1);
// 		tempBlock0 = tempBlock0.bit_left_move_norise(shift) | tempBlock1.bit_right_move_norise(cryptor.get_block_size() * 8 - shift);
// 	}
// 	crypt.flush();
// }
// void NSROOT::mode::CFBb::decrypt_stream(std::istream& crypt, dog_torch::serialize::Data iv, std::ostream& plain, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint64_t shift = cryptor.get_reback_size();
// 	int8_t read_bit_pos = 0;
// 	dog_torch::serialize::Data tempBlock0 = iv, tempBlock1, tempBlock2;
// 	auto pick_shift = [&crypt, &shift, &read_bit_pos]()->dog_torch::serialize::Data
// 		{
// 			dog_torch::serialize::Data res; res.reserve((shift / 8) + 1);
// 			uint8_t fill_byte = 0x00;
// 			uint8_t temp_byte = 0x00;
// 			for (uint64_t i = 0; i < shift; i++)
// 			{
// 				temp_byte = crypt.peek();
// 				fill_byte |= ((temp_byte >> (7 - read_bit_pos)) & 0x01) << (7 - (i % 8));
// 				read_bit_pos++;
// 				if (i % 8 == 7)
// 				{
// 					res.push_back(fill_byte);
// 					fill_byte = 0x00;
// 				}
// 				if (read_bit_pos == 8)
// 				{
// 					read_bit_pos = 0;
// 					crypt.get();
// 				}
// 				if (crypt.eof())
// 				{
// 					break;
// 				}
// 			}
// 			if (shift % 8 != 0)
// 			{
// 				res.push_back(fill_byte);
// 			}
// 			return res;
// 		};
// 	int8_t waiting_byte = 0x00; int8_t write_bit_pos = 0;
// 	auto add_block = [&plain, &shift, &waiting_byte, &write_bit_pos](dog_torch::serialize::Data& tempBlock)->void
// 		{
// 			uint8_t temp_byte = 0x00;
// 			for (uint64_t i = 0; i < shift; i++)
// 			{
// 				if (i / 8 == tempBlock.size()) { break; }
// 				temp_byte = tempBlock[i / 8];
// 				waiting_byte |= ((temp_byte >> (7 - i % 8)) & 0x01) << (7 - (write_bit_pos % 8));
// 				write_bit_pos++;
// 				if (write_bit_pos == 8)
// 				{
// 					plain.put(waiting_byte);
// 					waiting_byte = 0x00;
// 					write_bit_pos = 0;
// 				}
// 			}
// 		};
// 	while (plain.eof())
// 	{
// 		cryptor.get_block_self_encryption()(tempBlock0, cryptor.get_block_size(), cryptor.get_available_key(), cryptor.get_key_size());
// 		tempBlock1 = pick_shift();
// 		while (tempBlock1.size() < cryptor.get_block_size()) { tempBlock1.push_back(0x00); }
// 		tempBlock2 = NSROOT::algorithmutils::squareXOR(tempBlock1, tempBlock0, cryptor.get_block_size());
// 		add_block(tempBlock2);
// 		tempBlock0 = tempBlock0.bit_left_move_norise(shift) | tempBlock1.bit_right_move_norise(cryptor.get_block_size() * 8 - shift);
// 	}
// 	plain.flush();
// }
// void NSROOT::mode::CFBb::encrypt_streamp(std::istream& plain, dog_torch::serialize::Data iv, std::ostream& crypt, NSROOT::algorithmCryptor& cryptor,
// 	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
// {
// 	uint64_t shift = cryptor.get_reback_size();
// 	plain.seekg(0, std::ios::end);
// 	uint64_t file_size = plain.tellg();
// 	plain.seekg(0, std::ios::beg);
// 	int8_t read_bit_pos = 0;
// 	dog_torch::serialize::Data tempBlock0 = iv, tempBlock1;
// 	auto pick_shift = [&plain, &shift, &read_bit_pos]()->dog_torch::serialize::Data
// 		{
// 			dog_torch::serialize::Data res; res.reserve((shift / 8) + 1);
// 			uint8_t fill_byte = 0x00;
// 			uint8_t temp_byte = 0x00;
// 			for (uint64_t i = 0; i < shift; i++)
// 			{
// 				temp_byte = plain.peek();
// 				fill_byte |= ((temp_byte >> (7 - read_bit_pos)) & 0x01) << (7 - (i % 8));
// 				read_bit_pos++;
// 				if (i % 8 == 7)
// 				{
// 					res.push_back(fill_byte);
// 					fill_byte = 0x00;
// 				}
// 				if (read_bit_pos == 8)
// 				{
// 					read_bit_pos = 0;
// 					plain.get();
// 				}
// 				if (plain.eof())
// 				{
// 					break;
// 				}
// 			}
// 			if (shift % 8 != 0)
// 			{
// 				res.push_back(fill_byte);
// 			}
// 			return res;
// 		};
// 	int8_t waiting_byte = 0x00; int8_t write_bit_pos = 0;
// 	auto add_block = [&crypt, &shift, &waiting_byte, &write_bit_pos](dog_torch::serialize::Data& tempBlock)->void
// 		{
// 			uint8_t temp_byte = 0x00;
// 			for (uint64_t i = 0; i < shift; i++)
// 			{
// 				if (i / 8 == tempBlock.size()) { break; }
// 				temp_byte = tempBlock[i / 8];
// 				waiting_byte |= ((temp_byte >> (7 - i % 8)) & 0x01) << (7 - (write_bit_pos % 8));
// 				write_bit_pos++;
// 				if (write_bit_pos == 8)
// 				{
// 					crypt.put(waiting_byte);
// 					waiting_byte = 0x00;
// 					write_bit_pos = 0;
// 				}
// 			}
// 		};
// 	while (plain.eof())
// 	{
// 		cryptor.get_block_self_encryption()(tempBlock0, cryptor.get_block_size(), cryptor.get_available_key(), cryptor.get_key_size());
// 		tempBlock1 = pick_shift();
// 		while (tempBlock1.size() < cryptor.get_block_size()) { tempBlock1.push_back(0x00); }
// 		NSROOT::algorithmutils::squareXOR_self(tempBlock1, tempBlock0, cryptor.get_block_size());
// 		add_block(tempBlock1);
// 		std::unique_lock<std::mutex> lock(*mutex_);
// 		while (*paused_ && !*stop_)
// 		{
// 			cond_->wait(lock);
// 		}
// 		if (*stop_) return;
// 		lock.unlock();
// 		progress->store(update_progress(progress->load(), shift / 8.0, file_size));
// 		tempBlock0 = tempBlock0.bit_left_move_norise(shift) | tempBlock1.bit_right_move_norise(cryptor.get_block_size() * 8 - shift);
// 	}
// 	crypt.flush();
// }
// void NSROOT::mode::CFBb::decrypt_streamp(std::istream& crypt, dog_torch::serialize::Data iv, std::ostream& plain, NSROOT::algorithmCryptor& cryptor,
// 	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
// {
// 	uint64_t shift = cryptor.get_reback_size();
// 	uint64_t now_pos = crypt.tellg();
// 	crypt.seekg(0, std::ios::end);
// 	uint64_t file_size = crypt.tellg();
// 	crypt.seekg(now_pos);
// 	int8_t read_bit_pos = 0;
// 	dog_torch::serialize::Data tempBlock0 = iv, tempBlock1, tempBlock2;
// 	auto pick_shift = [&crypt, &shift, &read_bit_pos]()->dog_torch::serialize::Data
// 		{
// 			dog_torch::serialize::Data res; res.reserve((shift / 8) + 1);
// 			uint8_t fill_byte = 0x00;
// 			uint8_t temp_byte = 0x00;
// 			for (uint64_t i = 0; i < shift; i++)
// 			{
// 				temp_byte = crypt.peek();
// 				fill_byte |= ((temp_byte >> (7 - read_bit_pos)) & 0x01) << (7 - (i % 8));
// 				read_bit_pos++;
// 				if (i % 8 == 7)
// 				{
// 					res.push_back(fill_byte);
// 					fill_byte = 0x00;
// 				}
// 				if (read_bit_pos == 8)
// 				{
// 					read_bit_pos = 0;
// 					crypt.get();
// 				}
// 				if (crypt.eof())
// 				{
// 					break;
// 				}
// 			}
// 			if (shift % 8 != 0)
// 			{
// 				res.push_back(fill_byte);
// 			}
// 			return res;
// 		};
// 	int8_t waiting_byte = 0x00; int8_t write_bit_pos = 0;
// 	auto add_block = [&plain, &shift, &waiting_byte, &write_bit_pos](dog_torch::serialize::Data& tempBlock)->void
// 		{
// 			uint8_t temp_byte = 0x00;
// 			for (uint64_t i = 0; i < shift; i++)
// 			{
// 				if (i / 8 == tempBlock.size()) { break; }
// 				temp_byte = tempBlock[i / 8];
// 				waiting_byte |= ((temp_byte >> (7 - i % 8)) & 0x01) << (7 - (write_bit_pos % 8));
// 				write_bit_pos++;
// 				if (write_bit_pos == 8)
// 				{
// 					plain.put(waiting_byte);
// 					waiting_byte = 0x00;
// 					write_bit_pos = 0;
// 				}
// 			}
// 		};
// 	while (plain.eof())
// 	{
// 		cryptor.get_block_self_encryption()(tempBlock0, cryptor.get_block_size(), cryptor.get_available_key(), cryptor.get_key_size());
// 		tempBlock1 = pick_shift();
// 		while (tempBlock1.size() < cryptor.get_block_size()) { tempBlock1.push_back(0x00); }
// 		tempBlock2 = NSROOT::algorithmutils::squareXOR(tempBlock1, tempBlock0, cryptor.get_block_size());
// 		add_block(tempBlock2);
// 		std::unique_lock<std::mutex> lock(*mutex_);
// 		while (*paused_ && !*stop_) { cond_->wait(lock); }
// 		if (*stop_) return;
// 		lock.unlock();
// 		progress->store(update_progress(progress->load(), shift / 8.0, file_size));
// 		tempBlock0 = tempBlock0.bit_left_move_norise(shift) | tempBlock1.bit_right_move_norise(cryptor.get_block_size() * 8 - shift);
// 	}
// 	plain.flush();
// }

// dog_torch::serialize::Data NSROOT::mode::CFBb::encrypt_CFB1(dog_torch::serialize::Data plain, dog_torch::serialize::Data iv, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	dog_torch::serialize::Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1; tempBlock1.reserve(block_size);
// 	for (uint64_t i0 = 0; i0 < plain.size(); i0++)
// 	{
// 		uint8_t B = 0x00;
// 		for (int j = 0; j < 8; j++)
// 		{
// 			tempBlock1 = tempBlock0;
// 			cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 			uint8_t b = (plain[i0] >> (7 - j) & 0x01) ^ (tempBlock0[0] >> (7 - j) & 0x01);
// 			B += b << (7 - j);
// 			uint8_t c = b, d = 0x00;
// 			for (int i1 = 0; i1 < 16; i1++)
// 			{
// 				d = tempBlock1[15 - i1] >> 7;
// 				tempBlock1[15 - i1] = (tempBlock1[15 - i1] << 1) + c;
// 				c = d;
// 			}
// 		}
// 		res.push_back(B);
// 	}
// 	return res;
// }
// dog_torch::serialize::Data NSROOT::mode::CFBb::decrypt_CFB1(dog_torch::serialize::Data crypt, dog_torch::serialize::Data iv, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	dog_torch::serialize::Data res; res.reserve(((crypt.size() / block_size) + 1) * block_size);
// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1; tempBlock1.reserve(block_size);
// 	for (uint64_t i0 = 0; i0 < crypt.size(); i0++)
// 	{
// 		uint8_t B = 0x00;
// 		for (int j = 0; j < 8; j++)
// 		{
// 			tempBlock1 = tempBlock0;
// 			cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 			uint8_t b = (crypt[i0] >> (7 - j) & 0x01) ^ (tempBlock0[0] >> (7 - j) & 0x01);
// 			B += b << (7 - j);
// 			uint8_t c = crypt[i0] >> (7 - j) & 0x01, d = 0x00;
// 			for (int i1 = 0; i1 < 16; i1++)
// 			{
// 				d = tempBlock1[15 - i1] >> 7;
// 				tempBlock1[15 - i1] = (tempBlock1[15 - i1] << 1) + c;
// 				c = d;
// 			}
// 		}
// 		res.push_back(B);
// 	}
// 	return res;

// }
// void NSROOT::mode::CFBb::encrypt_CFB1_stream(std::istream& plain, dog_torch::serialize::Data iv, std::ostream& crypt, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	plain.seekg(0, std::ios::end);
// 	uint64_t file_size = plain.tellg();
// 	plain.seekg(0, std::ios::beg);

// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1(block_size);
// 	while (plain.tellg() < file_size)
// 	{
// 		//uint64_t s = plain.tellg();
// 		//printf("%llu\r", s);
// 		uint8_t B = 0x00;
// 		for (int j = 0; j < 8; j++)
// 		{
// 			tempBlock1 = tempBlock0;
// 			cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 			uint8_t b = (plain.peek() >> (7 - j) & 0x01) ^ (tempBlock0[0] >> (7 - j) & 0x01);
// 			B += b << (7 - j);
// 			uint8_t c = b, d = 0x00;
// 			for (int i1 = 0; i1 < 16; i1++)
// 			{
// 				d = tempBlock1[15 - i1] >> 7;
// 				tempBlock1[15 - i1] = (tempBlock1[15 - i1] << 1) + c;
// 				c = d;
// 			}
// 		}
// 		plain.get();
// 		crypt.put(B);
// 	}
// 	crypt.flush();
// }
// void NSROOT::mode::CFBb::decrypt_CFB1_stream(std::istream& crypt, dog_torch::serialize::Data iv, std::ostream& plain, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	uint64_t now_pos = crypt.tellg();
// 	crypt.seekg(0, std::ios::end);
// 	uint64_t file_size = crypt.tellg();
// 	crypt.seekg(now_pos);

// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1; tempBlock1.reserve(block_size);
// 	while (crypt.tellg() < file_size)
// 	{
// 		//uint64_t s = crypt.tellg();
// 		//printf("%llu\r", s);

// 		uint8_t B = 0x00;
// 		for (int j = 0; j < 8; j++)
// 		{
// 			tempBlock1 = tempBlock0;
// 			cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 			uint8_t b = (crypt.peek() >> (7 - j) & 0x01) ^ (tempBlock0[0] >> (7 - j) & 0x01);
// 			B += b << (7 - j);
// 			uint8_t c = crypt.peek() >> (7 - j) & 0x01, d = 0x00;
// 			for (int i1 = 0; i1 < 16; i1++)
// 			{
// 				d = tempBlock1[15 - i1] >> 7;
// 				tempBlock1[15 - i1] = (tempBlock1[15 - i1] << 1) + c;
// 				c = d;
// 			}
// 		}
// 		crypt.get();
// 		plain.put(B);
// 	}
// 	plain.flush();
// }
// void NSROOT::mode::CFBb::encrypt_CFB1_streamp(std::istream& plain, dog_torch::serialize::Data iv, std::ostream& crypt, NSROOT::algorithmCryptor& cryptor,
// 	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	plain.seekg(0, std::ios::end);
// 	uint64_t file_size = plain.tellg();
// 	plain.seekg(0, std::ios::beg);

// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1(block_size);
// 	while (plain.tellg() < file_size)
// 	{
// 		//uint64_t s = plain.tellg();
// 		//printf("%llu\r", s);
// 		uint8_t B = 0x00;
// 		for (int j = 0; j < 8; j++)
// 		{
// 			tempBlock1 = tempBlock0;
// 			cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 			uint8_t b = (plain.peek() >> (7 - j) & 0x01) ^ (tempBlock0[0] >> (7 - j) & 0x01);
// 			B += b << (7 - j);
// 			uint8_t c = b, d = 0x00;
// 			for (int i1 = 0; i1 < 16; i1++)
// 			{
// 				d = tempBlock1[15 - i1] >> 7;
// 				tempBlock1[15 - i1] = (tempBlock1[15 - i1] << 1) + c;
// 				c = d;
// 			}
// 		}
// 		plain.get();
// 		crypt.put(B);
// 		std::unique_lock<std::mutex> lock(*mutex_);
// 		while (*paused_ && !*stop_)
// 		{
// 			cond_->wait(lock);
// 		}
// 		if (*stop_) return;
// 		lock.unlock();
// 		progress->store(update_progress(progress->load(), 1, file_size));
// 	}
// 	crypt.flush();
// 	progress->store(1.0);
// }
// void NSROOT::mode::CFBb::decrypt_CFB1_streamp(std::istream& crypt, dog_torch::serialize::Data iv, std::ostream& plain, NSROOT::algorithmCryptor& cryptor,
// 	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	uint64_t now_pos = crypt.tellg();
// 	crypt.seekg(0, std::ios::end);
// 	uint64_t file_size = crypt.tellg();
// 	crypt.seekg(now_pos);

// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1; tempBlock1.reserve(block_size);
// 	while (crypt.tellg() < file_size)
// 	{
// 		//uint64_t s = crypt.tellg();
// 		//printf("%llu\r", s);

// 		uint8_t B = 0x00;
// 		for (int j = 0; j < 8; j++)
// 		{
// 			tempBlock1 = tempBlock0;
// 			cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 			uint8_t b = (crypt.peek() >> (7 - j) & 0x01) ^ (tempBlock0[0] >> (7 - j) & 0x01);
// 			B += b << (7 - j);
// 			uint8_t c = crypt.peek() >> (7 - j) & 0x01, d = 0x00;
// 			for (int i1 = 0; i1 < 16; i1++)
// 			{
// 				d = tempBlock1[15 - i1] >> 7;
// 				tempBlock1[15 - i1] = (tempBlock1[15 - i1] << 1) + c;
// 				c = d;
// 			}
// 		}
// 		crypt.get();
// 		plain.put(B);
// 		std::unique_lock<std::mutex> lock(*mutex_);
// 		while (*paused_ && !*stop_) { cond_->wait(lock); }
// 		if (*stop_) return;
// 		lock.unlock();
// 		progress->store(update_progress(progress->load(), 1, file_size));
// 	}
// 	plain.flush();
// 	progress->store(1.0);
// }

// dog_torch::serialize::Data NSROOT::mode::CFBB::encrypt_CFB128(dog_torch::serialize::Data plain, dog_torch::serialize::Data iv, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	dog_torch::serialize::Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1(block_size);
// 	uint64_t i0 = 0;
// 	for (i0 = 0; i0 <= plain.size() - 16 && plain.size() >= 16; i0 += 16)
// 	{
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		tempBlock1 = plain.sub_by_len(i0, block_size);
// 		NSROOT::algorithmutils::squareXOR_self(tempBlock1, tempBlock0, 16);
// 		res = res + tempBlock1;
// 		tempBlock0 = tempBlock1;
// 	}
// 	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	tempBlock1 = plain.sub_by_len(i0, block_size);
// 	if (tempBlock1.size() < 16 && cryptor.get_using_padding()) { cryptor.get_padding()(tempBlock1, 16); }
// 	NSROOT::algorithmutils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
// 	res += tempBlock1;
// 	return res;
// }
// dog_torch::serialize::Data NSROOT::mode::CFBB::decrypt_CFB128(dog_torch::serialize::Data crypt, dog_torch::serialize::Data iv, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	dog_torch::serialize::Data res; res.reserve(((crypt.size() / block_size) + 1) * block_size);
// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1(block_size);
// 	uint64_t i0 = 0;
// 	for (i0 = 0; i0 < crypt.size() - 16 && crypt.size() > 16; i0 += 16)
// 	{
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		tempBlock1 = crypt.sub_by_pos(i0, i0 + 16);
// 		res = res + NSROOT::algorithmutils::squareXOR(tempBlock0, tempBlock1, block_size);
// 		tempBlock0 = tempBlock1;
// 	}
// 	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	tempBlock1 = crypt.sub_by_pos(i0, i0 + 16);
// 	NSROOT::algorithmutils::squareXOR_self(tempBlock1, tempBlock0, tempBlock0.size());
// 	if (cryptor.get_using_padding())
// 	{
// 		cryptor.get_unpadding()(tempBlock1, 16);
// 	}
// 	res += tempBlock1;
// 	return res;
// }
// void NSROOT::mode::CFBB::encrypt_CFB128_stream(std::istream& plain, dog_torch::serialize::Data iv, std::ostream& crypt, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	plain.seekg(0, std::ios::end);
// 	uint64_t file_size = plain.tellg();
// 	plain.seekg(0, std::ios::beg);

// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1(block_size);
// 	while (plain.tellg() <= file_size - block_size)
// 	{
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		plain.read((char*)tempBlock1.data(), 16);
// 		NSROOT::algorithmutils::squareXOR_self(tempBlock0, tempBlock1, block_size);
// 		crypt.write((char*)tempBlock0.data(), 16);
// 	}
// 	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	plain.read((char*)tempBlock1.data(), 16);
// 	for (int i = 0; i < 16 - plain.gcount(); i++) { tempBlock1.pop_back(); }
// 	if (cryptor.get_using_padding() && plain.gcount() < 16) { cryptor.get_padding()(tempBlock1, 16); }
// 	NSROOT::algorithmutils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
// 	crypt.write((char*)tempBlock1.data(), tempBlock1.size());
// 	crypt.flush();
// }
// void NSROOT::mode::CFBB::decrypt_CFB128_stream(std::istream& crypt, dog_torch::serialize::Data iv, std::ostream& plain, NSROOT::algorithmCryptor& cryptor)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	uint64_t now_pos = crypt.tellg();
// 	crypt.seekg(0, std::ios::end);
// 	uint64_t file_size = crypt.tellg();
// 	crypt.seekg(now_pos);

// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1(block_size);
// 	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
// 	{
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		crypt.read((char*)tempBlock1.data(), block_size);
// 		plain.write((char*)NSROOT::algorithmutils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
// 		tempBlock0 = tempBlock1;
// 	}
// 	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	crypt.read((char*)tempBlock1.data(), block_size);
// 	for (int i = 0; i < 16 - crypt.gcount(); i++) { tempBlock1.pop_back(); }
// 	NSROOT::algorithmutils::squareXOR_self(tempBlock1, tempBlock0, block_size);
// 	cryptor.get_unpadding()(tempBlock1, block_size);
// 	plain.write((char*)tempBlock1.data(), tempBlock1.size());
// 	plain.flush();
// }
// void NSROOT::mode::CFBB::encrypt_CFB128_streamp(std::istream& plain, dog_torch::serialize::Data iv, std::ostream& crypt, NSROOT::algorithmCryptor& cryptor,
// 	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	plain.seekg(0, std::ios::end);
// 	uint64_t file_size = plain.tellg();
// 	plain.seekg(0, std::ios::beg);

// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1(block_size);
// 	while (plain.tellg() <= file_size - block_size)
// 	{
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		plain.read((char*)tempBlock1.data(), 16);
// 		NSROOT::algorithmutils::squareXOR_self(tempBlock0, tempBlock1, block_size);
// 		crypt.write((char*)tempBlock0.data(), 16);
// 		std::unique_lock<std::mutex> lock(*mutex_);
// 		while (*paused_ && !*stop_)
// 		{
// 			cond_->wait(lock);
// 		}
// 		if (*stop_) return;
// 		lock.unlock();
// 		progress->store(NSROOT::mode::update_progress(progress->load(), 16, file_size));
// 	}
// 	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	plain.read((char*)tempBlock1.data(), 16);
// 	for (int i = 0; i < 16 - plain.gcount(); i++) { tempBlock1.pop_back(); }
// 	if (cryptor.get_using_padding() && plain.gcount() < 16) { cryptor.get_padding()(tempBlock1, 16); }
// 	NSROOT::algorithmutils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
// 	crypt.write((char*)tempBlock1.data(), tempBlock1.size());
// 	if (progress->load() < 0) { return; }progress->store(update_progress(progress->load(), 16, file_size));
// 	crypt.flush();
// 	progress->store(1.0);

// }
// void NSROOT::mode::CFBB::decrypt_CFB128_streamp(std::istream& crypt, dog_torch::serialize::Data iv, std::ostream& plain, NSROOT::algorithmCryptor& cryptor,
// 	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
// {
// 	uint8_t block_size = cryptor.get_block_size();
// 	uint64_t now_pos = crypt.tellg();
// 	crypt.seekg(0, std::ios::end);
// 	uint64_t file_size = crypt.tellg();
// 	crypt.seekg(now_pos);

// 	dog_torch::serialize::Data tempBlock0 = iv;
// 	dog_torch::serialize::Data tempBlock1(block_size);
// 	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
// 	{
// 		cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 		crypt.read((char*)tempBlock1.data(), block_size);
// 		plain.write((char*)NSROOT::algorithmutils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
// 		std::unique_lock<std::mutex> lock(*mutex_);
// 		while (*paused_ && !*stop_) { cond_->wait(lock); }
// 		if (*stop_) return;
// 		lock.unlock();
// 		progress->store(update_progress(progress->load(), 16, file_size));
// 		tempBlock0 = tempBlock1;
// 	}
// 	cryptor.get_block_self_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
// 	crypt.read((char*)tempBlock1.data(), block_size);
// 	for (int i = 0; i < 16 - crypt.gcount(); i++) { tempBlock1.pop_back(); }
// 	NSROOT::algorithmutils::squareXOR_self(tempBlock1, tempBlock0, block_size);
// 	cryptor.get_unpadding()(tempBlock1, block_size);
// 	plain.write((char*)tempBlock1.data(), tempBlock1.size());
// 	if (progress->load() < 0) { return; }progress->store(update_progress(progress->load(), 16, file_size));
// 	plain.flush();
// 	progress->store(1.0);
// }

// const std::vector<NSROOT::mode::Config> NSROOT::mode::list = {
// 	NSROOT::mode::CBC::CONFIG,
// 	NSROOT::mode::ECB::CONFIG,
// 	NSROOT::mode::PCBC::CONFIG,
// 	NSROOT::mode::OFB::CONFIG,
// 	NSROOT::mode::CTR::CONFIG,
// 	NSROOT::mode::CFBb::CONFIG,
// 	NSROOT::mode::CFBB::CONFIG
// };

// const std::vector<NSROOT::algorithmAlgorithmConfig> NSROOT::algorithmAlgorithm_list = {
// 	NSROOT::algorithmAES::CONFIG,
// 	NSROOT::algorithmSM4::CONFIG,
// 	NSROOT::algorithmcamellia::CONFIG,
// 	NSROOT::algorithmTwofish::CONFIG
// };

// NSROOT::algorithmCryptionConfig::CryptionConfig(
// 	const std::string& cryption_algorithm, const uint64_t block_size, const uint64_t key_size,
// 	bool using_padding, const std::string& padding_function,
// 	const std::string& mult_function, bool using_iv, uint64_t shift,
// 	std::vector<std::pair<std::string, std::any>> extra_config)
// {
// 	this->cryption_algorithm = cryption_algorithm;
// 	this->block_size = block_size;
// 	this->key_size = key_size;
// 	this->using_padding = using_padding;
// 	this->padding_function = padding_function;
// 	this->mult_function = mult_function;
// 	this->using_iv = using_iv;
// 	this->shift = shift;
// 	for (auto& [key, value] : extra_config)
// 	{
// 		if (value.type() == typeid(const char*))
// 		{
// 			this->extra_config[key] = std::string(std::any_cast<const char*>(value));
// 		}
// 		else if (value.type() == typeid(std::string) ||
// 			value.type() == typeid(uint8_t) ||
// 			value.type() == typeid(uint16_t) ||
// 			value.type() == typeid(uint32_t) ||
// 			value.type() == typeid(uint64_t) ||
// 			value.type() == typeid(int8_t) ||
// 			value.type() == typeid(int16_t) ||
// 			value.type() == typeid(int32_t) ||
// 			value.type() == typeid(int64_t))
// 		{
// 			this->extra_config[key] = value;
// 		}
// 	}
// }

// NSROOT::algorithmCryptionConfig::CryptionConfig(
// 	const std::string& cryption_algorithm, const uint64_t block_size, const uint64_t key_size,
// 	bool using_padding, const std::string& padding_function,
// 	const std::string& mult_function, bool using_iv, uint64_t shift,
// 	std::unordered_map<std::string, std::any> extra_config)
// {
// 	this->cryption_algorithm = cryption_algorithm;
// 	this->block_size = block_size;
// 	this->key_size = key_size;
// 	this->using_padding = using_padding;
// 	this->padding_function = padding_function;
// 	this->mult_function = mult_function;
// 	this->using_iv = using_iv;
// 	this->shift = shift;
// 	this->extra_config = extra_config;
// }
// dog_torch::serialize::Data NSROOT::algorithmCryptionConfig::to_data() const
// {
// 	dog_torch::serialize::Data data;
// 	data += dog_torch::serialize::tlv::string(this->cryption_algorithm);
// 	data += dog_torch::serialize::tlv::integer_num(this->block_size);
// 	data += dog_torch::serialize::tlv::integer_num(this->key_size);
// 	{
// 		using namespace NSROOT::mode;
// 		bool is_fill = false;
// 		for (auto& config : NSROOT::mode::list)
// 		{
// 			if (this->mult_function == config.name)
// 			{
// 				is_fill = true;
// 				data += dog_torch::serialize::tlv::integer_num(config.code);
// 			}
// 		}
// 		if (!is_fill)
// 		{
// 			throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:Unknown mode function\n错误：未知的工作模式"));
// 		}
// 	}
// 	data += dog_torch::serialize::tlv::boolean(this->using_padding);
// 	if (using_padding)
// 	{
// 		using namespace NSROOT::algorithmpadding;
// 		bool is_fill = false;
// 		for (auto& config : NSROOT::algorithmpadding::list)
// 		{
// 			if (this->padding_function == config.name)
// 			{
// 				is_fill = true;
// 				data += dog_torch::serialize::tlv::integer_num(config.code);
// 			}
// 		}
// 		if (!is_fill)
// 		{
// 			throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:Unknown padding function\n错误：未知填充函数"));
// 		}
// 	}
// 	data += dog_torch::serialize::tlv::boolean(this->using_iv);
// 	data += dog_torch::serialize::tlv::object(this->extra_config);
// 	return data;
// }
// std::string NSROOT::algorithmCryptionConfig::to_string() const
// {
// 	//{cryption_algorithm}_{block_size}_{key_size}_{mult_function}_{using_iv}_{with_iv}_{using_padding}_{padding_function}_{"key":value}
// 	std::string base_str = std::format("{}_{}_{}_{}_{}_{}_{}",
// 		cryption_algorithm, block_size, key_size,
// 		mult_function + (mult_function.substr(0, 3) == "CFB" ? std::format("{}", shift) : ""), (using_iv ? "UsingIV" : "NotUsingIV"),
// 		(using_padding ? "UsingPadding" : "NotUsingPadding"), padding_function);
// 	if (!this->extra_config.empty())
// 	{
// 		std::string extra_str = "{";
// 		for (auto& [key, value] : this->extra_config)
// 		{
// 			if (value.type() == typeid(std::string))
// 			{
// 				std::string value_str = std::any_cast<std::string>(value);
// 				std::string single = std::vformat("\"{}\":\"{}\"", std::make_format_args(key, value_str));
// 				extra_str = extra_str + single + ",";
// 			}
// 			else if (value.type() == typeid(uint8_t))
// 			{
// 				uint64_t value_num = std::any_cast<uint8_t>(value);
// 				std::string single = std::vformat("\"{}\":{}", std::make_format_args(key, value_num));
// 				extra_str = extra_str + single + ",";
// 			}
// 			else if (value.type() == typeid(uint16_t))
// 			{
// 				uint64_t value_num = std::any_cast<uint16_t>(value);
// 				std::string single = std::vformat("\"{}\":{}", std::make_format_args(key, value_num));
// 				extra_str = extra_str + single + ",";
// 			}
// 			else if (value.type() == typeid(uint32_t))
// 			{
// 				uint64_t value_num = std::any_cast<uint32_t>(value);
// 				std::string single = std::vformat("\"{}\":{}", std::make_format_args(key, value_num));
// 				extra_str = extra_str + single + ",";
// 			}
// 			else if (value.type() == typeid(uint64_t))
// 			{
// 				uint64_t value_num = std::any_cast<uint64_t>(value);
// 				std::string single = std::vformat("\"{}\":{}", std::make_format_args(key, value_num));
// 				extra_str = extra_str + single + ",";
// 			}
// 			else if (value.type() == typeid(int8_t))
// 			{
// 				uint64_t value_num = std::any_cast<int8_t>(value);
// 				std::string single = std::vformat("\"{}\":{}", std::make_format_args(key, value_num));
// 				extra_str = extra_str + single + ",";
// 			}
// 			else if (value.type() == typeid(int16_t))
// 			{
// 				uint64_t value_num = std::any_cast<int16_t>(value);
// 				std::string single = std::vformat("\"{}\":{}", std::make_format_args(key, value_num));
// 				extra_str = extra_str + single + ",";
// 			}
// 			else if (value.type() == typeid(int32_t))
// 			{
// 				uint64_t value_num = std::any_cast<int32_t>(value);
// 				std::string single = std::vformat("\"{}\":{}", std::make_format_args(key, value_num));
// 				extra_str = extra_str + single + ",";
// 			}
// 			else if (value.type() == typeid(int64_t))
// 			{
// 				uint64_t value_num = std::any_cast<int64_t>(value);
// 				std::string single = std::vformat("\"{}\":{}", std::make_format_args(key, value_num));
// 				extra_str = extra_str + single + ",";
// 			}

// 		}
// 		return base_str + extra_str.substr(0, extra_str.size() - 1) + "}";
// 	}
// 	else
// 	{
// 		return base_str;
// 	}
// }
// NSROOT::algorithmCryptionConfig NSROOT::algorithmCryptionConfig::get_cryption_config(std::istream& config_stream, bool return_start)
// {
// 	try
// 	{
// 		NSROOT::algorithmCryptionConfig config;
// 		std::any value = dog_torch::serialize::tlv::read(config_stream);
// 		config.cryption_algorithm = std::any_cast<std::string>(value);
// 		value = dog_torch::serialize::tlv::read(config_stream);
// 		config.block_size = std::any_cast<uint64_t>(value);
// 		value = dog_torch::serialize::tlv::read(config_stream);
// 		config.key_size = std::any_cast<uint64_t>(value);
// 		value = dog_torch::serialize::tlv::read(config_stream);
// 		uint64_t mode_code = std::any_cast<uint64_t>(value);
// 		{
// 			using namespace NSROOT::mode;
// 			bool is_fill = false;
// 			for (auto& config_it : list)
// 			{
// 				if (config_it.code == mode_code)
// 				{
// 					is_fill = true;
// 					config.mult_function = config_it.name;
// 				}
// 			}
// 			if (!is_fill)
// 			{
// 				throw CryptionException(DOG_EXCEPTION_MSG_OPINION(std::format("Error:invalid mode function code {}错误：无效的工作模式代码 {} ", mode_code, mode_code)));
// 			}
// 		}
// 		value = dog_torch::serialize::tlv::read(config_stream);
// 		config.using_padding = std::any_cast<bool>(value);
// 		if (config.using_padding)
// 		{
// 			using namespace NSROOT::algorithmpadding;
// 			bool is_fill = false;
// 			value = dog_torch::serialize::tlv::read(config_stream);
// 			uint64_t padding_code = std::any_cast<uint64_t>(value);	
// 			for (auto& config_it : list)
// 			{
// 				if (config_it.code == padding_code)
// 				{
// 					config.padding_function = config_it.name;
// 				}
// 			}
// 			if (!is_fill)
// 			{
// 				throw CryptionException(DOG_EXCEPTION_MSG_OPINION(std::format("Error:invalid padding function code {}\n错误：无效的填充方法代码 {}", padding_code, padding_code)));
// 			}
// 		}
// 		else
// 		{
// 			config.padding_function = NSROOT::algorithmpadding::NONE_CONFIG.name;
// 		}
// 		value = dog_torch::serialize::tlv::read(config_stream);
// 		config.using_iv = std::any_cast<bool>(value);
// 		value = dog_torch::serialize::tlv::read(config_stream);
// 		config.extra_config = std::any_cast<std::unordered_map<std::string, std::any>>(value);
// 		if (return_start) { config_stream.seekg(0); }
// 		return config;
// 	}
// 	catch (std::exception& e)
// 	{
// 		throw DOG_EXCEPTION("Error:wrong in reading config\n错误：配置读取错误");
// 	}
// }
// NSROOT::algorithmCryptionConfig NSROOT::algorithmCryptionConfig::get_cryption_config(dog_torch::serialize::Data& config_data, bool is_cut)
// {
// 	try
// 	{
// 		NSROOT::algorithmCryptionConfig config;
// 		dog_torch::serialize::DataStream config_stream(config_data);
// 		std::any value = dog_torch::serialize::tlv::read(config_stream);
// 		config.cryption_algorithm = std::any_cast<std::string>(value);
// 		value = dog_torch::serialize::tlv::read(config_stream);
// 		config.block_size = std::any_cast<uint64_t>(value);
// 		value = dog_torch::serialize::tlv::read(config_stream);
// 		config.key_size = std::any_cast<uint64_t>(value);
// 		value = dog_torch::serialize::tlv::read(config_stream);
// 		uint64_t mode_code = std::any_cast<uint64_t>(value);
// 		{
// 			using namespace NSROOT::mode;
// 			bool is_fill = false;
// 			for (auto& config_it : list)
// 			{
// 				if (config_it.code == mode_code)
// 				{
// 					is_fill = true;
// 					config.mult_function = config_it.name;
// 				}
// 			}
// 			if (!is_fill)
// 			{
// 				throw CryptionException(DOG_EXCEPTION_MSG_OPINION(std::format("Error:invalid mode function code {}错误：无效的工作模式代码 {} ", mode_code, mode_code)));
// 			}

// 		}
// 		value = dog_torch::serialize::tlv::read(config_stream);
// 		config.using_padding = std::any_cast<bool>(value);
// 		if (config.using_padding)
// 		{
// 			using namespace NSROOT::algorithmpadding;
// 			bool is_fill = false;
// 			value = dog_torch::serialize::tlv::read(config_stream);
// 			uint64_t padding_code = std::any_cast<uint64_t>(value);
// 			for (auto& config_it : list)
// 			{
// 				if (config_it.code == padding_code)
// 				{
// 					config.padding_function = config_it.name;
// 				}
// 			}
// 			if (!is_fill)
// 			{
// 				throw CryptionException(DOG_EXCEPTION_MSG_OPINION(std::format("Error:invalid padding function code {}\n错误：无效的填充方法代码 {}", padding_code, padding_code)));
// 			}
// 		}
// 		else
// 		{
// 			config.padding_function = NSROOT::algorithmpadding::NONE_CONFIG.name;
// 		}
// 		value = dog_torch::serialize::tlv::read(config_stream);
// 		config.using_iv = std::any_cast<bool>(value);
// 		value = dog_torch::serialize::tlv::read(config_stream);
// 		config.extra_config = std::any_cast<std::unordered_map<std::string, std::any>>(value);
// 		if (is_cut)
// 		{
// 			uint64_t size = config_stream.tellg();
// 			config_data = config_data.sub_by_pos(size, config_data.size());
// 		}
// 		return config;
// 	}
// 	catch (std::exception& e)
// 	{
// 		throw DOG_EXCEPTION("Error:wrong in reading config\n错误：配置读取错误");
// 	}
// }

// bool NSROOT::algorithmCryptor::is_config_available(const CryptionConfig& config)
// {
// 	std::unique_ptr<NSROOT::algorithmAlgorithmConfig> algorithm_config;
// 	for (auto& algorithm : NSROOT::algorithmAlgorithm_list)
// 	{
// 		if (algorithm.name == config.cryption_algorithm)
// 		{
// 			algorithm_config = std::make_unique<NSROOT::algorithmAlgorithmConfig>(algorithm);
// 		}
// 	}
// 	if (!algorithm_config)
// 	{
// 		return false;
// 	}
// 	if (!dog_torch::math::region::gap::is_fall(algorithm_config->block_size_region, config.block_size))
// 	{
// 		return false;
// 	}
// 	if (!dog_torch::math::region::gap::is_fall(algorithm_config->key_size_region, config.key_size))
// 	{
// 		return false;
// 	}

// 	std::unique_ptr<NSROOT::mode::Config> mode_config;
// 	for (auto& mode : NSROOT::mode::list)
// 	{
// 		if (mode.name == config.mult_function)
// 		{
// 			mode_config = std::make_unique<NSROOT::mode::Config>(mode);
// 		}
// 	}
// 	if (!mode_config)
// 	{
// 		return false;
// 	}
// 	if (mode_config->force_padding)
// 	{
// 		std::unique_ptr<NSROOT::algorithmpadding::Config> padding_config;
// 		for (auto& padding : NSROOT::algorithmpadding::list)
// 		{
// 			if (padding.name == config.padding_function)
// 			{
// 				padding_config = std::make_unique<NSROOT::algorithmpadding::Config>(padding);
// 			}
// 		}
// 		if (!padding_config)
// 		{
// 			return false;
// 		}
// 		return true;
// 	}
// 	else
// 	{
// 		return true;
// 	}
// }
// std::unordered_map<std::string, std::any> NSROOT::algorithmCryptor::turn_map(std::vector<std::pair<std::string, std::any>> vec)
// {
// 	std::unordered_map<std::string, std::any> res;
// 	for (auto& p : vec)
// 	{
// 		res[p.first] = p.second;
// 	}
// 	return res;
// }
// std::vector<std::pair<std::string, std::any>> NSROOT::algorithmCryptor::turn_vec(std::unordered_map<std::string, std::any> map)
// {
// 	std::vector<std::pair<std::string, std::any>> res;
// 	for (auto& p : map)
// 	{
// 		res.emplace_back(p.first, p.second);
// 	}
// 	return res;
// }

// //cryptor
// NSROOT::algorithmCryptor::Cryptor(
// 	const std::string& cryption_algorithm, const uint64_t block_size, const uint64_t key_size,
// 	bool using_padding, const std::string& padding_function,
// 	const std::string& mult_function, bool using_iv, uint64_t shift,
// 	std::vector<std::pair<std::string, std::any>> extra_config)
// {
// 	std::string name = cryption_algorithm;
// 	/*
// 	else if (name == NSROOT::algorithmtype::name)
// 	{
// 		using namespace NSROOT::algorithmcamellia;
// 		if (!dog_torch::math::region::gap::is_fall(KEY_REGION, key_size))
// 		{
// 			throw CryptionException(DOG_EXCEPTION_MSG_OPINION(std::format("invalid key size for {},{} only support number in {}", name, name, KEY_REGION).c_str()));
// 		}
// 		if (!dog_torch::math::region::gap::is_fall(BLOCK_REGION, block_size))
// 		{
// 			throw CryptionException(DOG_EXCEPTION_MSG_OPINION(std::format("invalid block size for {},{} only support number in {}", name, name, BLOCK_REGION).c_str()));
// 		}

// 		this->extend_key_ = extend_key;

// 		this->block_encryption_ = encoding;
// 		this->block_decryption_ = decoding;

// 		this->block_encryption_self_ = encoding_self;
// 		this->block_decryption_self_ = decoding_self;
// 	}
// 	*/
// #define CRYPTOR_INIT(type) \
// if (name == NSROOT::algorithmtype::CONFIG.name)\
// {\
// 	using namespace NSROOT::algorithmtype;\
// 	if (!dog_torch::math::region::gap::is_fall(CONFIG.key_size_region, key_size))\
// 	{\
// 		throw CryptionException(DOG_EXCEPTION_MSG_OPINION(std::format("Error:invalid key size for {},{} only support number in {}\n错误：无效的密钥长度，{}仅支持{}", name, name, CONFIG.key_size_region,name, name, CONFIG.key_size_region)));\
// 	}\
// 	if (!dog_torch::math::region::gap::is_fall(CONFIG.block_size_region, block_size))\
// 	{\
// 		throw CryptionException(DOG_EXCEPTION_MSG_OPINION(std::format("Error:invalid block size for {},{} only support number in {}\n错误：无效的密钥长度，{}仅支持{}", name, name, CONFIG.block_size_region,name, name, CONFIG.block_size_region)));\
// 	}\
// 	this->extend_key_ = extend_key;\
// 	\
// 	this->block_encryption_ = encoding;\
// 	this->block_decryption_ = decoding;\
// 	\
// 	this->block_encryption_self_ = encoding_self;\
// 	this->block_decryption_self_ = decoding_self;\
// }
// 	CRYPTOR_INIT(AES)
// 	else CRYPTOR_INIT(SM4)
// 	else CRYPTOR_INIT(camellia)
// 	else CRYPTOR_INIT(Twofish)
// 	else
// 	{
// 		//throw CryptionException(DOG_EXCEPTION_MSG_OPINION("invalid cryption algorithm"));
// 		throw WrongConfigException(DOG_EXCEPTION_OPINION);
// 	}

// #undef CRYPTOR_INIT
// 	{
// 		using namespace NSROOT::algorithmpadding;
// 		std::string padding_name = padding_function;
// #define PADDING_INIT(name_) if(padding_name == name_##_CONFIG.name){this->padding_ = name_##_padding;this->unpadding_ = name_##_unpadding;}
// 		PADDING_INIT(PKCS7)
// 		else PADDING_INIT(ZERO)
// 		else PADDING_INIT(ANSIX923)
// 		else PADDING_INIT(ISO10126)
// 		else PADDING_INIT(ISO7816_4)
// 		else PADDING_INIT(NONE)
// 		else
// 		{
// 			throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:invalid padding function\n错误：无效的填充函数"));
// 		}
// #undef PADDING_INIT
// 	}

// 	{
// 		using namespace NSROOT::mode;
// 		std::string mult_mode = mult_function;
// 		/*
// 		   vx:不强制 v:强制
// 				 iv|填充|
// 			ECB |vx|v |
// 			CBC |v |v |
// 			OFB |v |vx|
// 			CTR |v |vx|
// 			CFB |v |vx|
// 		*/
// 		if (mult_mode == ECB::CONFIG.name)
// 		{
// 			this->config_.using_iv = using_iv;
// 			this->config_.using_padding = true;

// 			this->mult_encrypt_ = ECB::encrypt;
// 			this->mult_decrypt_ = ECB::decrypt;

// 			this->stream_encrypt_ = ECB::encrypt_stream;
// 			this->stream_decrypt_ = ECB::decrypt_stream;

// 			this->stream_encryptp_ = ECB::encrypt_streamp;
// 			this->stream_decryptp_ = ECB::decrypt_streamp;

// 		}
// 		else if (mult_mode == ECB::CONFIG.name)
// 		{
// 			this->config_.using_iv = true;
// 			this->config_.using_padding = true;

// 			this->mult_encrypt_ = CBC::encrypt;
// 			this->mult_decrypt_ = CBC::decrypt;

// 			this->stream_encrypt_ = CBC::encrypt_stream;
// 			this->stream_decrypt_ = CBC::decrypt_stream;

// 			this->stream_encryptp_ = CBC::encrypt_streamp;
// 			this->stream_decryptp_ = CBC::decrypt_streamp;

// 		}
// 		else if (mult_mode == ECB::CONFIG.name)
// 		{
// 			this->config_.using_iv = true;
// 			this->config_.using_padding = true;

// 			this->mult_encrypt_ = PCBC::encrypt;
// 			this->mult_decrypt_ = PCBC::decrypt;

// 			this->stream_encrypt_ = PCBC::encrypt_stream;
// 			this->stream_decrypt_ = PCBC::decrypt_stream;

// 			this->stream_encryptp_ = PCBC::encrypt_streamp;
// 			this->stream_decryptp_ = PCBC::decrypt_streamp;
// 		}
// 		else if (mult_mode == ECB::CONFIG.name)
// 		{
// 			this->config_.using_iv = true;
// 			this->config_.using_padding = using_padding;

// 			if (shift == 1)
// 			{
// 				this->mult_encrypt_ = CFBb::encrypt_CFB1;
// 				this->mult_decrypt_ = CFBb::decrypt_CFB1;

// 				this->stream_encrypt_ = CFBb::encrypt_stream;
// 				this->stream_decrypt_ = CFBb::decrypt_stream;

// 				this->stream_encryptp_ = CFBb::encrypt_streamp;
// 				this->stream_decryptp_ = CFBb::decrypt_streamp;
// 			}
// 			else if (shift / 8 == 16)
// 			{
// 				this->mult_encrypt_ = CFBB::encrypt_CFB128;
// 				this->mult_decrypt_ = CFBB::decrypt_CFB128;

// 				this->stream_encrypt_ = CFBB::encrypt_CFB128_stream;
// 				this->stream_decrypt_ = CFBB::decrypt_CFB128_stream;

// 				this->stream_encryptp_ = CFBB::encrypt_CFB128_streamp;
// 				this->stream_decryptp_ = CFBB::decrypt_CFB128_streamp;
// 			}
// 			else if (shift / 8 <= block_size)
// 			{
// 				this->mult_encrypt_ = CFBb::encrypt;
// 				this->mult_decrypt_ = CFBb::decrypt;

// 				this->stream_encrypt_ = CFBb::encrypt_stream;
// 				this->stream_decrypt_ = CFBb::decrypt_stream;

// 				this->stream_encryptp_ = CFBb::encrypt_streamp;
// 				this->stream_decryptp_ = CFBb::decrypt_streamp;
// 			}
// 			else
// 			{
// 				throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:invalid config for CFBb, shift need less than block size\n错误：CFBb配置无效，偏移量小于分块大小"));
// 			}
// 		}
// 		else if (mult_mode == ECB::CONFIG.name)
// 		{
// 			this->config_.using_iv = true;
// 			this->config_.using_padding = using_padding;

// 			if (shift == 1)
// 			{
// 				this->mult_encrypt_ = CFBB::encrypt_CFB8;
// 				this->mult_decrypt_ = CFBB::decrypt_CFB8;

// 				this->stream_encrypt_ = CFBB::encrypt_CFB8_stream;
// 				this->stream_decrypt_ = CFBB::decrypt_CFB8_stream;

// 				this->stream_encryptp_ = CFBB::encrypt_CFB8_streamp;
// 				this->stream_decryptp_ = CFBB::decrypt_CFB8_streamp;
// 			}
// 			else if (shift == 16)
// 			{
// 				this->mult_encrypt_ = CFBB::encrypt_CFB128;
// 				this->mult_decrypt_ = CFBB::decrypt_CFB128;

// 				this->stream_encrypt_ = CFBB::encrypt_CFB128_stream;
// 				this->stream_decrypt_ = CFBB::decrypt_CFB128_stream;

// 				this->stream_encryptp_ = CFBB::encrypt_CFB128_streamp;
// 				this->stream_decryptp_ = CFBB::decrypt_CFB128_streamp;
// 			}
// 			else if (shift <= block_size)
// 			{
// 				this->mult_encrypt_ = CFBB::encrypt;
// 				this->mult_decrypt_ = CFBB::decrypt;

// 				this->stream_encrypt_ = CFBB::encrypt_stream;
// 				this->stream_decrypt_ = CFBB::decrypt_stream;

// 				this->stream_encryptp_ = CFBB::encrypt_streamp;
// 				this->stream_decryptp_ = CFBB::decrypt_streamp;
// 			}
// 			else
// 			{
// 				throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:invalid config for CFBb, shift need less than block size\n错误：CFBb配置无效，偏移量小于分块大小"));
// 			}
// 		}
// 		else if (mult_mode == ECB::CONFIG.name)
// 		{
// 			this->config_.using_iv = true;
// 			this->config_.using_padding = using_padding;

// 			this->mult_encrypt_ = OFB::encrypt;
// 			this->mult_decrypt_ = OFB::decrypt;

// 			this->stream_encrypt_ = OFB::encrypt_stream;
// 			this->stream_decrypt_ = OFB::decrypt_stream;

// 			this->stream_encryptp_ = OFB::encrypt_streamp;
// 			this->stream_decryptp_ = OFB::decrypt_streamp;
// 		}
// 		else if (mult_mode == ECB::CONFIG.name)
// 		{
// 			this->config_.using_iv = true;
// 			this->config_.using_padding = using_padding;

// 			this->mult_encrypt_ = CTR::encrypt;
// 			this->mult_decrypt_ = CTR::decrypt;

// 			this->stream_encrypt_ = CTR::encrypt_stream;
// 			this->stream_decrypt_ = CTR::decrypt_stream;

// 			this->stream_encryptp_ = CTR::encrypt_streamp;
// 			this->stream_decryptp_ = CTR::decrypt_streamp;
// 		}
// 		else
// 		{
// 			throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:invalid encryption mode\n错误：加密模式无效"));
// 		}
// 	}
// 	this->is_valid_ = true;
// 	this->config_.cryption_algorithm = cryption_algorithm;
// 	this->config_.block_size = block_size;
// 	this->config_.key_size = key_size;
// 	this->config_.using_padding = using_padding;
// 	this->config_.padding_function = padding_function;
// 	this->config_.mult_function = mult_function;
// 	this->config_.using_iv = using_iv;
// 	this->config_.shift = shift;
// 	for (auto& [key, value] : extra_config)
// 	{
// 		this->config_.extra_config[key] = value;
// 	}
// }

// void NSROOT::algorithmCryptor::set_key(dog_torch::serialize::Data key)
// {
// 	this->original_key_ = key;
// 	this->key_ = this->extend_key_(key, this->config_.block_size, this->config_.key_size);
// 	this->is_setting_key_ = true;
// }
// void NSROOT::algorithmCryptor::swap(Cryptor& other)
// {
// 	std::swap(this->is_valid_, other.is_valid_);
// 	std::swap(this->config_, other.config_);
// 	std::swap(this->is_setting_key_, other.is_setting_key_);
// 	std::swap(this->key_, other.key_);
// 	std::swap(this->original_key_, other.original_key_);
// 	std::swap(this->extend_key_, other.extend_key_);
// 	std::swap(this->padding_, other.padding_);
// 	std::swap(this->unpadding_, other.unpadding_);
// 	std::swap(this->block_encryption_self_, other.block_encryption_self_);
// 	std::swap(this->block_decryption_self_, other.block_decryption_self_);
// 	std::swap(this->block_encryption_, other.block_encryption_);
// 	std::swap(this->block_decryption_, other.block_decryption_);
// 	std::swap(this->mult_encrypt_, other.mult_encrypt_);
// 	std::swap(this->mult_decrypt_, other.mult_decrypt_);
// 	std::swap(this->stream_encrypt_, other.stream_encrypt_);
// 	std::swap(this->stream_decrypt_, other.stream_decrypt_);
// 	std::swap(this->stream_encryptp_, other.stream_encryptp_);
// 	std::swap(this->stream_decryptp_, other.stream_decryptp_);
// }
// void NSROOT::algorithmCryptor::swap_config(Cryptor& other)
// {
// 	std::swap(this->is_valid_, other.is_valid_);
// 	std::swap(this->config_, other.config_);
// 	std::swap(this->extend_key_, other.extend_key_);
// 	std::swap(this->padding_, other.padding_);
// 	std::swap(this->unpadding_, other.unpadding_);
// 	std::swap(this->block_encryption_self_, other.block_encryption_self_);
// 	std::swap(this->block_decryption_self_, other.block_decryption_self_);
// 	std::swap(this->block_encryption_, other.block_encryption_);
// 	std::swap(this->block_decryption_, other.block_decryption_);
// 	std::swap(this->mult_encrypt_, other.mult_encrypt_);
// 	std::swap(this->mult_decrypt_, other.mult_decrypt_);
// 	std::swap(this->stream_encrypt_, other.stream_encrypt_);
// 	std::swap(this->stream_decrypt_, other.stream_decrypt_);
// 	std::swap(this->stream_encryptp_, other.stream_encryptp_);
// 	std::swap(this->stream_decryptp_, other.stream_decryptp_);
// 	if (this->is_setting_key_)
// 	{
// 		this->key_ = this->extend_key_(this->original_key_, this->config_.block_size, this->config_.key_size);
// 	}
// }
// uint64_t NSROOT::algorithmCryptor::get_block_size() const
// {
// 	return this->config_.block_size;
// }
// uint64_t NSROOT::algorithmCryptor::get_key_size() const
// {
// 	return this->config_.key_size;
// }
// bool NSROOT::algorithmCryptor::get_using_iv() const
// {
// 	return this->config_.using_iv;
// }
// bool NSROOT::algorithmCryptor::get_using_padding() const
// {
// 	return this->config_.using_padding;
// }
// dog_torch::serialize::Data NSROOT::algorithmCryptor::get_original_key() const
// {
// 	return this->original_key_;
// }
// dog_torch::serialize::Data NSROOT::algorithmCryptor::get_available_key() const
// {
// 	return this->key_;
// }
// NSROOT::algorithmCryptor::padding_func NSROOT::algorithmCryptor::get_padding() const
// {
// 	return this->padding_;
// }
// NSROOT::algorithmCryptor::padding_func  NSROOT::algorithmCryptor::get_unpadding() const
// {
// 	return this->unpadding_;
// }
// NSROOT::algorithmCryptor::block_self_cryption_func NSROOT::algorithmCryptor::get_block_self_encryption() const
// {
// 	return this->block_encryption_self_;
// }
// NSROOT::algorithmCryptor::block_self_cryption_func NSROOT::algorithmCryptor::get_block_self_decryption() const
// {
// 	return this->block_decryption_self_;
// }
// NSROOT::algorithmCryptor::block_cryption_func NSROOT::algorithmCryptor::get_block_encryption() const
// {
// 	return this->block_encryption_;
// }
// NSROOT::algorithmCryptor::block_cryption_func NSROOT::algorithmCryptor::get_block_decryption() const
// {
// 	return this->block_decryption_;
// }
// NSROOT::algorithmCryptionConfig NSROOT::algorithmCryptor::get_config()
// {
// 	return this->config_;
// }
// uint64_t NSROOT::algorithmCryptor::get_reback_size() const
// {
// 	if (this->config_.cryption_algorithm == "CFBb" || this->config_.shift % 8 == 0)
// 	{
// 		return this->config_.shift / 8;
// 	}
// 	return this->config_.shift;
// }
// bool NSROOT::algorithmCryptor::is_available() const
// {
// 	if (!this->is_valid_)
// 	{
// 		throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:Cryptor config is invalid\n错误：Cryptor加密器配置无效"));
// 	}
// 	if (!this->is_setting_key_)
// 	{
// 		throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:encrypt key is not set or key is invalid\n错误：加密密钥未设置或密钥无效"));
// 	}
// 	return true;
// }

// dog_torch::serialize::Data NSROOT::algorithmCryptor::encrypt(dog_torch::serialize::Data plain, bool with_config, bool with_iv, dog_torch::serialize::Data iv, bool with_check)
// {
// 	if (!this->is_available())
// 	{
// 		throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:Cryptor config is invalid\n错误：Cryptor加密器配置无效"));
// 	}
// 	dog_torch::serialize::Data res;
// 	if (with_config)
// 	{
// 		res += this->config_.to_data();
// 	}
// 	if (with_check)
// 	{
// 		dog_torch::serialize::Data check = NSROOT::algorithmutils::get_sequence(this->config_.block_size);
// 		this->get_block_self_encryption()(check, this->config_.block_size, this->get_available_key(), this->get_key_size());
// 		res += check;
// 	}
// 	if (with_iv)
// 	{
// 		res += iv.sub_by_len(0, this->config_.block_size);
// 	}
// 	res += this->mult_encrypt_(plain, iv, *this);
// 	return res;
// }
// void NSROOT::algorithmCryptor::encrypt(std::istream& plain, std::ostream& crypt, bool with_config, bool with_iv, dog_torch::serialize::Data iv, bool with_check)
// {
// 	if (!this->is_available())
// 	{
// 		throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:Cryptor config is invalid\n错误：Cryptor加密器配置无效"));
// 	}
// 	if (with_config)
// 	{
// 		dog_torch::serialize::Data config_data = this->config_.to_data();
// 		crypt.write((char*)config_data.data(), config_data.size());
// 	}
// 	if (with_check)
// 	{
// 		dog_torch::serialize::Data check = NSROOT::algorithmutils::get_sequence(this->config_.block_size);
// 		this->get_block_self_encryption()(check, this->config_.block_size, this->get_available_key(), this->get_key_size());
// 		crypt.write((char*)check.data(), check.size());
// 	}
// 	if (with_iv)
// 	{
// 		crypt.write((char*)iv.data(), this->config_.block_size);
// 	}
// 	this->stream_encrypt_(plain, iv, crypt, *this);
// }
// void NSROOT::algorithmCryptor::encryptp(std::istream& plain, std::ostream& crypt, bool with_config, bool with_iv, dog_torch::serialize::Data iv, bool with_check,
// 	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
// {
// 	if (!this->is_available())
// 	{
// 		throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:Cryptor config is invalid\n错误：Cryptor加密器配置无效"));
// 	}
// 	if (with_config)
// 	{
// 		dog_torch::serialize::Data config_data = this->config_.to_data();
// 		crypt.write((char*)config_data.data(), config_data.size());
// 	}
// 	if (with_check)
// 	{
// 		dog_torch::serialize::Data check = NSROOT::algorithmutils::get_sequence(this->config_.block_size);
// 		this->get_block_self_encryption()(check, this->config_.block_size, this->get_available_key(), this->get_key_size());
// 		crypt.write((char*)check.data(), check.size());
// 	}
// 	if (with_iv)
// 	{
// 		crypt.write((char*)iv.data(), this->config_.block_size);
// 	}
// 	this->stream_encryptp_(plain, iv, crypt, *this, mutex_, cond_, progress, running_, paused_, stop_);
// }

// dog_torch::serialize::Data NSROOT::algorithmCryptor::decrypt(dog_torch::serialize::Data crypt, bool with_config, bool with_iv, dog_torch::serialize::Data iv, bool with_check)
// {
// 	std::unique_ptr<NSROOT::algorithmCryptor> ori_cryptor;
// 	if (with_config)
// 	{
// 		ori_cryptor = std::make_unique<NSROOT::algorithmCryptor>(*this);
// 		NSROOT::algorithmCryptor temp_cryptor(NSROOT::algorithmCryptionConfig::get_cryption_config(crypt, true));
// 		this->swap_config(temp_cryptor);
// 	}
// 	if (!this->is_available())
// 	{
// 		throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:Cryptor config is invalid\n错误：Cryptor加密器配置无效"));
// 	}
// 	if (with_check)
// 	{
// 		dog_torch::serialize::Data crypt_check = crypt.sub_by_len(0, this->config_.block_size);
// 		crypt = crypt.sub_by_pos(this->config_.block_size, crypt.size());
// 		this->get_block_self_decryption()(crypt_check, this->config_.block_size, this->get_available_key(), this->get_key_size());
// 		dog_torch::serialize::Data plain_check = NSROOT::algorithmutils::get_sequence(this->config_.block_size);
// 		if (plain_check != crypt_check)
// 		{
// 			//throw CryptionException(DOG_EXCEPTION_MSG_OPINION("wrong key"));
// 			throw WrongKeyException(DOG_EXCEPTION_OPINION);
// 		}
// 	}
// 	dog_torch::serialize::Data res, iv_;
// 	if (with_iv)
// 	{
// 		iv_ = crypt.sub_by_len(0, this->config_.block_size);
// 		crypt = crypt.sub_by_pos(this->config_.block_size, crypt.size());
// 	}
// 	else
// 	{
// 		iv_ = iv;
// 	}
// 	res = this->mult_decrypt_(crypt, iv_, *this);
// 	if (with_config)
// 	{
// 		this->swap_config(*ori_cryptor);
// 	}
// 	return res;
// }
// void NSROOT::algorithmCryptor::decrypt(std::istream& crypt, std::ostream& plain, bool with_config, bool with_iv, dog_torch::serialize::Data iv, bool with_check)
// {
// 	std::unique_ptr<NSROOT::algorithmCryptionConfig> ori_config;
// 	if (with_config)
// 	{
// 		NSROOT::algorithmCryptionConfig config = NSROOT::algorithmCryptionConfig::get_cryption_config(crypt, false);
// 		ori_config = std::make_unique<NSROOT::algorithmCryptionConfig>(this->config_);
// 		this->config_ = config;
// 	}
// 	if (!this->is_available())
// 	{
// 		throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:Cryptor config is invalid\n错误：Cryptor加密器配置无效"));
// 	}
// 	if (with_check)
// 	{
// 		dog_torch::serialize::Data crypt_check(config_.block_size);
// 		crypt.read((char*)crypt_check.data(), crypt_check.size());
// 		this->get_block_self_decryption()(crypt_check, this->config_.block_size, this->get_available_key(), this->get_key_size());
// 		dog_torch::serialize::Data plain_check = NSROOT::algorithmutils::get_sequence(this->config_.block_size);
// 		if (plain_check != crypt_check)
// 		{
// 			//throw CryptionException(DOG_EXCEPTION_MSG_OPINION("wrong key"));
// 			throw WrongKeyException(DOG_EXCEPTION_OPINION);
// 		}
// 	}
// 	dog_torch::serialize::Data iv_(this->config_.block_size);
// 	if (with_iv)
// 	{
// 		crypt.read((char*)iv_.data(), this->config_.block_size);
// 	}
// 	else
// 	{
// 		iv_ = iv;
// 	}
// 	this->stream_decrypt_(crypt, iv, plain, *this);
// 	if (with_config)
// 	{
// 		this->config_ = *ori_config;
// 	}
// }
// void NSROOT::algorithmCryptor::decryptp(std::istream& crypt, std::ostream& plain, bool with_config, bool with_iv, dog_torch::serialize::Data iv, bool with_check,
// 	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
// {
// 	std::unique_ptr<NSROOT::algorithmCryptionConfig> ori_config;
// 	if (with_config)
// 	{
// 		NSROOT::algorithmCryptionConfig config = NSROOT::algorithmCryptionConfig::get_cryption_config(crypt, false);
// 		ori_config = std::make_unique<NSROOT::algorithmCryptionConfig>(this->config_);
// 		this->config_ = config;
// 	}
// 	if (!this->is_available())
// 	{
// 		throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:Cryptor config is invalid\n错误：Cryptor加密器配置无效"));
// 	}
// 	if (with_check)
// 	{
// 		dog_torch::serialize::Data crypt_check(config_.block_size);
// 		crypt.read((char*)crypt_check.data(), crypt_check.size());
// 		this->get_block_self_decryption()(crypt_check, this->config_.block_size, this->get_available_key(), this->get_key_size());
// 		dog_torch::serialize::Data plain_check = NSROOT::algorithmutils::get_sequence(this->config_.block_size);
// 		if (plain_check != crypt_check)
// 		{
// 			throw WrongKeyException(DOG_EXCEPTION_OPINION);
// 		}
// 	}
// 	dog_torch::serialize::Data iv_(this->config_.block_size);
// 	if (with_iv)
// 	{
// 		crypt.read((char*)iv_.data(), this->config_.block_size);
// 		if (iv_.size() < this->config_.block_size)
// 		{
// 			throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:iv size is too small\n错误：iv长度过小"));
// 		}
// 	}
// 	else
// 	{
// 		if (iv.size() < this->config_.block_size)
// 		{
//             throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:iv size is too small\n错误：iv长度过小"));
// 		}
// 		iv_ = iv;
// 	}
// 	this->stream_decryptp_(crypt, iv_, plain, *this, mutex_, cond_, progress, running_, paused_, stop_);
// 	if (with_config)
// 	{
// 		this->config_ = *ori_config;
// 	}
// }

// #undef NSROOT