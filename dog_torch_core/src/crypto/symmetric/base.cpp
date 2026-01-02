#include "crypto/symmetric/base.h"

#define NSROOT dog_torch::crypto::symmetric //NSROOT = namespace root
#define DOG_DATA dog_torch::serialize::Data

//utils
uint8_t NSROOT::utils::rand_byte()
{
	std::random_device rd;
	return (uint8_t)rd() % 128;
}
DOG_DATA NSROOT::utils::squareXOR(const dog_torch::serialize::Data& a, const dog_torch::serialize::Data& b, uint64_t size)
{
	dog_torch::serialize::Data res;
	res.reserve(size);
	uint64_t n = a.size() < b.size() ? a.size() : b.size();
	for (uint64_t i = 0; i < (n > size ? size : n); i++)
	{
		res.push_back(a.at(i) ^ b.at(i));
	}
	return res;
}
void NSROOT::utils::squareXOR_self(dog_torch::serialize::Data& a, dog_torch::serialize::Data& b, uint64_t size)
{
	uint64_t n = a.size() < b.size() ? a.size() : b.size();
	for (uint64_t i = 0; i < (n > size ? size : n); i++)
	{
		a[i] ^= b[i];
	}
}
DOG_DATA NSROOT::utils::randiv(uint8_t block_size)
{
	dog_torch::serialize::Data iv(block_size);
	for (int i = 0; i < block_size; i++)
	{
		iv[i] = NSROOT::utils::rand_byte();
	}
	return iv;
}
DOG_DATA NSROOT::utils::get_sequence(uint64_t lenght)
{
	dog_torch::serialize::Data res(lenght);
	uint8_t list[8] = { 0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF };
	for (uint64_t i = 0; i < lenght; i++)
	{
		res[i] = list[i % 8];
	}
	return res;
}

std::unique_ptr<NSROOT::algorithm::Algorithm> NSROOT::algorithm::Algorithm::clone() const
{
	return std::move(std::make_unique<Algorithm>(*this));
}

DOG_DATA NSROOT::algorithm::Algorithm::to_data() const
{
	using namespace dog_torch::serialize;
	uint64_t size = 3;
	Data res = tlv::integer_num(size);
	res += tlv::string(this->name);
	res += tlv::integer_num(this->block_size);
	res += tlv::integer_num(this->key_size);
	return res;
}

std::string NSROOT::algorithm::Algorithm::fmt_config() const
{
	return std::format("{}_{}_{}", name, key_size, block_size);
}
std::string NSROOT::algorithm::Algorithm::get_name() const
{
	return this->name;
}
uint64_t NSROOT::algorithm::Algorithm::get_block_size() const
{
	return this->block_size;
}
uint64_t NSROOT::algorithm::Algorithm::get_key_size() const
{
	return this->key_size;
}
NSROOT::algorithm::extend_key_func NSROOT::algorithm::Algorithm::get_extend_key() const
{
	return [](const Data&, uint64_t, uint64_t) -> Data {return ""; };
}
NSROOT::algorithm::block_cryption_func NSROOT::algorithm::Algorithm::get_encrypt() const
{
	return [](const Data&, uint64_t, const Data&, uint64_t) -> Data {return ""; };
}
NSROOT::algorithm::block_cryption_func NSROOT::algorithm::Algorithm::get_decrypt() const
{
	return [](const Data&, uint64_t, const Data&, uint64_t) -> Data {return ""; };
}
NSROOT::algorithm::block_self_cryption_func NSROOT::algorithm::Algorithm::get_encrypt_self() const
{
	return [](Data&, uint64_t, const Data&, uint64_t) -> void {};
}
NSROOT::algorithm::block_self_cryption_func NSROOT::algorithm::Algorithm::get_decrypt_self() const
{
	return [](Data&, uint64_t, const Data&, uint64_t) -> void {};
}

NSROOT::padding::Padding::Padding(const std::string& name)
{
	this->name = name;
}
NSROOT::padding::Padding::Padding()
{
	this->name = "None";
}
std::unique_ptr<NSROOT::padding::Padding> NSROOT::padding::Padding::clone() const
{
	return std::move(std::make_unique<Padding>(*this));
}
DOG_DATA NSROOT::padding::Padding::to_data() const
{
	using namespace dog_torch::serialize;
	uint64_t size = 1;
	Data res = tlv::integer_num(size);
	res += tlv::string(this->name);
	return res;
}
std::string NSROOT::padding::Padding::fmt_config() const
{
	return "None";
}
std::string NSROOT::padding::Padding::get_name() const
{
	return this->name;
}
NSROOT::padding::padding_func NSROOT::padding::Padding::get_padding() const
{
	return [](Data&, uint64_t) -> void {};
}
NSROOT::padding::padding_func NSROOT::padding::Padding::get_unpadding() const
{
	return [](Data&, uint64_t) -> void {};
}

std::unique_ptr<NSROOT::mode::Mode> NSROOT::mode::Mode::clone() const
{
	return std::move(std::make_unique<Mode>(*this));
}

std::string NSROOT::mode::Mode::fmt_config() const
{
	return this->name;
}
DOG_DATA NSROOT::mode::Mode::to_data() const
{
	using namespace dog_torch::serialize;
	uint64_t size = 1;
	Data res = tlv::integer_num(size);
	res += tlv::string(this->name);
	return res;
}
NSROOT::mode::crypt_func NSROOT::mode::Mode::get_mult_encrypt() const
{
	return crypt_func();
}
NSROOT::mode::crypt_func NSROOT::mode::Mode::get_mult_decrypt() const
{
	return crypt_func();
}
NSROOT::mode::stream_crypt_func NSROOT::mode::Mode::get_stream_encrypt() const
{
	return stream_crypt_func();
}
NSROOT::mode::stream_crypt_func NSROOT::mode::Mode::get_stream_decrypt() const
{
	return stream_crypt_func();
}
NSROOT::mode::stream_cryptp_func NSROOT::mode::Mode::get_stream_encryptp() const
{
	return stream_cryptp_func();
}
NSROOT::mode::stream_cryptp_func NSROOT::mode::Mode::get_stream_decryptp() const
{
	return stream_cryptp_func();
}
double NSROOT::mode::update_progress(double progress, double progress_step, double progress_max)
{
	return progress + progress_step * 1.0 / progress_max;
}


NSROOT::CryptionConfig::CryptionConfig(const algorithm::Algorithm& algorithm, const mode::Mode& mode)
	: algorithm_(algorithm.clone()), mode_(mode.clone())
{
	//2025.12.28 20:57 发现加密模式是空指针 一看构造函数没有构造 给我气笑了
}

NSROOT::CryptionConfig::CryptionConfig(const CryptionConfig& other)
{
	this->algorithm_ = other.algorithm_->clone();
	this->mode_      = other.mode_->clone();
}

NSROOT::CryptionConfig::CryptionConfig(CryptionConfig&& other)
{
	this->algorithm_ = std::move(other.algorithm_);
	this->mode_      = std::move(other.mode_);
}

void NSROOT::CryptionConfig::swap(CryptionConfig& other)
{
	this->algorithm_.swap(other.algorithm_);
	this->mode_.swap(other.mode_);
}

DOG_DATA NSROOT::CryptionConfig::to_data() const
{
	return this->algorithm_->to_data() + this->mode_->to_data();
}
std::string NSROOT::CryptionConfig::to_string() const
{
	return this->algorithm_->fmt_config() + "_" + this->mode_->fmt_config();
}

NSROOT::Cipher::Cipher(const algorithm::Algorithm& algorithm, const mode::Mode& mode) 
	: config_(algorithm, mode)
{

}

NSROOT::Cipher::Cipher(const Cipher& other) : config_(other.config_)
{
	this->original_key_   = other.original_key_;
	this->available_key_ = other.available_key_;
	this->is_setting_key_ = other.is_setting_key_;
}

dog_torch::crypto::symmetric::Cipher::Cipher(Cipher&& other) : config_(std::move(other.config_))
{
	this->original_key_ = std::move(other.original_key_);
	this->available_key_ = std::move(other.available_key_);
	this->is_setting_key_ = other.is_setting_key_;
}

void NSROOT::Cipher::set_key(Data key)
{
	this->original_key_   = key;
	this->available_key_  = this->config_.algorithm_->get_extend_key()(key, this->config_.algorithm_->get_block_size(), this->config_.algorithm_->get_key_size());
	this->is_setting_key_ = true;
}
bool NSROOT::Cipher::is_available() const
{
 	if (!this->is_setting_key_)
 	{
 		throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:encrypt key is not set or key is invalid\n错误：加密密钥未设置或密钥无效"));
 	}
 	return true;
}
void NSROOT::Cipher::swap(Cipher& other)
{
	other.config_.swap(this->config_);
	std::swap(this->original_key_, other.original_key_);
	std::swap(this->available_key_, other.available_key_);
	std::swap(this->is_setting_key_, other.is_setting_key_);
}
void NSROOT::Cipher::swap_config(Cipher& other)
{
	other.config_.swap(this->config_);
	if (this->is_setting_key_)
	{
		this->available_key_ = this->config_.algorithm_->get_extend_key()(this->original_key_, this->config_.algorithm_->get_block_size(), this->config_.algorithm_->get_key_size());
	}
}
uint64_t NSROOT::Cipher::get_block_size() const
{
	return this->config_.algorithm_->get_block_size();
}
uint64_t NSROOT::Cipher::get_key_size() const
{
	return this->config_.algorithm_->get_key_size();
}
DOG_DATA& NSROOT::Cipher::get_original_key()
{
	return this->original_key_;
}
DOG_DATA& NSROOT::Cipher::get_available_key()
{
	return this->available_key_;
}
const DOG_DATA& NSROOT::Cipher::get_original_key() const
{
	return this->original_key_;
}
const DOG_DATA& NSROOT::Cipher::get_available_key() const
{
	return this->available_key_;
}
const NSROOT::algorithm::block_self_cryption_func NSROOT::Cipher::get_block_self_encryption() const
{
	return this->config_.algorithm_->get_encrypt_self();
}
const NSROOT::algorithm::block_self_cryption_func NSROOT::Cipher::get_block_self_decryption() const
{
	return this->config_.algorithm_->get_decrypt_self();
}
const NSROOT::algorithm::block_cryption_func NSROOT::Cipher::get_block_encryption() const
{
	return this->config_.algorithm_->get_encrypt();
}
const NSROOT::algorithm::block_cryption_func NSROOT::Cipher::get_block_decryption() const
{
	return this->config_.algorithm_->get_decrypt();
}
NSROOT::algorithm::block_self_cryption_func NSROOT::Cipher::get_block_self_encryption()
{
	return this->config_.algorithm_->get_encrypt_self();
}
NSROOT::algorithm::block_self_cryption_func NSROOT::Cipher::get_block_self_decryption()
{
	return this->config_.algorithm_->get_decrypt_self();
}
NSROOT::algorithm::block_cryption_func NSROOT::Cipher::get_block_encryption()
{
	return this->config_.algorithm_->get_encrypt();
}
NSROOT::algorithm::block_cryption_func NSROOT::Cipher::get_block_decryption()
{
	return this->config_.algorithm_->get_decrypt();
}
DOG_DATA dog_torch::crypto::symmetric::Cipher::to_data() const
{
	return this->config_.to_data();
}
std::string dog_torch::crypto::symmetric::Cipher::to_string() const
{
	return this->config_.to_string();
}
const NSROOT::algorithm::Algorithm& NSROOT::Cipher::get_algorithm() const
{
	return *this->config_.algorithm_;
}
const NSROOT::mode::Mode& NSROOT::Cipher::get_mode() const
{
	return *this->config_.mode_;
}
NSROOT::algorithm::Algorithm& NSROOT::Cipher::get_algorithm()
{
	return *this->config_.algorithm_;
}
NSROOT::mode::Mode& NSROOT::Cipher::get_mode()
{
	return *this->config_.mode_;
}

DOG_DATA NSROOT::Cipher::encrypt(const Data& plain)
{//only for test
	return this->config_.mode_->get_mult_encrypt()(plain, *this);
}
DOG_DATA NSROOT::Cipher::decrypt(const Data& crypt)
{//only for test
	return this->config_.mode_->get_mult_decrypt()(crypt, *this);
}


#undef NSROOT
#undef DOG_DATA


