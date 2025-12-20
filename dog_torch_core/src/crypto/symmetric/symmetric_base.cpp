#include "crypto/symmetric/symmetric_base.h"

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
NSROOT::padding::padding_func NSROOT::padding::Padding::get_padding() const
{
	return [](Data&, uint64_t) -> void {};
}
NSROOT::padding::padding_func NSROOT::padding::Padding::get_unpadding() const
{
	return [](Data&, uint64_t) -> void {};
}

std::string NSROOT::mode::Mode::fmt_config() const
{
	return std::format("{}_{}_{}",
		this->name,
		this->using_iv ? "UsingIV" : "NotUsingIV",
		this->using_padding ? "UsingPadding" : "NotUsingPadding"
	);
}
DOG_DATA NSROOT::mode::Mode::to_data() const
{
	using namespace dog_torch::serialize;
	uint64_t size = 3;
	Data res = tlv::integer_num(size);
	res += tlv::string(this->name);
	res += tlv::boolean(this->using_iv);
	res += tlv::boolean(this->using_padding);
	return res;
}
bool NSROOT::mode::Mode::get_using_iv() const
{
	return this->using_iv;
}
bool NSROOT::mode::Mode::get_using_padding() const
{
	return this->using_padding;
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

DOG_DATA NSROOT::CryptionConfig::to_data() const
{
	return this->algorithm_.to_data() + this->mode_.to_data() + (this->mode_.get_using_padding() ? this->padding_.to_data() : Data());
}
std::string NSROOT::CryptionConfig::to_string() const
{
	return this->algorithm_.fmt_config() + "_" + this->mode_.fmt_config() + (this->mode_.get_using_padding() ? "_" + this->padding_.fmt_config() : "");
}

dog_torch::crypto::symmetric::Cryptor::Cryptor(const algorithm::Algorithm& algorithm, const mode::Mode& mode, const padding::Padding& padding) :
	config_(algorithm, mode, padding)
{
	if (mode.get_using_padding() && typeid(padding) == typeid(padding::Padding))
	{
		throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:padding is not set or padding is invalid\n错误：填充未设置或填充无效"));
	}
}

void NSROOT::Cryptor::set_key(Data key)
{
	this->original_key_   = key;
	this->available_key_  = this->config_.algorithm_.get_extend_key()(key, this->config_.algorithm_.get_block_size(), this->config_.algorithm_.get_key_size());
	this->is_setting_key_ = true;
}
bool dog_torch::crypto::symmetric::Cryptor::is_available() const
{
 	if (!this->is_setting_key_)
 	{
 		throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:encrypt key is not set or key is invalid\n错误：加密密钥未设置或密钥无效"));
 	}
 	return true;
}
void NSROOT::Cryptor::swap(const Cryptor& other)
{
	this->config_          = other.config_;
	this->is_setting_key_  = other.is_setting_key_;
	this->original_key_    = other.original_key_;
	this->available_key_   = other.available_key_;
}
void NSROOT::Cryptor::swap_config(const Cryptor& other)
{
	this->config_             = other.config_;
	this->is_setting_key_     = other.is_setting_key_;
	this->available_key_      = this->config_.algorithm_.get_extend_key()(this->original_key_, this->config_.algorithm_.get_block_size(), this->config_.algorithm_.get_key_size());
}
uint64_t NSROOT::Cryptor::get_block_size() const
{
	return this->config_.algorithm_.get_block_size();
}
uint64_t NSROOT::Cryptor::get_key_size() const
{
	return this->config_.algorithm_.get_key_size();
}
bool NSROOT::Cryptor::get_using_iv() const
{
	return this->config_.mode_.get_using_iv();
}
bool NSROOT::Cryptor::get_using_padding() const
{
	return this->config_.mode_.get_using_padding();
}
DOG_DATA& dog_torch::crypto::symmetric::Cryptor::get_original_key()
{
	return this->original_key_;
}
DOG_DATA& dog_torch::crypto::symmetric::Cryptor::get_available_key()
{
	return this->available_key_;
}
DOG_DATA NSROOT::Cryptor::get_original_key() const
{
	return this->original_key_;
}
DOG_DATA NSROOT::Cryptor::get_available_key() const
{
	return this->available_key_;
}
NSROOT::padding::padding_func NSROOT::Cryptor::get_padding() const
{
	return this->config_.padding_.get_padding();
}
NSROOT::padding::padding_func NSROOT::Cryptor::get_unpadding() const
{
	return this->config_.padding_.get_unpadding();
}
NSROOT::algorithm::block_self_cryption_func NSROOT::Cryptor::get_block_self_encryption() const
{
	return this->config_.algorithm_.get_encrypt_self();
}
NSROOT::algorithm::block_self_cryption_func NSROOT::Cryptor::get_block_self_decryption() const
{
	return this->config_.algorithm_.get_decrypt_self();
}
NSROOT::algorithm::block_cryption_func NSROOT::Cryptor::get_block_encryption() const
{
	return this->config_.algorithm_.get_encrypt();
}
NSROOT::algorithm::block_cryption_func NSROOT::Cryptor::get_block_decryption() const
{
	return this->config_.algorithm_.get_decrypt();
}

const NSROOT::algorithm::Algorithm& NSROOT::Cryptor::get_algorithm() const
{
	return this->config_.algorithm_;
}
const NSROOT::padding::Padding& NSROOT::Cryptor::get_paddion() const
{
	return this->config_.padding_;
}
const NSROOT::mode::Mode& NSROOT::Cryptor::get_mode() const
{
	return this->config_.mode_;
}

DOG_DATA NSROOT::Cryptor::encrypt(const Data& plain, bool with_config, bool with_iv, const Data& iv, bool with_check)
{
 	dog_torch::serialize::Data res;
	this->is_available();
 	if (with_config)
 	{
 		//res += this->config_.to_data();
 	}
 	if (with_check)
 	{
 		dog_torch::serialize::Data check = NSROOT::utils::get_sequence(this->config_.algorithm_.get_block_size());
 		this->get_block_self_encryption()(check, this->config_.algorithm_.get_block_size(), this->get_available_key(), this->get_key_size());
 		res += check;
 	}
 	if (with_iv)
 	{
 		res += iv.sub_by_len(0, this->config_.algorithm_.get_block_size());
 	}
 	res += this->config_.mode_.get_mult_encrypt()(plain, iv, *this);
 	return res;
}
void NSROOT::Cryptor::encrypt(std::istream& plain, std::ostream& crypt, bool with_config, bool with_iv, const Data& iv, bool with_check)
{
 	if (with_config)
 	{
 		//dog_torch::serialize::Data config_data = this->config_.to_data();
 		//crypt.write((char*)config_data.data(), config_data.size());
 	}
 	if (with_check)
 	{
 		dog_torch::serialize::Data check = NSROOT::utils::get_sequence(this->config_.algorithm_.get_block_size());
 		this->get_block_self_encryption()(check, this->config_.algorithm_.get_block_size(), this->get_available_key(), this->get_key_size());
 		crypt.write((char*)check.data(), check.size());
 	}
 	if (with_iv)
 	{
 		crypt.write((char*)iv.data(), this->config_.algorithm_.get_block_size());
 	}
 	this->config_.mode_.get_stream_encrypt()(plain, iv, crypt, *this);
}
void NSROOT::Cryptor::encryptp(std::istream& plain, std::ostream& crypt, bool with_config, bool with_iv, const Data& iv, bool with_check, std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
}
DOG_DATA NSROOT::Cryptor::decrypt(const Data& crypt, bool with_config, bool with_iv, const Data& iv, bool with_check)
{
	return Data();
}
void NSROOT::Cryptor::decrypt(std::istream& crypt, std::ostream& plain, bool with_config, bool with_iv, const Data& iv, bool with_check)
{
}
void NSROOT::Cryptor::decryptp(std::istream& plain, std::ostream& crypt, bool with_config, bool with_iv, const Data& iv, bool with_check, std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
}

#undef NSROOT
#undef DOG_DATA


