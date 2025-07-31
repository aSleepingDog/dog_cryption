#include "../lib/dog_cryption.h"
#include "../extend/util.h"

#include <iostream>
#include <print>
#include <fstream>
#include <format>

int main()
{
	//dog_cryption::CryptionConfig c("AES", 16, 32, true, "PKCS7", "PCBC", true, 16);
	//dog_cryption::Cryptor cryptor(c);
	//dog_data::Data plain = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
	//cryptor.set_key(plain);
	//dog_data::Data crypt = cryptor.encrypt(plain, false, false, plain, false);
	//dog_data::print::space(crypt);
	//std::cout << std::endl;
	//plain = cryptor.decrypt(crypt, false, false, plain, false);
	//dog_data::print::space(plain);

	//std::cout << typeid(work::hash_running).name() << std::endl;
	//std::cout << typeid(work::encrypt_running).name() << std::endl;
	//std::cout << typeid(work::decrypt_running).name() << std::endl;
	//std::cout << (typeid(work::encrypt_running) == typeid(work::decrypt_running)) << std::endl;

	work::TaskPool task_pool = work::TaskPool(4);
	std::string path = "E:/project/1.29/x64/Debug/1.29.exe";
	dog_hash::HashCrypher hash_crypher("SHA2", 32);
	task_pool.add_hash(path, hash_crypher);
	std::this_thread::sleep_for(std::chrono::seconds(30));
	task_pool.get_running_task_info();

	return 0;
}

