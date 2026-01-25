#include <chrono>
#include <filesystem>
#include <format>
#include <fstream>
#include <future>
#include <iostream>
#include <print>
#include <unordered_set>
#include <coroutine>
#include <cmath>

//#include <crtdbg.h>
//#define _CRTDBG_MAP_ALLOC
//#define _DEBUG
//_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

#include "crypto/symmetric/algorithm/algorithm.h"
#include "crypto/symmetric/mode/mode.h"
#include "crypto/symmetric/padding/padding.h"
#include "crypto/symmetric/symmetric.h"
#include "asyncion/coroutine/coroutine.h"
#include "asyncion/asyncion.h"
#include "asyncion/pool/PausedThreadPool.h"
#include "asyncion/thread/thread.h"
#include "crypto/hash/algorithm/algorithm.h"

using dog_torch::asyncion::thread::PauseableChannel;
using dog_torch::serialize::BinaryData;
using dog_torch::crypto::symmetric::Cipher;
using dog_torch::crypto::symmetric::algorithm::AES;
using dog_torch::crypto::symmetric::mode::CBC;
using dog_torch::crypto::symmetric::mode::CTR;
using dog_torch::crypto::symmetric::padding::PKCS7;

using dog_torch::asyncion::pool::PausedThreadPool;

void controller(PausedThreadPool& pool)
{
	char op = '0';
	while (true)
	{
		std::cin >> op;
		if (op == 'd')
		{
			auto display = pool.get_tasks_detail();
			for (auto& item : display)
			{
				uint64_t task_id = item.first;
				dog_torch::asyncion::State status = item.second.state;
				std::string status_str = dog_torch::asyncion::State_to_str(status);
				double progress = item.second.progress;
				uint64_t cost = item.second.cost;
				std::string cost_str = dog_torch::asyncion::Clock<std::chrono::milliseconds>::iso_fmt_cost(cost);
				uint64_t except = cost / progress - cost;
				std::string except_str = dog_torch::asyncion::Clock<std::chrono::milliseconds>::iso_fmt_cost(except);
				std::cout << std::format("--------\ntask id: {}\nstatus: {}\nprogress: {:.2f}%\ncost: {}\nexcept: {}",
					task_id, status_str, progress * 100, cost_str, except_str) << std::endl;
			}
		}
		else if (op == 'p')
		{
			uint64_t task_id = 0;
			std::cin >> task_id;
			pool.pause(task_id);
		}
		else if (op == 'r')
		{
			uint64_t task_id = 0;
			std::cin >> task_id;
			pool.resume(task_id);
		}
		else if (op == 's')
		{
			uint64_t task_id = 0;
			std::cin >> task_id;
			pool.stop(task_id);
		}
		else if (op == 'e')
		{
			return;
		}
	}
}


int main()
{
	//PauseableChannel pc;
	//uint64_t max = std::filesystem::file_size(std::filesystem::path("E:\\电影\\阳光电影dygod.org.茶啊二中.2023.BD.1080P.国语中字.mkv"));
	//std::ifstream plain("E:\\电影\\阳光电影dygod.org.茶啊二中.2023.BD.1080P.国语中字.mkv", std::ios::binary);
	//std::ofstream crypt("E:\\电影\\阳光电影dygod.org.茶啊二中.2023.BD.1080P.国语中字.mkv.enc", std::ios::binary);
	//
	//BinaryData key = "0123456789ABCDEF0123456789ABCDEF";
	//BinaryData iv_ = "0123456789ABCDEF0123456789ABCDEF";
	
    auto algorithmList = dog_torch::crypto::symmetric::algorithm::get_all_algorithms();
	auto paddingList = dog_torch::crypto::symmetric::padding::PaddingList;
	auto modeList = dog_torch::crypto::symmetric::mode::ModeList;

	for (auto& [name, block, key] : algorithmList)
	{
		std::cout << std::format("{}=[{}]=[{}]", name, block, key) << std::endl;
	}
	for (auto& padding : paddingList)
	{
		std::cout << padding->get_name() << std::endl;
	}
	for (auto& mode : modeList)
	{
		std::cout << mode.name << std::endl;
		for (auto& [name,type] : mode.params)
		{
			std::cout << std::format("{}:{} ", name, type);
		}
		std::cout << std::endl;
	}

	auto hashs = dog_torch::crypto::hash::algorithm::get_all_algorithms();
	for (auto& [name, region] : hashs)
	{
		std::cout << std::format("{}=[{}]", name, region) << std::endl;
	}

	//PausedThreadPool pool(8);

	//Cipher cipher(AES(16), CTR(PKCS7(), iv_));
	//cipher.set_key(key);
	//auto func = cipher.get_mode().get_streamp_encrypt();
	//auto promise = pool.add_task(func, std::ref(plain), max, std::ref(crypt), std::ref(cipher.get_available_key()), std::ref(cipher.get_algorithm()));
	//std::cout << promise.first << std::endl;
	//pool.start();
	//std::thread test(controller, std::ref(pool));
	//test.join();
}