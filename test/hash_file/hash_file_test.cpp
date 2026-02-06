#include "dog_torch.h"

#include <iostream>
#include <fstream>
#include <filesystem>

char HexList[17] = "0123456789ABCDEF";

struct Result
{
    std::string name;
    std::string start_time;
    std::string end_time;
    double total_time;
    Result(std::string name, 
        std::string start_time, 
        std::string end_time, 
        double total_time) :
        name(name), start_time(start_time), end_time(end_time), total_time(total_time) 
    {}
};

dog_torch::asyncion::container::VectorMove<Result> result_vec;

void log(std::string msg)
{
    static std::mutex log_mutex;
    std::lock_guard<std::mutex> lock(log_mutex);
    static std::ofstream log_file("log.txt", std::ios::app);
    std::cout << msg << std::endl;
    log_file << msg << std::endl;
    log_file.flush();
}

std::string fmt_now_time()
{
    return std::format("{:%Y-%m-%d %H:%M:%S}", std::chrono::zoned_time{ std::chrono::current_zone(), std::chrono::system_clock::now() });
}

int row = 16;

void doing(std::unique_ptr<dog_torch::crypto::hash::algorithm::Hash> hasher)
{
    using dog_torch::serialize::BinaryData;
    using dog_torch::asyncion::Clock;
    dog_torch::crypto::hash::HashGenerator hasher_gen(*hasher);
    std::ifstream file("plain.txt");
    std::string config = std::format("{}-{}", hasher->get_name(), hasher->get_effective());
    std::ofstream result_file(std::format("{}.txt", config));
    std::string line;

    Clock<std::chrono::milliseconds> clock;
    clock.start();
    clock.pause();

    std::string start_time = fmt_now_time();
    while (std::getline(file, line))
    {
        BinaryData data(line);

        clock.resume();
        data = hasher_gen.calculate(data);
        clock.pause();

        result_file << data.to_hex_string() << std::endl;
        
    }
    clock.stop();
    std::string end_time = fmt_now_time();
    result_file << std::format("start:{} end:{} spend:{}ms", start_time, end_time, clock.get_cost()) << std::endl;

    result_vec.emplace_back({ config,start_time,end_time,clock.get_cost() });
}

int main()
{
    std::random_device rd;
    std::ofstream file("plain.txt");
    for (int i = 0; i < row; i++)
    {
        std::string line;
        for (int j = 0; j < row; j++)
        {
            line += HexList[rd() % 16];
        }
        file << line << std::endl;
    }
	try
	{
        using namespace dog_torch::crypto::hash::algorithm;
        dog_torch::asyncion::pool::ThreadPool thread_pool(4);
        thread_pool.add_task(doing, SHA2(256 / 8).clone());
        thread_pool.add_task(doing, SHA2(224 / 8).clone());
        thread_pool.add_task(doing, SHA2(384 / 8).clone());
        thread_pool.add_task(doing, SHA2(512 / 8).clone());
        thread_pool.add_task(doing, SM3(256 / 8).clone());

        thread_pool.wait_complete();

        result_vec.doing([](std::vector<Result> in)->void
            {
                for (const auto& result : in)
                {
                    std::cout << std::format("{} start:{} end:{} spend:{}ms",
                        result.name, result.start_time, result.end_time, result.total_time) << std::endl;
                }
            });
	}
	catch (const std::exception& e)
	{
		std::cout << e.what() << std::endl;
	}

}