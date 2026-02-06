#include "dog_torch.h"

#include <iostream>
#include <fstream>
#include <filesystem>

uint32_t OScode()
{
#if __APPLE__
#include <TargetConditionals.h>
#if TARGET_OS_IPHONE && TARGET_IPHONE_SIMULATOR
    return 0;// iPhone Simulator iPhone模拟器
#elif TARGET_OS_IPHONE
    return 1;// iPhone iPhone手机
#elif TARGET_OS_MAC
    return 2;// Mac OS MacOS
#else
    return 3;// Other Mac OS
#endif
#elif _WIN32
#ifdef _WIN64
    return 4;// Windows 64 bit 64位Windows
#else
    return 5;// Windows 32 bit 32位Windows
#endif
#elif __linux__
    return 6;// Linux Linux系统
#elif __unix__
    return 7;// Unix Unix系统
#else
    return 8;// Other 其他系统
#endif
    return -1;
}

char HexList[17] = "0123456789ABCDEF";

struct Result
{
    std::string name;
    std::string start_time;
    std::string end_time;
    uint64_t total_time;
    Result(std::string name,
        std::string start_time,
        std::string end_time,
        uint64_t total_time) :
        name(name), start_time(start_time), end_time(end_time), total_time(total_time)
    {
    }
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

void doing(const dog_torch::crypto::hash::algorithm::Hash& hasher)
{
    std::string config = std::format("{}-{}", hasher.get_name(), hasher.get_effective());
    try
    {
        using dog_torch::serialize::BinaryData;
        using dog_torch::asyncion::Clock;
        dog_torch::crypto::hash::HashGenerator hasher_gen(hasher);
        std::ifstream file("plain.txt");
        std::ofstream result_file(std::format("{}.txt", config));
        std::string line;

        Clock<std::chrono::milliseconds> clock;
        clock.start();
        clock.pause();
        uint64_t i = 1;
        std::string start_time = fmt_now_time();
        while (std::getline(file, line))
        {
            BinaryData data = line;
            std::cout << std::format("{} {}", config, i) << std::endl;
            i++;
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
    catch (std::exception& e)
    {
        log(std::format("{}:error:{}\n", config, e.what()));
    }

}

int main()
{
    std::cout <<
R"(测试算法：
SHA2-256 SHA2-224 SHA2-384 SHA2-512 SM3-256
Hash:
SHA2-256 SHA2-224 SHA2-384 SHA2-512 SM3-256)"
        << std::endl;
    std::cout << R"(注意事项:
    本软件旨在测试分组散列函数的性能 准确性等参数
    运行时会占用计算机的部分资源
    可能会对计算机的运行速度产生一定影响
    如果您还想继续测试 请输入任意键继续 反之则直接关闭
    测试前请确保您的文件系统大小写敏感)" << std::endl;
    std::cout << R"(Warning:
    this script is used to be test the speed and accuracy of the block cipher mode
    there will be some resources of PC used
    It may make the computer slower than normal
    If you want to continue,please press any key,otherwise,close directly
    make sure you filesystem is case sensitive before running)" << std::endl;
    std::cin.get();

    std::cout << R"(本测试项目将生成 1B-nB 的测试数据 n默认为16B 你可以在下面指定最后的测试数据大小 下面有一个示例)" << std::endl;
    std::cout << R"(this test will create the binary with the size of 1B-nB. n is default 16.you can input anohter number. there is an example)" << std::endl;

    std::cout << R"( n == 3;
01
0123
012345
)" << std::endl;

    std::cout << R"(请输入n(默认为16B))" << std::endl;
    std::cout << R"(please input n (default 16))" << std::endl;

    std::string num_str;

    std::cin >> num_str;

    try
    {
        row = std::stoull(num_str);
    }
    catch (std::exception& e)
    {
        row = 16;
        std::cout << R"(无效输入! n将使用16)" << std::endl;
        std::cout << R"(inavalid input.n will use 16)" << std::endl;
    }


    char is_off;

    std::cout << "测试完成后自动关机?[y/n]" << std::endl;
    std::cout << "power off after running?[y/n]" << std::endl;

    std::cin >> is_off;


    std::random_device rd;
    std::ofstream file("plain.txt");
    for (int i = 0; i < row; i++)
    {
        std::string line;
        for (int j = 0; j < i; j++)
        {
            line += HexList[rd() % 16];
            line += HexList[rd() % 16];
        }
        file << line << std::endl;
    }
    std::cout << "random data generated" << std::endl;
    try
    {
        using namespace dog_torch::crypto::hash::algorithm;
        dog_torch::asyncion::pool::PollingTaskPool thread_pool(5);
        thread_pool.add_task(doing, SHA2(256 / 8));
        thread_pool.add_task(doing, SHA2(224 / 8));
        thread_pool.add_task(doing, SHA2(384 / 8));
        thread_pool.add_task(doing, SHA2(512 / 8));
        thread_pool.add_task(doing, SM3(256 / 8));
        thread_pool.start();

        thread_pool.wait_complete();

    }
    catch (const std::exception& e)
    {
        std::cout << e.what() << std::endl;
    }

    std::ofstream results_txt("./result.txt");

    result_vec.doing([&results_txt](std::vector<Result> vec)->void
        {
            for (auto& item : vec)
            {
                std::cout << std::format("name:{} start at:{} end:at {} total:{}ms",
                    item.name, item.start_time, item.end_time, item.total_time) << std::endl;
                results_txt << std::format("name:{} start at:{} end:at {} total:{}ms",
                    item.name, item.start_time, item.end_time, item.total_time) << std::endl;
            }
        }
    );

    results_txt.close();

    if (is_off == 'y' || is_off == 'Y')
    {
        if (OScode() == 4)
        {
            system("shutdown /s /t 0");
        }
        else if (OScode() == 6)
        {
            system("shutdown -s -t 0");
        }
    }

}