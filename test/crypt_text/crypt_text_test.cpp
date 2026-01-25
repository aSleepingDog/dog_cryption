/*
* 使用AES 16B密钥长度 必要时PKCS7填充 使用文本测试各个加密模式
* ECB CBC PCBC CFBB(1 10 16) CFBb(1 10) OFB CTR
*/

#include <chrono>
#include <filesystem>
#include <format>
#include <fstream>
#include <future>
#include <iostream>
#include <print>
#include <shared_mutex>

#include <cmath>

#include "crypto/symmetric/algorithm/Rijndael.h"
#include "crypto/symmetric/symmetric.h"
#include "crypto/symmetric/mode/CBC.h"
#include "crypto/symmetric/mode/CFB.h"
#include "crypto/symmetric/mode/CTR.h"
#include "crypto/symmetric/mode/ECB.h"
#include "crypto/symmetric/mode/OFB.h"
#include "crypto/symmetric/mode/PCBC.h"
#include "crypto/symmetric/padding/PKCS7.h"

#include "asyncion/pool/PollingTaskPool.h"

//#include <crtdbg.h>
//#define _CRTDBG_MAP_ALLOC
//#define _DEBUG
//_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

uint64_t row = 16;

struct Result
{
    std::string name;
    std::string start_time;
    std::string end_time;
    double encrypt_time;
    double decrypt_time;
    uint64_t failure_time;
    Result(std::string name, std::string start_time, std::string end_time, double encrypt_time, double decrypt_time, uint64_t failure_time) :
        name(name), start_time(start_time), end_time(end_time), encrypt_time(encrypt_time), decrypt_time(decrypt_time), failure_time(failure_time) {}
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
void doing(const dog_torch::crypto::symmetric::mode::Mode& mode)
{
    double encrypt_time = 0.0;
    double decrypt_time = 0.0;
    uint64_t failure_time = 0;
    auto start = std::chrono::steady_clock::now();
    std::string start_time = fmt_now_time();
    try
    {
        log(std::format("[{}] {} start\n", start_time, mode.fmt_config()));
        using namespace dog_torch::crypto::symmetric;
        using namespace dog_torch::crypto::symmetric::algorithm;
        using namespace dog_torch::crypto::symmetric::mode;
        using namespace dog_torch::crypto::symmetric::padding;

        std::ifstream plain_stream("plain.txt");
        std::ifstream key_stream("key.txt");
        std::ifstream iv_stream("iv.txt");

        std::string plain_str;
        std::string key_str;
        std::string iv_str;

        Data plain_data;
        Data key_data;
        Data iv_data;

        Cipher cipher(AES(16), mode);
        std::filesystem::path target_dir = std::filesystem::path(".") / cipher.to_string();
        std::filesystem::create_directory(target_dir);
        std::ofstream crypt_stream(target_dir / "crypt.txt");
        std::ofstream plain_stream_(target_dir / "plain.txt");


        for (uint64_t i = 0; i < row; ++i)
        {
            log(std::format("[{}] {} running {} \n", fmt_now_time(), mode.fmt_config(), (i + 1)));
            
            getline(plain_stream, plain_str);
            getline(key_stream, key_str);
            getline(iv_stream, iv_str);
            
            plain_data = Data(plain_str);
            key_data = Data(key_str);
            iv_data = Data(iv_str);
            
            cipher.set_key(key_data);
            cipher.set_mode_data_param("iv", iv_data);

            auto start_mid = std::chrono::steady_clock::now();
            Data crypt_data = cipher.encrypt(plain_data);
            auto end_mid = std::chrono::steady_clock::now();

            std::string crypt = crypt_data.to_hex_string(true);
            crypt += " ";
            crypt += std::format(" en:{}ms ", std::chrono::duration_cast<std::chrono::milliseconds>(end_mid - start_mid).count());
            encrypt_time += std::chrono::duration_cast<std::chrono::milliseconds>(end_mid - start_mid).count();
            crypt_stream << crypt << std::endl;

            start_mid = std::chrono::steady_clock::now();
            Data plain_data_ = cipher.decrypt(crypt_data);
            end_mid = std::chrono::steady_clock::now();

            std::string plain = plain_data_.to_hex_string(true);
            plain += " ";
            plain += std::format(" de:{}ms ", std::chrono::duration_cast<std::chrono::milliseconds>(end_mid - start_mid).count());
            plain += plain_data == plain_data_ ? "success" : "failure";
            failure_time += plain_data == plain_data_ ? 0 : 1;
            decrypt_time += std::chrono::duration_cast<std::chrono::milliseconds>(end_mid - start_mid).count();
            plain_stream_ << plain << std::endl;

            crypt_stream.flush();
            plain_stream_.flush();
        }
        auto end = std::chrono::steady_clock::now();
        crypt_stream << std::format("total:{}ms", encrypt_time) << std::endl;
        plain_stream_ << std::format("total:{}ms", decrypt_time) << std::endl;
    }
    catch (std::exception& e)
    {
        log(std::format("[{}] {} error {} \n", fmt_now_time(), mode.fmt_config(), e.what()));
    }
    std::string end_time = fmt_now_time();
    result_vec.push_back(Result{ mode.fmt_config(),start_time,end_time, encrypt_time, decrypt_time, failure_time });
    log(std::format("[{}] {} complete encrypt_time:{}ms decrypt_time:{}ms failure:{}\n",
        fmt_now_time(), mode.fmt_config(), encrypt_time, decrypt_time, failure_time));
}

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

int main()
{
    using namespace dog_torch::crypto::symmetric;
    using namespace dog_torch::crypto::symmetric::algorithm;
    using namespace dog_torch::crypto::symmetric::mode;
    using namespace dog_torch::crypto::symmetric::padding;

    std::cout << R"(基准算法：
AES128
测试的工作模式：
ECB CBC PCBC CFBB1 CFBB10 CFBB16 CFBb1 CFBb10 OFB CTR
预计运行时间：(以ECB为基准)
100 100 100  600   50     37     4000  500    30  25
)" << std::endl;
    std::cout << R"(Base on:
AES128
mode:
ECB CBC PCBC CFBB1 CFBB10 CFBB16 CFBb1 CFBb10 OFB CTR
estimated time:(Base on ECB)
100 100 100  600   50     37     4000  500    30  25
)" << std::endl;
    std::cout << R"(注意事项:
    本软件旨在测试分组加密模式的性能 准确性等参数
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

    std::filesystem::path plain("plain.txt");
    std::filesystem::path key("key.txt");
    std::filesystem::path iv("iv.txt");

    std::random_device rd;

    std::ofstream plains(plain);
    std::ofstream keys(key);
    std::ofstream ivs(iv);
    for (uint64_t i = 0; i < row; ++i)
    {
        std::string res;
        switch (i % 4)
        {
        case 3: { res += std::format("{:02X}", rd() & 0xFF); }
        case 2: { res += std::format("{:02X}", rd() & 0xFF); }
        case 1: { res += std::format("{:02X}", rd() & 0xFF); }
        case 0: { res += std::format("{:02X}", rd() & 0xFF); }
        }
        for (uint64_t j = 0; j < i / 4; j++)
        {
            res += std::format("{:08X}", rd());
        }
        plains << res << std::endl;
    }
    plains.flush();
    log("plain.txt generated");
    for (uint64_t i = 0; i < row; ++i)
    {
        std::string res;
        for (uint64_t j = 0; j < 4; j++)
        {
            res += std::format("{:08X}", rd());
        }
        keys << res << std::endl;
    }
    keys.flush();
    log("key.txt generated");
    for (uint64_t i = 0; i < row; ++i)
    {
        std::string res;
        for (uint64_t j = 0; j < 4; j++)
        {
            res += std::format("{:08X}", rd());
        }
        ivs << res << std::endl;
    }
    ivs.flush();
    log("iv.txt generated");
    dog_torch::asyncion::pool::PollingTaskPool polling_task_pool(8);
    Data iv_data = "0123456789ABCDEF0123456789ABCDEF";
    try
    {
        polling_task_pool.add_task(doing, CFBb(padding::PKCS7(), iv_data, 1));

        polling_task_pool.add_task(doing, ECB(padding::PKCS7()));
        polling_task_pool.add_task(doing, CBC(padding::PKCS7(), iv_data));
        polling_task_pool.add_task(doing, PCBC(padding::PKCS7(), iv_data));

        polling_task_pool.add_task(doing, CFBB(padding::PKCS7(), iv_data, 1));
        polling_task_pool.add_task(doing, CFBB(padding::PKCS7(), iv_data, 10));
        polling_task_pool.add_task(doing, CFBB(padding::PKCS7(), iv_data, 16));

        polling_task_pool.add_task(doing, CFBb(padding::PKCS7(), iv_data, 10));

        polling_task_pool.add_task(doing, OFB(padding::PKCS7(), iv_data));
        polling_task_pool.add_task(doing, CTR(padding::PKCS7(), iv_data));

        polling_task_pool.start();
        polling_task_pool.wait_complete();
    }
    catch (std::exception& e)
    {
        log(std::format("[{}] error {} \n", fmt_now_time(), e.what()));
    }

    std::ofstream results_txt("./result.txt");

    result_vec.doing([&results_txt](std::vector<Result> vec)->void
        {
            for (auto& item : vec)
            {
                std::cout << std::format("name:{} start at:{} end:at {} en:{}ms de:{} ms fail-{}",
                    item.name, item.start_time, item.end_time, item.encrypt_time, item.decrypt_time, item.failure_time) << std::endl;
                results_txt << std::format("name:{} start at:{} end:at {} en:{}ms de:{} ms fail-{}",
                    item.name, item.start_time, item.end_time, item.encrypt_time, item.decrypt_time, item.failure_time) << std::endl;
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

    return 0;
}