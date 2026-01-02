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
#include "crypto/symmetric/base.h"
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

void log(std::string msg)
{
    static std::mutex log_mutex;  // 保护共享资源
    std::lock_guard<std::mutex> lock(log_mutex);
    static std::ofstream log_file("log.txt", std::ios::app);
    std::cout << msg << std::endl;
    log_file << msg << std::endl;
    log_file.flush();
}

std::unique_ptr<dog_torch::crypto::symmetric::mode::Mode> create(std::string name,dog_torch::serialize::Data iv,uint64_t shift)
{
    using namespace dog_torch::crypto::symmetric::mode;
    using namespace dog_torch::crypto::symmetric::padding;
    if (name == "ECB")
    {
        return std::move(ECB(PKCS7()).clone());
    }
    else if (name == "CBC")
    {
        return std::move(CBC(PKCS7(), iv).clone());
    }
    else if (name == "PCBC")
    {
        return std::move(PCBC(PKCS7(), iv).clone());
    }
    else if (name == "CFBB")
    {
        return std::move(CFBB(PKCS7(), iv, shift).clone());
    }
    else if (name == "CFBb")
    {
        return std::move(CFBb(PKCS7(), iv, shift).clone());
    }
    else if (name == "OFB")
    {
        return std::move(OFB(PKCS7(), iv).clone());
    }
    else if (name == "CTR")
    {
        return std::move(CTR(PKCS7(), iv).clone());
    }
    throw std::runtime_error("no such mode");
}
std::string fmt_now_time()
{
    return std::format("{:%Y-%m-%d %H:%M:%S}", std::chrono::zoned_time{ std::chrono::current_zone(), std::chrono::system_clock::now() });
}
void doing(std::string name, uint64_t shift)
{
    try
    {
        auto start = std::chrono::steady_clock::now();
        log(std::format("[{}] name:{} shift:{} start\n", fmt_now_time(), name, shift));
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

        Cipher cipher(AES(16), *create(name, iv_data, shift));
        std::filesystem::path target_dir = std::filesystem::path(".") / cipher.to_string();
        std::filesystem::create_directory(target_dir);
        std::ofstream crypt_stream(target_dir / "crypt.txt");

        for (uint64_t i = 0; i < 4096; ++i)
        {
            log(std::format("[{}] name:{} shift:{} running {} \n", fmt_now_time(), name, shift, (i + 1)));
            getline(plain_stream, plain_str);
            getline(key_stream, key_str);
            getline(iv_stream, iv_str);
            plain_data = Data(plain_str);
            key_data = Data(key_str);
            iv_data = Data(iv_str);
            Cipher cipher(AES(16), *create(name, iv_data, shift));
            cipher.set_key(key_data);
            auto start_mid = std::chrono::steady_clock::now();
            Data crypt_data = cipher.encrypt(plain_data);
            auto end_mid = std::chrono::steady_clock::now();
            std::string crypt = crypt_data.to_hex_string(true);
            crypt += " ";
            crypt += std::format("en:{}ms ", std::chrono::duration_cast<std::chrono::milliseconds>(end_mid - start_mid).count());
            start_mid = std::chrono::steady_clock::now();
            Data plain_data_ = cipher.decrypt(crypt_data);
            end_mid = std::chrono::steady_clock::now();
            crypt += std::format("de:{}ms ", std::chrono::duration_cast<std::chrono::milliseconds>(end_mid - start_mid).count());
            crypt += plain_data == plain_data_ ? "success" : " failure";
            crypt_stream << crypt << std::endl;
            crypt_stream.flush();
        }
        auto end = std::chrono::steady_clock::now();
        crypt_stream << std::format("total:{}ms", std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count()) << std::endl;
    }
    catch (std::exception& e)
    {
        log(std::format("[{}] name:{} shift:{} error {} \n", fmt_now_time(), name, shift, e.what()));
    }
    log(std::format("[{}] name:{} shift:{} complete\n", fmt_now_time(), name, shift));
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

    std::cout << R"(注意事项:
    本软件旨在测试分组加密模式的性能 准确性等参数
    运行时会占用计算机的部分资源
    可能会对计算机的运行速度产生一定影响
    如果您还想继续测试 请输入任意键继续 反之则直接关闭)" << std::endl;
    std::cout << R"(Warning:
    this script is used to be test the speed and accuracy of the block cipher mode
    there will be some resources of PC used
    It may make the computer slower than normal
    If you want to continue,please press any key,otherwise,close directly)" << std::endl;
    std::cin.get();

    std::filesystem::path plain("plain.txt");
    std::filesystem::path key("key.txt");
    std::filesystem::path iv("iv.txt");

    std::random_device rd;

    std::ofstream plains(plain);
    std::ofstream keys(key);
    std::ofstream ivs(iv);
    for (uint64_t i = 0; i < 4096; ++i)
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
    log("plain.txt generated");
    for (uint64_t i = 0; i < 4096; ++i)
    {
        std::string res;
        for (uint64_t j = 0; j < 4; j++)
        {
            res += std::format("{:08X}", rd());
        }
        keys << res << std::endl;
    }
    log("key.txt generated");
    for (uint64_t i = 0; i < 4096; ++i)
    {
        std::string res;
        for (uint64_t j = 0; j < 4; j++)
        {
            res += std::format("{:08X}", rd());
        }
        ivs << res << std::endl;
    }
    log("iv.txt generated");
    dog_torch::asyncion::pool::PollingTaskPool polling_task_pool(8);

    try
    {
        //因为CFBb1太慢了 所以提前测试
        polling_task_pool.add_task(doing, "CFBb", 1);
        polling_task_pool.start();

        polling_task_pool.add_task(doing, "ECB", 0);
        polling_task_pool.add_task(doing, "CBC", 0);
        polling_task_pool.add_task(doing, "PCBC", 0);

        polling_task_pool.add_task(doing, "CFBB", 1);
        polling_task_pool.add_task(doing, "CFBB", 10);
        polling_task_pool.add_task(doing, "CFBB", 16);

        polling_task_pool.add_task(doing, "CFBb", 10);

        polling_task_pool.add_task(doing, "OFB", 0);
        polling_task_pool.add_task(doing, "CTR", 0);


        polling_task_pool.wait_complete();
    }
    catch (std::exception& e)
    {
        log(std::format("[{}] error {} \n", fmt_now_time(), e.what()));
    }

    //if (OScode() == 4)
    //{
    //    system("shutdown /s /t 0");
    //}
    //else if (OScode() == 6)
    //{
    //    system("shutdown -s -t 0");
    //}

    return 0;
}