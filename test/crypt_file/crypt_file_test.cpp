#include <filesystem>
#include <fstream>
#include <iostream>

#include <iomanip>

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

std::random_device rd;

struct Result
{
    std::string name;
    std::string start_time;
    std::string end_time;
    double encrypt_time;
    double decrypt_time;
    uint64_t failure_time;
    Result(std::string name, std::string start_time, std::string end_time, double encrypt_time, double decrypt_time, uint64_t failure_time) :
        name(name), start_time(start_time), end_time(end_time), encrypt_time(encrypt_time), decrypt_time(decrypt_time), failure_time(failure_time) {
    }
};

dog_torch::asyncion::container::VectorMove<Result> result_vec;

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
std::string fmt_dur(int64_t dur)
{
    const static std::vector<std::pair<std::string, int64_t>> radix =
    {
        {"ms", 1000},{"s", 60},{"min", 60},{"h", 24},{"d", 30}
    };
    std::string res = "";
    for (auto& [name, base] : radix)
    {
        if (dur % base != 0)
        {
            res = (std::format("{}{}", dur % base, name) + res);
        }
        dur /= base;
        if (dur == 0)
        {
            break;
        }
    }
    return res;
}
void log(std::string msg)
{
    static std::mutex log_mutex;
    std::lock_guard<std::mutex> lock(log_mutex);
    static std::ofstream log_file("log.txt", std::ios::app);
    std::cout << msg << std::endl;
    log_file << msg << std::endl;
    log_file.flush();
}
uint64_t is_file_same(std::filesystem::path path1, std::filesystem::path path2)
{
    if (std::filesystem::file_size(path1) != std::filesystem::file_size(path2))
    {
        return false;
    }
    std::ifstream file1(path1, std::ios::binary);
    std::ifstream file2(path2, std::ios::binary);
    uint64_t offset = 0;
    while (file1.good() && file2.good())
    {
        if (file1.get() != file2.get())
        {
            return offset;
        }
        offset++;
    }
    return -1;
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
    auto end = std::chrono::steady_clock::now();
    auto dur = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    std::string start_time = fmt_now_time();
    try
    {
        log(std::format("[{}] {} start\n", start_time, mode.fmt_config()));
        using namespace dog_torch::crypto::symmetric;
        using namespace dog_torch::crypto::symmetric::algorithm;
        using namespace dog_torch::crypto::symmetric::mode;
        using namespace dog_torch::crypto::symmetric::padding;

        std::ifstream key_stream("key.txt");
        std::ifstream iv_stream("iv.txt");

        std::string key_str;
        std::string iv_str;

        Data key_data;
        Data iv_data;

        Cipher cipher(AES(16), mode);
        std::filesystem::path target_dir = std::filesystem::current_path() / cipher.to_string();
        std::filesystem::create_directory(target_dir);

        std::filesystem::directory_iterator dir_iter(std::filesystem::current_path() / std::filesystem::path("plain"));
        for (const auto& file : dir_iter)
        {
            getline(key_stream, key_str);
            getline(iv_stream, iv_str);

            std::string file_name = file.path().filename().string();

            std::filesystem::path plain_path = file.path();
            std::filesystem::path crypt_path = target_dir / (file_name + ".crypt");
            std::ofstream crypt_stream(crypt_path, std::ios::binary);
            crypt_stream.close();
            std::filesystem::path plain_path_ = target_dir / (file_name + ".plain");
            std::ofstream plain_stream_(plain_path_, std::ios::binary);
            plain_stream_.close();
            key_data = Data(key_str);
            iv_data = Data(iv_str);

            cipher.set_key(key_data);
            cipher.set_mode_data_param("iv", iv_data);

            start = std::chrono::steady_clock::now();
            cipher.encrypt(plain_path, crypt_path);
            end = std::chrono::steady_clock::now();
            dur = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
            log(std::format("[{}] {} encrypt {} {} \n", fmt_now_time(), mode.fmt_config(), file.path().string(), fmt_dur(dur)));

            start = std::chrono::steady_clock::now();
            cipher.decrypt(crypt_path, plain_path_);
            end = std::chrono::steady_clock::now();
            dur = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
            log(std::format("[{}] {} decrypt {} {} \n", fmt_now_time(), mode.fmt_config(), file.path().string(), fmt_dur(dur)));

            uint64_t offset = is_file_same(plain_path, plain_path_);
            offset == (uint64_t)(-1) ? failure_time += 0 : failure_time++;
            if (offset == (uint64_t)(-1))
            {
                log(std::format("[{}] {} wrong {} offset:{} \n", fmt_now_time(), mode.fmt_config(), file.path().string(), offset));
            }
        }
    }
    catch (std::exception& e)
    {
        log(std::format("[{}] {} error {} \n", fmt_now_time(), mode.fmt_config(), e.what()));
    }
    std::string end_time = fmt_now_time();
    result_vec.push_back(Result{ mode.fmt_config(),start_time,end_time, encrypt_time, decrypt_time, failure_time });
    log(std::format("[{}] {} complete encrypt_time:{} decrypt_time:{} failure:{}\n",
        fmt_now_time(), mode.fmt_config(), fmt_dur((int64_t)encrypt_time), fmt_dur((int64_t)decrypt_time), failure_time));
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

    char is_off;

    std::cout << "测试完成后自动关机?[y/n]" << std::endl;
    std::cout << "power off after running?[y/n]" << std::endl;

    std::cin >> is_off;

    uint64_t kb_size = 0;
    uint64_t mb_size = 9437184 + (rd() % 2097152);
    uint32_t rd_size = 0;
    do { rd_size = rd(); } while (rd_size > 4294963200);
    kb_size = rd_size % 5120 + 5120;

    std::filesystem::path plain_dir = "./plain";
    std::filesystem::path small_one = plain_dir / "small_one";
    std::filesystem::path big_one = plain_dir / "big_one";

    std::filesystem::create_directory(plain_dir);
    std::ofstream small_one_stream = std::ofstream(small_one, std::ios::binary);
    std::ofstream big_one_stream = std::ofstream(big_one, std::ios::binary);

    log("plain file generating...");
    switch (kb_size % 4)
    {
    case 3: small_one_stream.put((uint8_t)(rd() & 0xFF));
    case 2: small_one_stream.put((uint8_t)(rd() & 0xFF));
    case 1: small_one_stream.put((uint8_t)(rd() & 0xFF));
    }
    for (uint64_t i = 0; i < kb_size; i += 4)
    {
        rd_size = rd();
        small_one_stream.put((uint8_t)(rd_size >> 24));
        small_one_stream.put((uint8_t)(rd_size >> 16));
        small_one_stream.put((uint8_t)(rd_size >> 8));
        small_one_stream.put((uint8_t)(rd_size >> 0));
    }
    small_one_stream.close();

    switch (mb_size % 4)
    {
    case 3: big_one_stream.put((uint8_t)(rd() & 0xFF));
    case 2: big_one_stream.put((uint8_t)(rd() & 0xFF));
    case 1: big_one_stream.put((uint8_t)(rd() & 0xFF));
    }
    for (uint64_t i = 0; i < mb_size; i += 4)
    {
        rd_size = rd();
        big_one_stream.put((uint8_t)(rd_size >> 24));
        big_one_stream.put((uint8_t)(rd_size >> 16));
        big_one_stream.put((uint8_t)(rd_size >> 8));
        big_one_stream.put((uint8_t)(rd_size >> 0));
    }
    big_one_stream.close();
    log("plain file generated");

    std::filesystem::path key("key.txt");
    std::filesystem::path iv("iv.txt");
    std::ofstream keys(key);
    std::ofstream ivs(iv);
    for (uint64_t i = 0; i < 2; ++i)
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
    for (uint64_t i = 0; i < 2; ++i)
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