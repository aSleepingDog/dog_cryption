#include<iostream>
#include<cstdint>
#include<thread>

#include <cstdint>

#include "../../libcryption/include/cryption/dog_cryption.h"
#include "../../libtask/include/task/task.h"


//命令行版本因为输入配置过多,不推荐使用 请优先使用GUI版本
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
std::vector<std::string> get_args()
{
    auto get_utf8_str = [](uint64_t number)
        {
            std::string result = "";
            if (number <= 0x7F)
            {
                result += (char)number;
            }
            else if (number <= 0x7FF)
            {
                result += (char)(0b11000000 | ((number >> 06) & 0x1F));
                result += (char)(0b10000000 | ((number >> 00) & 0x3F));
            }
            else if (number <= 0xFFFF)
            {
                result += (char)(0b11100000 | ((number >> 12) & 0x0F));
                result += (char)(0b10000000 | ((number >> 06) & 0x3F));
                result += (char)(0b10000000 | ((number >> 00) & 0x3F));
            }
            else if (number <= 0x1FFFFF)
            {
                result += (char)(0b11110000 | ((number >> 18) & 0x07));
                result += (char)(0b10000000 | ((number >> 12) & 0x3F));
                result += (char)(0b10000000 | ((number >> 06) & 0x3F));
                result += (char)(0b10000000 | ((number >> 00) & 0x3F));
            }
            else if (number <= 0x3FFFFFF)
            {
                result += (char)(0b11111000 | ((number >> 24) & 0x03));
                result += (char)(0b10000000 | ((number >> 18) & 0x3F));
                result += (char)(0b10000000 | ((number >> 12) & 0x3F));
                result += (char)(0b10000000 | ((number >> 06) & 0x3F));
                result += (char)(0b10000000 | ((number >> 00) & 0x3F));
            }
            else if (number <= 0x7FFFFFFF)
            {
                result += (char)(0b11111100 | ((number >> 30) & 0x01));
                result += (char)(0b10000000 | ((number >> 24) & 0x3F));
                result += (char)(0b10000000 | ((number >> 18) & 0x3F));
                result += (char)(0b10000000 | ((number >> 12) & 0x3F));
                result += (char)(0b10000000 | ((number >> 06) & 0x3F));
                result += (char)(0b10000000 | ((number >> 00) & 0x3F));
            }
            return result;
        };
    std::vector<std::string> args;
    std::string input = "";
    std::string param = "";
    uint64_t number = 0;
    uint64_t number_size = 0;
    std::getline(std::cin, input);
    bool is_string = false;
    uint64_t is_trun = 0;//0常规 1单转义 2/x十六进制转义 3/u\U unicode字符转义 4八进制转移
    for (auto& c : input)
    {
        if (c == ' ' && !is_string && param != "")
        {
            args.emplace_back(param);
            param = "";
        }
        else if (c == '"' && is_trun == 0)
        {
            is_string = !is_string;
        }
        else if (c == '\\' && is_trun == 0)
        {
            is_trun = 1;
            number_size = 3;
        }
        else if (c == '\\' && is_trun == 1)
        {
            param.push_back(0x92);
            is_trun = 0;
        }
        else if (c == '\\' && is_trun > 1)
        {
            number_size = 0;
            if (is_trun == 4 || is_trun == 2)
            {
                param.push_back((char)(number & 0xFF));
            }
            else if (is_trun == 3)
            {
                param += get_utf8_str(number);
            }
            number = 0;
            is_trun = 1;
        }
        else if (c == 'a' && is_trun == 1)
        {
            param.push_back(0x07);
            is_trun = 0;
        }
        else if (c == 'b' && is_trun == 1)
        {
            param.push_back(0x08);
            is_trun = 0;
        }
        else if (c == 'f' && is_trun == 1)
        {
            param.push_back(0x0C);
            is_trun = 0;
        }
        else if (c == 'n' && is_trun == 1)
        {
            param.push_back(0x0A);
            is_trun = 0;
        }
        else if (c == 'r' && is_trun == 1)
        {
            param.push_back(0x0D);
            is_trun = 0;
        }
        else if (c == 't' && is_trun == 1)
        {
            param.push_back(0x09);
            is_trun = 0;
        }
        else if (c == 'v' && is_trun == 1)
        {
            param.push_back(0x0B);
            is_trun = 0;
        }
        else if (c == '\'' && is_trun == 1)
        {
            param.push_back('\'');
            is_trun = 0;
        }
        else if (c == '"' && is_trun == 1)
        {
            param.push_back('"');
            is_trun = 0;
        }
        else if (c == '?' && is_trun == 1)
        {
            param.push_back('?');
            is_trun = 0;
        }
        else if (c == '\0' && is_trun == 1)
        {
            param.push_back(0x00);
            is_trun = 0;
        }
        else if ((c >= '0' && c <= '7') && is_trun == 1)
        {
            is_trun = 4;
            number = number * 8 + (c - '0');
            number_size = 2;
        }
        else if ((c >= '0' && c <= '7') && number_size != 0 && is_trun == 4)
        {
            number = number * 8 + (c - '0');
            number_size--;
        }
        else if (c == 'x' && is_trun == 1)
        {
            is_trun = 2;
            number_size = 2;
        }
        else if (c == 'u' && is_trun == 1)
        {
            is_trun = 3;
            number_size = 4;
        }
        else if (c == 'U' && is_trun == 1)
        {
            is_trun = 3;
            number_size = 8;
        }
        else if ((c >= '0' && c <= '9') && number_size != 0 && (is_trun == 2 || is_trun == 3))
        {
            number = number * 16 + (c - '0');
            number_size--;
        }
        else if ((c >= 'a' && c <= 'f') && number_size != 0 && (is_trun == 2 || is_trun == 3))
        {
            number = number * 16 + ((c - 'a') + 10);
            number_size--;
        }
        else if ((c >= 'A' && c <= 'F') && number_size != 0 && (is_trun == 2 || is_trun == 3))
        {
            number = number * 16 + ((c - 'A') + 10);
            number_size--;
        }
        else
        {
            number_size = 0;
            if (is_trun == 4 || is_trun == 2)
            {
                param.push_back((char)(number & 0xFF));
            }
            else if (is_trun == 3)
            {
                param += get_utf8_str(number);
            }
            is_trun = 0;
            number = 0;
            param.push_back(c);
        }
    }
    if (is_trun != 0)
    {
        param += get_utf8_str(number);
    }
    if (param != "")
    {
        args.emplace_back(param);
    }
    return args;
}
std::vector<std::string> spilt(std::string str, char c)
{
    std::vector<std::string> res;
    std::string one = "";
    for (auto cit : str)
    {
        if (cit == c)
        {
            res.emplace_back(one);
            one = "";
        }
        else
        {
            one.push_back(cit);
        }
    }
    if (one != "")
    {
        res.emplace_back(one);
    }
    return res;
}
bool effect_char(char c, std::string range)
{
    for (int i = 0; i < range.size(); i++)
    {
        if (c == range[i])
        {
            return true;
        }
    }
    return false;
}
bool effect_str(std::string str, std::string range)
{
    for (int i = 0; i < str.size(); i++)
    {
        if (!effect_char(str[i], range))
        {
            std::cout << std::format("字符串只能由{}组成 出现{}非法字符在{}处", range, str[i], i) << std::endl;
            return false;
        }
    }
    return true;
}
dog_param::IOConfig get_data_type(std::string sign, bool allow_file, bool is_input)
{
    std::string type_str = "";
    std::string param = "";
    std::unordered_map<std::string, std::any> map;
    if (allow_file)
    {
        std::cout << std::format("当前输入 {}\n请输入数据类型", sign) << std::endl;
        std::cout << "数据类型可以为 utf8 base64[][][] hex/Hex file" << std::endl;
        std::cout << "[]中可以填入 (空格) ! \" # $ % & ' ( ) * + , - .  / : ; < = > ? @ [ \\ ] ^ _ ` { | } ~ 其中两两不能相同" << std::endl;
    }
    else
    {
        std::cout << std::format("当前输入 {}\n请输入数据类型", sign) << std::endl;
        std::cout << "数据类型可以为 utf8/base64[][][]/hex Hex" << std::endl;
        std::cout << "[]中可以填入 (空格) ! \" # $ % & ' ( ) * + , - .  / : ; < = > ? @ [ \\ ] ^ _ ` { | } ~ 其中两两不能相同" << std::endl;
    }
    std::vector<std::string> params = get_args();
    if (params.size() == 0)
    {
        throw DOG_EXCEPTION(std::format("参数数量不足 需要1当前{}", params.size()));
    }
    param = params[0];
    map["is_file"] = false;
    if (param == "utf8")
    {
        map["is_file"] = false;
        map["type"] = (uint64_t)0;
    }
    else if (param == "Hex")
    {
        map["type"] = (uint64_t)2;
        map["is_file"] = false;
        map["is_upper"] = true;
    }
    else if (param == "hex")
    {
        map["type"] = (uint64_t)2;
        map["is_file"] = false;
        map["is_upper"] = false;
    }
    else if (param == "file" && allow_file)
    {
        map["is_file"] = true;
    }
    else if (param.substr(0, 6) == "base64")
    {
        map["is_file"] = false;
        map["type"] = (uint64_t)1;
        if (param.size() == 6)
        {
            map["replace0"] = '+';
            map["replace1"] = '/';
            map["replace2"] = '=';
        }
        if (param.size() == 9)
        {
            map["replace0"] = (char)param[6];
            map["replace1"] = (char)param[7];
            map["replace2"] = (char)param[8];
        }
    }
    if (allow_file)
    {
        if (param == "file")
        {
            std::cout << "请输入文件路径" << std::endl;
            std::getline(std::cin, param);
            map["is_file"] = true;
            map["ori_str"] = param;
            if (!std::filesystem::exists(param) && is_input)
            {
                throw DOG_EXCEPTION(std::format("文件不存在 {}", param));
            }
        }
        else if(is_input)
        {
            std::cout << "请输入文本" << std::endl;
            std::getline(std::cin, param);
            map["ori_str"] = param;
        }
    }
    else
    {
        if (is_input)
        {
            std::cout << "请输入文本" << std::endl;
            std::getline(std::cin, param);
            map["ori_str"] = param;
        }
    }
    return dog_param::IOConfig(map, is_input);
}
dog_param::IOConfig get_file(bool is_input)
{
    std::cout << "请输入文件路径" << std::endl;
    std::string path = "";
    std::getline(std::cin, path);
    if (!std::filesystem::exists(path) && is_input)
    {
        throw DOG_EXCEPTION(std::format("文件不存在 {}", path));
    }
    std::unordered_map<std::string, std::any> map;
    map["is_file"] = true;
    map["ori_str"] = path;
    return dog_param::IOConfig(map, true);
}

dog_hash::HashCrypher get_hash_type()
{
    std::string input = "";
    std::vector<std::string> params;
    std::cout << "请输入散列类型[hash] [type] 可选项如下 示例SHA2 256" << std::endl;
    for (auto one : dog_hash::list)
    {
        std::cout << std::format("{} |", one.name);
        std::cout.flush();
        dog_number::region::NumberIterator nit(one.region);
        while (nit.have_next())
        {
            std::cout << std::format(" {} ", nit.next() * 8);
            std::cout.flush();
        }
        std::cout << std::endl;
    }
    auto args = get_args();
    if (args.size() != 2)
    {
        throw DOG_EXCEPTION(std::format("参数过少 需要2 当前{}", args.size()));
    }
    std::string hash_name = args[0];
    uint64_t number = 0;
    try
    {
        number = std::stoull(args[1]);
    }
    catch (std::exception& e)
    {
        throw DOG_EXCEPTION(std::format("此处应该输入数字{}", args[1]));
    }
    for (auto one : dog_hash::list)
    {
        if (one.name == args[0])
        {
            if (dog_number::region::is_fall(one.region, number/8))
            {
                return dog_hash::HashCrypher(one.name, number / 8);
            }
            else
            {
                throw DOG_EXCEPTION(std::format("{} 的散列类型不支持 {} 位", one.name, number));
            }
        }
    }
    throw DOG_EXCEPTION(std::format("不支持的的散列类型 {}", args[0]));
}
dog_param::IOConfig get_iv(uint64_t block_size)
{
    std::cout << "是否自动生成iv y/n" << std::endl;
    auto args = get_args();
    if (args.size() != 1)
    {
        throw DOG_EXCEPTION(std::format("参数过少 需要1 当前{}", args.size()));
    }
    if (args[0] == "y")
    {
        std::unordered_map<std::string, std::any> iv_params;
        iv_params["ori_str"] = dog_cryption::utils::randiv(block_size).getHexString();
        iv_params["type"] = (uint64_t)2;
        iv_params["is_upper"] = true;
        iv_params["is_file"] = false;
        return dog_param::IOConfig(iv_params, true);
    }
    else
    {
        return get_data_type("请输入iv", false, true);
    }
}
struct CryptionParams
{
    dog_cryption::CryptionConfig config;
    bool with_config;
    bool with_iv;
    bool with_check;
};
CryptionParams get_cryption_type()
{
    std::string input = "";
    std::cout << "请输入基础算法类型[type] [block_size] [key_size]可选项如下" << std::endl;
    for (auto one : dog_cryption::Algorithm_list)
    {
        std::cout << std::format("{} |", one.name);
        dog_number::region::NumberIterator nit(one.block_size_region);
        while (nit.have_next())
        {
            std::cout << nit.next() * 8 << " ";
        }
        std::cout << "|";
        nit = dog_number::region::NumberIterator(one.key_size_region);
        while (nit.have_next())
        {
            std::cout << nit.next() * 8 << " ";
        }
        std::cout << std::endl;
    }
    std::cout << "示例ASE 128 128" << std::endl;
    auto args = get_args();
    if (args.size() != 3)
    {
        throw DOG_EXCEPTION(std::format("参数过少 需要3 当前{}", args.size()));
    }
    std::string algorithm_name = args[0];
    uint64_t block_size = 0;
    uint64_t key_size = 0;
    bool is_config_effective = false;
    try
    {
        block_size = std::stoull(args[1]) / 8;
        key_size = std::stoull(args[2]) / 8; 
    }
    catch (std::exception& e)
    {
        throw DOG_EXCEPTION(std::format("此处应该输入数字{}", args[1]));
    }
    dog_cryption::CryptionConfig config;
    for (auto one : dog_cryption::Algorithm_list)
    {
        if (one.name == args[0])
        {
            if (dog_number::region::is_fall(one.block_size_region, block_size) && dog_number::region::is_fall(one.key_size_region, key_size))
            {
                is_config_effective = true;
            }
        }
    }
    if (!is_config_effective)
    {
        throw DOG_EXCEPTION(std::format("不支持 {} {} {}", algorithm_name, block_size, key_size));
    }
    std::cout << "请输入工作模式[mode] [using iv y/n] [using padding y/n] [using shift]" << std::endl;
    std::cout << "以下是可选工作模式和如何针对三个参数,如果某个参数强制需要,则会忽略用户输入" << std::endl;
    for (auto one : dog_cryption::mode::list)
    {
        std::cout << std::format("{} | {} | {} | {} \n", 
            one.name_, 
            one.force_iv_ ? "强制使用iv" : "不强制使用iv", 
            one.force_padding_ ? "强制使用填充" : "不强制使用填充", 
            one.force_shift_ ? "需要偏移" : "不需要偏移");
    }
    std::cout << "示例CBC y y 0" << std::endl;
    auto args2 = get_args();
    if (args2.size() != 4)
    {
        throw DOG_EXCEPTION(std::format("参数过少 需要4 当前{}", args2.size()));
    }
    std::string mode_name = args2[0];
    bool using_iv = (args2[1] == "y");
    bool using_padding = (args2[2] == "y");
    uint64_t shift = 0;
    try
    {
        shift = std::stoull(args2[3]);
    }
    catch (std::exception& e)
    {
        throw DOG_EXCEPTION(std::format("此处应该输入数字{}", args2[3]));
    }
    std::string padding_name = "";
    uint64_t padding_code = 0;
    std::cout << "请选择填充方式 [padding_code] \n可选项如下 示例PKCS7" << std::endl;
    for (auto one : dog_cryption::padding::list)
    {
        std::cout << std::format("{}->{}|", one.name_, one.code_);
    }
    std::cout << std::endl;
    auto args3 = get_args();
    if (args3.size() != 1)
    {
        throw DOG_EXCEPTION(std::format("参数过少 需要1 当前{}", args3.size()));
    }
    try
    {
        padding_code = std::stoull(args3[0]);
    }
    catch (std::exception& e)
    {
        throw DOG_EXCEPTION(std::format("此处应该输入数字{}", args3[0]));
    }
    for (auto one : dog_cryption::padding::list)
    {
        if (one.code_ == padding_code)
        {
            padding_name = one.name_;
        }
    }
    if (padding_name == "" && using_padding)
    {
        throw DOG_EXCEPTION(std::format("不支持填充方式{}", padding_code));
    }
    std::cout << "请选择数据头部信息 [with_config y/n] [with_check y/n] [with_iv y/n]" << std::endl;
    auto args4 = get_args();
    bool with_config = (args4[0] == "y");
    bool with_check = (args4[1] == "y");
    bool with_iv = (args4[2] == "y");
    dog_cryption::CryptionConfig config_ = {
        algorithm_name, block_size, key_size,
        using_padding,padding_name,
        mode_name, using_iv,shift,
    };
    return { config_, with_config, with_iv, with_check };
}
std::string fmt_time(double time)
{
    const std::vector<std::pair<uint64_t, std::string>> list = {
    {1000,"us"},{1000,"ms"},{60,"s"},{60,"min"},{24,"h"},{30,"d"}};
    std::string result = "";
    for (uint64_t i = 0; i < list.size(); ++i) 
    {
        uint64_t nowPoint = (uint64_t)time % list[i].first;
        if (nowPoint == 0)
        {
            break;
        }
        result = std::format("{}{}{}", nowPoint, list[i].second, result);
        time = time / list[i].first;
        if (time == 0) 
        {
            break;
        }
    }
    return result;
}

void clear_print()
{
    switch (OScode())
    {
    case 0:
    case 1:
    case 2:
    case 3:
    {
        system("clear");
        break;
    }
    case 4:
    case 5:
    {
        system("cls");
        break;
    }
    case 6:
    case 7:
    {
        system("clear");
        break;

    }
    case 8:
    default:
    {
        system("clear");
        break;
    }
    }
}

dog_work::TaskPool* task_pool = new dog_work::TaskPool(std::thread::hardware_concurrency());
std::unordered_map<uint64_t, std::unordered_map<std::string, std::any>> task_info;

void update_task()
{
    std::vector<std::unordered_map<std::string, std::any>> waitting = task_pool->get_all_waitting_task_info();
    std::vector<std::unordered_map<std::string, std::any>> running = task_pool->get_all_running_task_info();
    for (auto single_task : waitting)
    {
        task_info[std::any_cast<uint64_t>(single_task["id"])] = single_task;
    }
    for (auto single_task : running)
    {
        task_info[std::any_cast<uint64_t>(single_task["id"])] = single_task;
    }
}

int main()
{
    bool is_running = true;
    while (is_running)
    {
        std::cout << "简易散列加密解密散列" << std::endl;
        std::cout << "1-文本数据转换" << std::endl;
        std::cout << "2-数据散列计算" << std::endl;
        std::cout << "3-数据对称加密" << std::endl;
        std::cout << "4-数据对称解密" << std::endl;
        std::cout << "5-运行任务管理" << std::endl;
        std::cout << "0-退出当前程序" << std::endl;
        std::string operate_code_str = "";
        std::getline(std::cin, operate_code_str);
        int operate_code = 0;
        try
        {
            operate_code = std::stoi(operate_code_str);
            switch (operate_code)
            {
            case 0:
            {
                clear_print();
                std::cout << "正在退出程序" << std::endl;
                delete task_pool;
                clear_print();
                std::cout << "资源释放完成" << std::endl;
                is_running = false;
                break;
            }
            case 1:
            {
                clear_print();
                auto input_config = get_data_type("数据转换输入", false, true);
                auto output_config = get_data_type("数据转换输出", false, false);
                dog_work::Timer timer;
                timer.start();
                std::string result = output_config.fmt_data(input_config.get_data());
                timer.end();
                clear_print();
                std::cout << "处理文本" << std::endl;
                std::cout << input_config.get_ori_str() << std::endl;
                std::cout << "转换方式" << std::endl;
                std::cout << std::format("{} -> {}", input_config.get_IO_string(), output_config.get_IO_string()) << std::endl;
                std::cout << "转换结果" << std::endl;
                std::cout << result << std::endl;
                std::cout << "转换耗时" << std::endl;
                std::cout << fmt_time(timer.get_time()) << std::endl;
                break;
            }
            case 2:
            {
                clear_print();
                auto input_config = get_data_type("数据散列输入", true, true);
                auto hash_crypter = get_hash_type();
                auto output_config = get_data_type("数据散列输出", false, false);
                if (!input_config.is_file())
                {
                    clear_print();
                    dog_work::Timer timer;
                    timer.start();
                    std::string result = output_config.fmt_data(hash_crypter.getDataHash(input_config.get_data()));
                    timer.end();
                    std::cout << "处理文本" << std::endl;
                    std::cout << input_config.get_ori_str() << std::endl;
                    std::cout << "转换方式" << std::endl;
                    std::cout << std::format("{} -[{}]-> {}", input_config.get_IO_string(), hash_crypter.get_config(), output_config.get_IO_string()) << std::endl;
                    std::cout << "转换结果" << std::endl;
                    std::cout << result << std::endl;
                    std::cout << "转换耗时" << std::endl;
                    std::cout << fmt_time(timer.get_time()) << std::endl;
                }
                else
                {
                    if (output_config.is_file())
                    {
                        std::cout << "散列计算文件不支持输出文件" << std::endl;
                    }
                    uint64_t task_id = task_pool->add_hash(input_config, hash_crypter, output_config);
                    clear_print();
                    std::cout << "添加任务成功，任务ID为" << task_id << std::endl;
                }
                break;
            }
            case 3:
            {
                clear_print();
                auto input_config = get_data_type("数据加密输入", true, true);
                auto cryption = get_cryption_type();
                auto iv_config = get_iv(cryption.config.block_size);
                auto key = get_data_type("密钥", true, true);


                if (!input_config.is_file())
                {
                    dog_param::IOConfig output_config = get_data_type("数据转换输出", false, false);
                    clear_print();
                    dog_cryption::Cryptor cryptor(cryption.config);
                    cryptor.set_key(key.get_data());
                    dog_work::Timer timer;
                    timer.start();
                    std::string result = output_config.fmt_data(
                        cryptor.encrypt(input_config.get_data(), cryption.with_config, cryption.with_iv, iv_config.get_data(), cryption.with_check)
                    );
                    timer.end();
                    clear_print();
                    std::cout << "处理文本" << std::endl;
                    std::cout << input_config.get_ori_str() << std::endl;
                    std::cout << "加密方式" << std::endl;
                    std::cout << std::format("{} -[{}]-> {}",input_config.get_IO_string(), cryption.config.to_string(),output_config.get_IO_string()) << std::endl;
                    std::cout << "加密密钥(莫忘记)" << std::endl;
                    std::cout << std::format("[{}]{}", key.get_IO_string(), key.get_ori_str()) << std::endl;
                    std::cout << "加密初始化向量(若写入iv则需要记忆)" << std::endl;
                    std::cout << std::format("[{}]{}", iv_config.get_IO_string(), iv_config.get_ori_str()) << std::endl;
                    std::cout << "密文组成" << std::endl;
                    if (cryption.with_config) { std::cout << "加密配置|"; }
                    if (cryption.with_check) { std::cout << "密钥校验|"; }
                    if (cryption.with_iv) { std::cout << "iv|"; }
                    std::cout << "密文" << std::endl;
                    std::cout << "加密结果" << std::endl;
                    std::cout << result << std::endl;
                    std::cout << "加密耗时" << std::endl;
                    std::cout << fmt_time(timer.get_time()) << std::endl;
                }
                else
                {
                    std::cout << "当前输入 加密文件输出" << std::endl;
                    dog_param::IOConfig output_config = get_file(false);
                    clear_print();
                    dog_cryption::Cryptor cryptor(cryption.config);
                    cryptor.set_key(key.get_data());
                    uint64_t task_id = task_pool->add_encrypt(
                        input_config.get_file_path(), output_config.get_file_path(), cryptor,
                        iv_config.get_data(), cryption.with_config, cryption.with_iv, cryption.with_check
                    );
                    std::cout << "添加任务成功，任务ID为" << task_id << std::endl;
                }
                break;
            }
            case 4:
            {
                clear_print();
                auto input_config = get_data_type("数据散列输入", true, true);
                auto cryption = get_cryption_type();
                auto iv_config = get_iv(cryption.config.block_size);
                auto key = get_data_type("密钥", true, true);
                auto output_config = get_data_type("数据转换输出", true, false);

                if (!input_config.is_file())
                {
                    clear_print();
                    dog_cryption::Cryptor cryptor(cryption.config);
                    cryptor.set_key(key.get_data());
                    dog_work::Timer timer;
                    timer.start();
                    std::string result = output_config.fmt_data(
                        cryptor.decrypt(input_config.get_data(), cryption.with_config, cryption.with_iv, iv_config.get_data(), cryption.with_check)
                    );
                    timer.end();
                    clear_print();
                    std::cout << "处理文本" << std::endl;
                    std::cout << input_config.get_ori_str() << std::endl;
                    std::cout << "输入的密文组成" << std::endl;
                    if (cryption.with_config) { std::cout << "加密配置|"; }
                    if (cryption.with_check) { std::cout << "密钥校验|"; }
                    if (cryption.with_iv) { std::cout << "iv|"; }
                    std::cout << "密文" << std::endl;
                    std::cout << "解密方式" << std::endl;
                    std::cout << std::format("{} -[{}]-> {}", input_config.get_IO_string(), cryption.config.to_string(), output_config.get_IO_string()) << std::endl;
                    std::cout << "解密密钥" << std::endl;
                    std::cout << std::format("[{}]{}", key.get_IO_string(), key.get_ori_str()) << std::endl;
                    std::cout << "解密初始化向量(若写入iv则需要记忆)" << std::endl;
                    std::cout << std::format("[{}]{}", iv_config.get_IO_string(), iv_config.get_ori_str()) << std::endl;
                    std::cout << "解密结果" << std::endl;
                    std::cout << result << std::endl;
                    std::cout << "解密耗时" << std::endl;
                    std::cout << fmt_time(timer.get_time()) << std::endl;
                }
                else
                {
                    clear_print();
                    dog_cryption::Cryptor cryptor(cryption.config);
                    cryptor.set_key(key.get_data());
                    uint64_t task_id = task_pool->add_decrypt(
                        input_config.get_file_path(), output_config.get_file_path(), cryptor,
                        iv_config.get_data(), cryption.with_config, cryption.with_iv, cryption.with_check
                    );
                    std::cout << "添加任务成功，任务ID为" << task_id << std::endl;
                }
                break;
            }
            case 5:
            {
                clear_print();
                update_task();
                if (!task_info.size())
                {
                    std::cout << "当前无运行任务" << std::endl;
                }
                for (auto& task : task_info)
                {
                    task_info[std::any_cast<uint64_t>(task.second["id"])] = task.second;
                    uint64_t id = std::any_cast<uint64_t>(task.second["id"]);
                    int status = std::any_cast<int>(task.second["status"]);
                    std::string status_str = "";
                    switch (status)
                    {
                    case -1:
                        status_str = "等待";
                        break;
                    case 0:
                        status_str = "运行";
                        break;
                    case 1:
                        status_str = "暂停";
                        break;
                    case 2:
                        status_str = "完成";
                        break;
                    }
                    double progress = std::any_cast<double>(task.second["progress"]);
                    std::string type = std::any_cast<std::string>(task.second["type"]);
                    if (type == "hash")
                    {
                        std::string hash = std::any_cast<std::string>(task.second["hash"]);
                        std::string input = std::any_cast<std::string>(task.second["input"]);
                        double time = std::any_cast<double>(task.second["time"]);
                        std::string output_type = std::any_cast<std::string>(task.second["output_type"]);
                        if (status == 2)
                        {
                            std::string result = std::any_cast<std::string>(task.second["result"]);
                            std::cout <<
                                std::format("任务id:{}\n任务状态:{}\n任务类型:{} {}\n输入:{}\n总时间:{}\n输出格式:{}\n输出结果:{}\n",
                                    id, status_str, type, hash, input, fmt_time(time * ((1 / progress) - 1)), output_type, result
                                ) << std::endl;
                        }
                        else
                        {
                            std::cout <<
                                std::format("任务id:{}\n任务状态:{}\n任务进度:{:.2f}%\n任务类型:{} {}\n输入:{}\n预计时间:{}\n输出格式:{}\n",
                                    id, status_str, progress * 100, type, hash, input, fmt_time(time), output_type
                                ) << std::endl;
                        }
                    }
                    else
                    {
                        double time = std::any_cast<double>(task.second["time"]);
                        //std::cout << dog_data::json_any::to_json_str(task.second, true) << std::endl;
                        if (status != 2)
                        {
                            std::cout << std::format("任务id:{}\n任务状态:{}\n任务类型:{}\n输入:{}\n输出:{}\n预计时间:{}\n运行消息:{}\n",
                                id, status_str,
                                std::any_cast<std::string>(task.second["config"]),
                                std::any_cast<std::string>(task.second["input"]),
                                std::any_cast<std::string>(task.second["output"]),
                                fmt_time(time * ((1 / progress) - 1)),
                                std::any_cast<std::string>(task.second["msg"])
                            ) << std::endl;
                        }
                        else
                        {
                            std::cout << std::format("任务id:{}\n任务状态:{}\n任务类型:{}\n输入:{}\n输出:{}\n总计时间:{}\n运行消息:{}\n",
                                id, status_str,
                                std::any_cast<std::string>(task.second["config"]),
                                std::any_cast<std::string>(task.second["input"]),
                                std::any_cast<std::string>(task.second["output"]),
                                fmt_time(time),
                                std::any_cast<std::string>(task.second["msg"])
                            ) << std::endl;
                        }
                    }
                }
                break;
            }
            }
        }
        catch (std::exception& e)
        {
            std::cout << spilt(e.what(), '\n')[0] << std::endl;
        }
        std::cout << "输入任意键继续";
        std::cout.flush();
        std::getline(std::cin, operate_code_str);

        clear_print();
    }
    return 0;
}