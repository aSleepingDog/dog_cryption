#include<iostream>
#include<cstdint>
#include<thread>

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
std::unordered_map<std::string, std::any> get_data_type(std::string sign)
{
    std::string input = "";
    std::unordered_map<std::string, std::any> result;
    std::unordered_map<std::string, std::any> error;
    std::cout << std::format("请输入数据类型{}",sign) << std::endl;
    std::cout << "数据类型可以为 utf8 base64[][][] hex/Hex file" << std::endl;
    std::cout << "[]中可以填入 (空格) ! \" # $ % & ' ( ) * + , - .  / : ; < = > ? @ [ \\ ] ^ _ ` { | } ~ 其中两两不能相同" << std::endl;
    std::getline(std::cin, input);
    if (input == "utf8")
    {
        result["type"] = 0;
    }
    else if (input == "hex")
    {
        result["type"] = 2;
        result["is_upper"] = false;
    }
    else if (input == "Hex")
    {
        result["type"] = 2;
        result["is_upper"] = true;
    }
    else if (input == "file")
    {
        result["type"] = 3;
    }
    else if (input.size() >= 6)
    {
        result["type"] = 1;
        if (input.substr(0, 6) == "base64" && input.size() == 6)
        {
            result["char1"] = '+';
            result["char2"] = '/';
            result["char3"] = '=';
        }
        else if (input.substr(0, 6) == "base64" && input.size() == 9)
        {
            if (input[6] == input[7] || input[7] == input[8] || input[8] == input[6])
            {
                error["type"] = -1;
                error["msg"] = std::string("base64 +/=的替换字符两两不能相同");
                return error;
            }
            if (!effect_char(input[6], " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~") ||
                !effect_char(input[7], " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~") ||
                !effect_char(input[8], " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
                )
            {
                error["type"] = -1;
                error["msg"] = std::string("base64 +/=的替换字符只能是(空格) ! \" # $ % & ' ( ) * + , - .  / : ; < = > ? @ [ \\ ] ^ _ ` { | } ~");
                return error;
            }
            result["char1"] = input[6];
            result["char2"] = input[7];
            result["char3"] = input[8];
        }
        else
        {
            error["type"] = -1;
            error["msg"] = std::string("输入数据类型错误");
            return error;
        }
        return result;
    }
    else
    {
        error["type"] = -1;
        error["msg"] = std::string(std::format("{}数据类型错误", sign));
        return error;
    }
    return result;
}
std::unordered_map<std::string, std::any> get_hash_type()
{
    std::string input = "";
    uint64_t number = 0;
    std::unordered_map<std::string, std::any> result;
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
    std::cin >> input;
    std::cin >> number;
    for (auto one : dog_hash::list)
    {
        if (one.name == input)
        {
            if (dog_number::region::is_fall(one.region, number/8))
            {
                result["effective"] = true;
                auto d = dog_hash::HashCrypher(one.name, number / 8);
                result["hasher"] = dog_hash::HashCrypher(one.name, number/8);
            }
            else
            {
                result["effective"] = false;
                result["msg"] = std::string(std::format("{} 的散列类型不支持 {} 位", input, number));
            }
        }
    }
    if (result.size() == 0)
    {
        result["effective"] = false;
        result["msg"] = std::string(std::format("不支持的的散列类型 {}", input));
    }
    std::getline(std::cin, input);
    return result;
}
std::string fmt_time(double time)
{
    const std::vector<std::pair<uint64_t, std::string>> list = {
    {1000,"us"},{1000,"ms"},{60,"s"},{60,"min"},{24,"h"},{30,"d"}};
    std::string result = "";
    for (uint64_t i = 0; i < list.size(); ++i) {
        uint64_t nowPoint = (uint64_t)time % list[i].first;
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
        //std::cout << "3-数据对称加密" << std::endl;
        //std::cout << "4-数据对称解密" << std::endl;
        std::cout << "5-运行任务管理" << std::endl;
        std::cout << "0-退出当前程序" << std::endl;
        int operate_code = 0;
        std::cin >> operate_code;
        getchar();
        switch (operate_code)
        {
        case 0:
        {
            clear_print();
            is_running = false;
            break;
        }
        case 1:
        {
            clear_print();

            auto input_args = get_data_type("(输入)");
            if (std::any_cast<int>(input_args["type"]) == -1)
            {
                std::cout << std::any_cast<std::string>(input_args["msg"]) << std::endl;
                break;
            }
            if (std::any_cast<int>(input_args["type"]) == 3)
            {
                std::cout << "文本数据不支持文件类型" << std::endl;
                break;
            }
            
            std::string text = "";
            std::cout << "请输入要转换的文本数据" << std::endl;
            std::getline(std::cin, text);

            if (std::any_cast<int>(input_args["type"]) == 2)
            {
                if (!effect_str(text, "0123456789ABCDEFabcdef"))
                {
                    std::cout << "hex/Hex字符串只能由0123456789ABCDEFabcdef组成" << std::endl;
                    break;
                }
            }
            else if (std::any_cast<int>(input_args["type"]) == 1)
            {
                char range[66] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
                range[64] = std::any_cast<char>(input_args["char3"]);
                range[63] = std::any_cast<char>(input_args["char2"]);
                range[62] = std::any_cast<char>(input_args["char1"]);
                if (!effect_str(text, range))
                {
                    std::cout << std::format("base64{}{}{}只能由{}组成", range[63], range[64], range[65], range) << std::endl;
                    break;
                }
            }
            
            auto output_args = get_data_type("(输出)");
            
            dog_work::Timer timer;
            timer.start();
            dog_data::Data data(text, std::any_cast<int>(input_args["type"]));
            if (std::any_cast<int>(output_args["type"]) == -1)
            {
                std::cout << std::any_cast<std::string>(input_args["msg"]) << std::endl;
                break;
            }
            else if (std::any_cast<int>(output_args["type"]) == 0)
            {
                text = data.getUTF8String();
            }
            else if (std::any_cast<int>(output_args["type"]) == 1)
            {
                text = data.getBase64String(
                    std::any_cast<char>(output_args["char1"]),
                    std::any_cast<char>(output_args["char2"]),
                    std::any_cast<char>(output_args["char3"])
                );
            }
            else if (std::any_cast<int>(output_args["type"]) == 2)
            {
                text = data.getHexString(std::any_cast<bool>(output_args["is_upper"]));
            }
            timer.end();
            std::cout << std::format("----结果----\n{}\n----耗时----\n{:0.2f}ms\n", text, timer.get_time());
            break;
        }
        case 2:
        {
            clear_print();

            auto input_args = get_data_type("(输入)");
            if (std::any_cast<int>(input_args["type"]) == -1)
            {
                std::cout << std::any_cast<std::string>(input_args["msg"]) << std::endl;
                break;
            }

            std::string text = "";
            std::cout << "请输入要求散列的文本或者文件路径" << std::endl;
            std::getline(std::cin, text);
            
            //hash
            auto hash_args = get_hash_type();
            if (!std::any_cast<bool>(hash_args["effective"]))
            {
                std::cout << std::any_cast<std::string>(hash_args["msg"]) << std::endl;
                break;
            }
            dog_hash::HashCrypher hash_crypher = std::any_cast<dog_hash::HashCrypher>(hash_args["hasher"]);

            if (std::any_cast<int>(input_args["type"]) == 2)
            {
                if (!effect_str(text, "0123456789ABCDEFabcdef"))
                {
                    std::cout << "hex/Hex字符串只能由0123456789ABCDEFabcdef组成" << std::endl;
                    break;
                }
            }
            else if (std::any_cast<int>(input_args["type"]) == 1)
            {
                char range[66] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
                range[64] = std::any_cast<char>(input_args["char3"]);
                range[63] = std::any_cast<char>(input_args["char2"]);
                range[62] = std::any_cast<char>(input_args["char1"]);
                if (!effect_str(text, range))
                {
                    std::cout << std::format("base64{}{}{}只能由{}组成", range[63], range[64], range[65], range) << std::endl;
                    break;
                }
            }
            else if (std::any_cast<int>(input_args["type"]) == 3)
            {
                std::filesystem::path file_path(text);
                if (!std::filesystem::exists(file_path))
                {
                    std::cout << "文件不存在" << std::endl;
                    break;
                }
            }

            auto output_args = get_data_type("(输出)");
            if (std::any_cast<int>(input_args["type"]) != 3)
            {
                dog_work::Timer timer;
                timer.start();
                if (std::any_cast<int>(output_args["type"]) == -1)
                {
                    std::cout << std::any_cast<std::string>(output_args["msg"]) << std::endl;
                    break;
                }
                else if (std::any_cast<int>(output_args["type"]) == 0)
                {
                    text = hash_crypher.getStringHash(text).getUTF8String();
                }
                else if (std::any_cast<int>(output_args["type"]) == 1)
                {
                    text = hash_crypher.getStringHash(text).getBase64String(
                        std::any_cast<char>(output_args["char1"]),
                        std::any_cast<char>(output_args["char2"]),
                        std::any_cast<char>(output_args["char3"])
                    );
                }
                else if (std::any_cast<int>(output_args["type"]) == 2)
                {
                    text = hash_crypher.getStringHash(text).getHexString(std::any_cast<bool>(output_args["is_upper"]));
                }
                else if (std::any_cast<int>(output_args["type"]) == 3)
                {
                    std::cout << "散列输出不支持文件" << std::endl;
                    break;
                }
                timer.end();
                std::cout << std::format("----结果----\n{}\n----耗时----\n{:0.2f}ms\n", text, timer.get_time());
                break;
            }
            else
            {
                std::unordered_map<std::string, std::any> output_params;
                output_params["output_type"] = (uint64_t)std::any_cast<int>(output_args["type"]);
                if (std::any_cast<int>(output_args["type"]) == 1)
                {
                    output_params["replace0"] = std::any_cast<char>(output_args["char1"]);
                    output_params["replace1"] = std::any_cast<char>(output_args["char2"]);
                    output_params["replace2"] = std::any_cast<char>(output_args["char3"]);
                }
                else if (std::any_cast<int>(output_args["type"]) == 2)
                {
                    output_params["upper"] = std::any_cast<bool>(output_args["is_upper"]);
                }
                uint64_t id = task_pool->add_hash(text, hash_crypher, output_params);
                std::cout << std::format("----任务已添加----\n任务ID: {}\n", id) << std::endl;
                break;
            }
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
                                id, status_str, progress*100, type, hash, input, fmt_time(time), output_type
                            ) << std::endl;
                    }
                }
            }
        }
        }

        std::cout << "输入任意键继续";
        std::cout.flush();
        char c = getchar();

        clear_print();
    }

}