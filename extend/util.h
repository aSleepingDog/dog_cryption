#include <chrono>
#include <atomic>
#include <mutex>
#include <istream>
#include <sstream>
#include <ostream>
#include <fstream>
#include "../lib/dog_cryption.h"

namespace work
{
    class timer
    {
    private:
        std::chrono::steady_clock::time_point startPoint = std::chrono::steady_clock::now();
        std::chrono::steady_clock::time_point endPoint = std::chrono::steady_clock::now();;
    public:
        void start();
        void end();
        double getTime();

    };

    class task
    {
    private:
        uint64_t id;
        std::atomic<int> status;//0-running 1-success -1-fail
        std::atomic<double> progress;
        DogData::Data result;
        std::string type;
        std::string msg;
        std::thread* thread = nullptr;
        timer stimer;
        std::mutex mutex;
    public:
        task(uint64_t id, std::string type);
        //拷贝
        task(task& other);
        //移动
        task(task&& other);
        task(task* other);

        ~task();

        uint64_t getId() const;
        double getProgress();
        double getMicroSecond();
        int getStatus();
        std::string getMsg();
        std::string getType();
        DogData::Data getResult();
        std::thread* getThread();
        

        friend bool operator==(const task& t1, const task& t2);
        
        void start();
        void fail();
        void success();

        void stop();
        void setMsg(std::string msg);
        void setThread(std::thread* thread);

        void startHash(std::string medhod,std::string path);
        void startEncrypt(DogCryption::cryption_config config, DogData::Data key, std::string input_path, std::string output_path);
        void startEncrypt(DogCryption::cryption_config config, DogData::Data key, std::string input_path, bool withConfig, std::string output_path);
        void startDecrypt(DogCryption::cryption_config config, DogData::Data key, std::string input_path, std::string output_path);
        void startDecrypt(DogCryption::cryption_config config, DogData::Data key, std::string input_path, bool withConfig, std::string output_path);
    };

    class taskInfo
    {
    public:
        uint64_t id;
        double progress;
        double microSecond;
        int status;
        std::string msg;
        DogData::Data result;
        std::string type;
    
        taskInfo(task* t);
        taskInfo();
    };

    class taskPool
    {
    private:
        std::list<task*> tasks;
        std::atomic<uint64_t> id;
        std::atomic<uint64_t> now_running;
        std::atomic<uint64_t> max_running;
        std::mutex pool_mutex;
    public:
        taskPool(uint64_t max_running);
        ~taskPool();
        uint64_t add_hash_task(std::string method, std::string path);
        uint64_t add_encrypt_task(DogCryption::cryption_config config, DogData::Data key, std::string input_path, std::string output_path);
        uint64_t add_encrypt_task(DogCryption::cryption_config config, DogData::Data key, std::string input_path, bool withConfig, std::string output_path);
        uint64_t add_decrypt_task(DogCryption::cryption_config config, DogData::Data key, std::string input_path, std::string output_path);
        uint64_t add_decrypt_task(DogCryption::cryption_config config, DogData::Data key, std::string input_path, bool withConfig, std::string output_path);
        
        work::taskInfo get_task_info(uint64_t id);
    };
}