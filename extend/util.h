#include <chrono>
#include <atomic>
#include <mutex>
#include <istream>
#include <sstream>
#include <ostream>
#include <fstream>
#include <thread>
#include <iostream>
#include <filesystem>
#include "../lib/dog_cryption.h"

namespace work
{
    class timer
    {
    private:
        std::chrono::steady_clock::time_point start_point_ = std::chrono::steady_clock::now();
        std::chrono::steady_clock::time_point end_point_ = std::chrono::steady_clock::now();;
    public:
        void start();
        void end();
        double get_time();

    };

    class task
    {
    private:
        uint64_t id;
        std::atomic<int> status;//0-running 1-success -1-fail
        std::atomic<double> progress;
        dog_data::Data result;
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

        uint64_t get_id() const;
        double get_progress();
        double get_micro_second();
        int get_status();
        std::string get_msg();
        std::string get_type();
        dog_data::Data get_result();
        std::thread * get_thread();
        

        friend bool operator==(const task& t1, const task& t2);
        
        void start_timer();
        void fail();
        void success();

        void stop();
        void set_msg(std::string msg);
        void set_thread(std::thread* thread);

        void start_hash_task(std::string hash, uint64_t effect, std::string input);
        void start_encrypt_task(bool with_config, bool with_check, bool with_iv, dog_data::Data iv, dog_cryption::CryptionConfig config, std::string input, std::string output);
        void start_decrypt_task(bool with_config, bool with_check, bool with_iv, dog_data::Data iv, dog_cryption::CryptionConfig config, std::string input, std::string output);

    };

    class taskInfo
    {
    public:
        uint64_t id;
        double progress;
        double microSecond;
        int status;
        std::string msg;
        dog_data::Data result;
        std::string type;
    
        taskInfo(task* t);
        taskInfo();
    };

    class taskPool
    {
    private:
        bool running = true;
        std::list<task*> tasks;
        std::deque<std::map<std::string,std::any>*> waiting;
        std::atomic<uint64_t> id;
        std::atomic<uint64_t> now_running;
        std::atomic<uint64_t> max_running;
        std::mutex pool_mutex;
    public:
        taskPool(uint64_t max_running);
        ~taskPool();
        
        work::taskInfo get_task_info(uint64_t id);

        void add();
        void sub();

        void add_hash(std::string hash, uint64_t effect, std::string input);
        void add_encrypt(bool with_config, bool with_check, bool with_iv, dog_cryption::CryptionConfig config, std::string iv, int32_t type, std::string input, std::string output);
        void add_decrypt(bool with_config, bool with_check, bool with_iv, dog_cryption::CryptionConfig config, std::string iv, int32_t type, std::string input, std::string output);
    };

    void hash_running(task* t, std::string hash, uint64_t effect, std::string input, taskPool* pool);
    void encrypt_running(task* t, bool with_config, bool with_check, bool with_iv, dog_data::Data iv_data, dog_cryption::CryptionConfig config, std::string input, std::string output, taskPool* pool);
    void decrypt_running(task* t, bool with_config, bool with_check, bool with_iv, dog_data::Data iv_data, dog_cryption::CryptionConfig config, std::string input, std::string output, taskPool* pool);
}