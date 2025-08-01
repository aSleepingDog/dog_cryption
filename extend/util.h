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
    class Task;
    class TaskPool;

    class Timer
    {
    private:
        std::chrono::steady_clock::time_point start_point_ = std::chrono::steady_clock::now();
        std::chrono::steady_clock::time_point end_point_ = std::chrono::steady_clock::now();;
        std::vector<double> times;
        bool paused_ = false;
    public:
        void start();
        void end();
        void pause();
        void resume();
        double get_time();

    };

    class PausableThread
    {
    private:
        std::thread thread_;

        std::mutex mutex_;
        std::condition_variable cond_;

        std::atomic<double> progress_;
        std::atomic<bool> running_;
        std::atomic<bool> paused_;
        std::atomic<bool> stop_;
    public:
        PausableThread() : running_(false), paused_(false), stop_(false), progress_(0) {}
        ~PausableThread();
        void start();
        void pause();
        void resume();
        void stop();
        double get_progress();
        bool isRunning() const { return running_; }
        bool isPaused() const { return paused_; }

        int get_status();//0-running, 1-paused, 2-stopped

        void run(std::string type, Task* task, std::unordered_map<std::string, std::any>* params);
    };

    class Task
    {
    private:
        uint64_t id_;
        PausableThread* thread_ = nullptr;
        std::string output;
        dog_data::Data result_;
        std::string type_;
        std::string msg_ = "运行正常";

        std::mutex mutex_;
        std::unordered_map<std::string, std::any>* params_ = nullptr;
    public:
        Timer timer;
        Task(uint64_t id, std::string input, dog_hash::HashCrypher hash_crypher, std::unordered_map<std::string, std::any> output_params);
        Task(uint64_t id, int type, std::string input, std::string output, dog_cryption::Cryptor& cryptor,
            dog_data::Data iv, bool with_config, bool with_iv, bool with_check);
        uint64_t get_id();

        ~Task();

        int get_status();

        void start();
        void pause();
        void resume();
        void stop();

        std::unordered_map<std::string, std::any> get_info();
        void set_msg(std::string msg) { msg_ = msg; }
    };

    template <typename T>
    class SafeDeque
    {
    private:
        using it = typename std::deque<T>::iterator;
        using rit = typename std::deque<T>::reverse_iterator;
        using cit = typename std::deque<T>::const_iterator;
        using crit = typename std::deque<T>::const_reverse_iterator;
        std::mutex mutex_;
        std::deque<T> deque_;
    public:
        bool empty() const { return deque_.empty(); }
        uint64_t size() const { return deque_.size(); }

        T& front() { std::lock_guard<std::mutex> lock(mutex_); return deque_.front(); }
        T& back() { std::lock_guard<std::mutex> lock(mutex_); return deque_.back(); }
        T& operator[](uint64_t index) { std::lock_guard<std::mutex> lock(mutex_); return deque_[index]; }
        T& at(uint64_t index) { std::lock_guard<std::mutex> lock(mutex_); return deque_.at(index); }
        void pop_front() { std::lock_guard<std::mutex> lock(mutex_); deque_.pop_front(); }
        void emplace_back(T& t) { std::lock_guard<std::mutex> lock(mutex_); deque_.emplace_back(t); }
        void emplace_back(T&& t) { std::lock_guard<std::mutex> lock(mutex_); deque_.emplace_back(t); }
        it begin() { std::lock_guard<std::mutex> lock(mutex_); return deque_.begin(); }
        it end() { std::lock_guard<std::mutex> lock(mutex_); return deque_.end(); }

        void erase(it it) { std::lock_guard<std::mutex> lock(mutex_); deque_.erase(it); }
    };

    class TaskPool
    {
    private:
        std::mutex mutex_;
        std::atomic<uint64_t> id_ = 0;
        std::jthread* manager_;
        uint64_t max_ = 0;
        SafeDeque<Task*> waitting_;
        SafeDeque<Task*> running_;
        std::atomic<int32_t> flag_ = 0;//0:stop, 1:running, -1:pause
    public:
        TaskPool(uint64_t max);
        ~TaskPool();
        
        void stop();
        void pause();
        void resume();

        std::vector<std::unordered_map<std::string, std::any>> get_all_running_task_info();
        std::vector<std::unordered_map<std::string, std::any>> get_all_waitting_task_info();

        std::unordered_map<std::string, std::any> get_waitting_task_info(uint64_t id);
        std::unordered_map<std::string, std::any> get_running_task_info(uint64_t id);

        int32_t stop_task(uint64_t id);
        int32_t pause_task(uint64_t id);
        int32_t resume_task(uint64_t id);

        uint64_t add_hash(std::string path, dog_hash::HashCrypher& hash_crypher, std::unordered_map<std::string,std::any> output_params);
        uint64_t add_encrypt(std::string input_path, std::string output_path, dog_cryption::Cryptor& cryptor, 
            dog_data::Data iv, bool with_config, bool with_iv, bool with_check);
        uint64_t add_decrypt(std::string input_path, std::string output_path, dog_cryption::Cryptor& cryptor,
            dog_data::Data iv, bool with_config, bool with_iv, bool with_check);


        static void manage(TaskPool* task_pool);
    };

    
}