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

    class PausableThread {
    private:
        std::thread thread_;
        std::mutex mutex_;
        std::condition_variable cond_;
        std::atomic<double> progress_;
        std::atomic<bool> running_;
        std::atomic<bool> paused_;
        std::atomic<bool> stop_;
    public:
        PausableThread() : running_(false), paused_(false), stop_(false) {}
        ~PausableThread();
        void start();
        void pause();
        void resume();
        void stop();
        double get_progress();
        bool isRunning() const { return running_; }
        bool isPaused() const { return paused_; }

    private:
        void run();

    };

    
}