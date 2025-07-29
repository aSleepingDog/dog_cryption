#include "util.h"

void work::timer::start()
{
    start_point_ = std::chrono::steady_clock::now();
}
void work::timer::end()
{
    end_point_ = std::chrono::steady_clock::now();
}
double work::timer::get_time()
{
    return std::chrono::duration_cast<std::chrono::microseconds>(end_point_ - start_point_).count();
}
work::PausableThread::~PausableThread()
{
    this->stop();
}

void work::PausableThread::start()
{
    if (running_) return;
    running_ = true;
    //thread_ = std::thread(&PausableThread::run, this);
}

void work::PausableThread::pause()
{
    std::unique_lock<std::mutex> lock(mutex_);
    paused_ = true;
}

void work::PausableThread::resume()
{
    std::unique_lock<std::mutex> lock(mutex_);
    paused_ = false;
    cond_.notify_one();
}

void work::PausableThread::stop()
{
    {
        std::unique_lock<std::mutex> lock(mutex_);
        stop_ = true;
        paused_ = false; // 确保线程不会卡在等待上
    }
    cond_.notify_one();

    if (thread_.joinable()) {
        thread_.join();
    }
    running_ = false;
}

double work::PausableThread::get_progress()
{
    return this->progress_.load();
}

void work::PausableThread::run()
{
    while (!stop_)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        while (paused_ && !stop_)
        {
            cond_.wait(lock);
        }
        if (stop_) break;
        lock.unlock();
    }
    running_ = false;
}