#include "util.h"

void work::Timer::start()
{
    start_point_ = std::chrono::steady_clock::now();
}
void work::Timer::end()
{
    end_point_ = std::chrono::steady_clock::now();
}
double work::Timer::get_time()
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
void work::PausableThread::run(std::string type, Task* task, std::unordered_map<std::string, std::any>* params)
{
    if (type == "hash")
    {
        auto work = [this, params, task]()->void
            {
                dog_hash::HashCrypher hash_crypher = std::any_cast<dog_hash::HashCrypher>((*params)["hash_crypher"]);
                std::ifstream input = std::ifstream(std::any_cast<std::string>((*params)["input"]));
                task->timer.start();
                dog_hash::HashCrypher::streamHashp(hash_crypher, input, std::any_cast<dog_data::Data*>((*params)["result"]),
                    &this->mutex_, &this->cond_, &this->progress_, &this->running_, &this->paused_, &this->stop_);
                task->timer.end();
            };
        std::thread thread(work);
        this->thread_ = std::move(thread);
    }
    else if (type == "encrypt")
    {
        auto work = [this, params, task]()->void
            {
                try
                {
                    dog_cryption::Cryptor cryptor = std::any_cast<dog_cryption::Cryptor>((*params)["cryptor"]);
                    std::ifstream input = std::ifstream(std::any_cast<std::string>((*params)["input"]));
                    std::ofstream output = std::ofstream(std::any_cast<std::string>((*params)["output"]));
                    bool with_config = std::any_cast<bool>((*params)["with_config"]);
                    bool with_iv = std::any_cast<bool>((*params)["with_iv"]);
                    bool with_check = std::any_cast<bool>((*params)["with_check"]);
                    dog_data::Data iv = std::any_cast<dog_data::Data>((*params)["iv"]);
                    task->timer.start();
                    cryptor.encryptp(input, output, with_config, with_iv, iv, with_check,
                        &this->mutex_, &this->cond_, &this->progress_, &this->running_, &this->paused_, &this->stop_);
                    task->timer.end();
                }
                catch (std::exception& e)
                {

                }
            };
        std::thread thread(work);
        this->thread_ = std::move(thread);
    }
    else if (type == "decrypt")
    {

    }
}
//void work::PausableThread::run()
//{
//    while (!stop_)
//    {
//        std::unique_lock<std::mutex> lock(mutex_);
//        while (paused_ && !stop_)
//        {
//            cond_.wait(lock);
//        }
//        if (stop_) break;
//        lock.unlock();
//    }
//    running_ = false;
//}

work::Task::Task(uint64_t id, std::string input, dog_hash::HashCrypher hash_crypher)
{
    this->id_ = id;
    this->params_ = new std::unordered_map<std::string, std::any>();
    this->type_ = "hash";
    (*this->params_)["input"] = input;
    (*this->params_)["hash_crypher"] = hash_crypher;
    (*this->params_)["result"] = &(this->result_);
}
work::Task::Task(uint64_t id, int type, std::string input, std::string output, dog_cryption::Cryptor& cryptor, dog_data::Data iv, bool with_config, bool with_iv, bool with_check)
{
    this->id_ = id;
    this->params_ = new std::unordered_map<std::string, std::any>();
    if (type == 1)
    {
        this->type_ = "encrypt";
    }
    else if (type == -1)
    {
        this->type_ = "decrypt";
    }
    (*this->params_)["input"] = input;
    (*this->params_)["output"] = output;
    (*this->params_)["cryptor"] = cryptor;
    (*this->params_)["iv"] = iv;
    (*this->params_)["with_config"] = with_config;
    (*this->params_)["with_iv"] = with_iv;
    (*this->params_)["with_check"] = with_check;
}

uint64_t work::Task::get_id()
{
    std::lock_guard<std::mutex>(this->mutex_);
    return this->id_;
}
void work::Task::start()
{
    auto thread = new PausableThread();
    this->thread_ = thread;
    thread->run(this->type_, this, this->params_);
}
void work::Task::pause()
{
    this->thread_->pause();
}
void work::Task::resume()
{
    this->thread_->resume();
}
void work::Task::stop()
{
    this->thread_->stop();
}

void work::TaskPool::manage(TaskPool* task_pool)
{
    int32_t flag = task_pool->flag_.load();
    while (flag != 0)
    {
        if (flag == 1 && !task_pool->waitting_.empty() && task_pool->running_.size() < task_pool->max_)
        {
            Task* task = task_pool->waitting_.front();
            task_pool->waitting_.pop_front();
            
            task_pool->running_.emplace_back(task);
        }
    }
}
work::TaskPool::TaskPool(uint64_t max)
{
    this->max_ = max;
    this->flag_.store(1);
    this->manager_ = new std::jthread(&TaskPool::manage, this);
}
work::TaskPool::~TaskPool()
{
    this->stop();
    for (auto& task : this->running_)
    {
        task->stop();
    }
    if (this->manager_->joinable())
    {
        this->manager_->join();
    }
    delete this->manager_;
}
void work::TaskPool::stop()
{
    this->flag_.store(0);
}
void work::TaskPool::pause()
{
    this->flag_.store(-1);
}
void work::TaskPool::resume()
{
    this->flag_.store(1);
}
int32_t work::TaskPool::stop_task(uint64_t id)
{
    for (auto& task : this->running_)
    {
        if (task->get_id() == id)
        {
            task->stop();
            return 0;
        }
    }
    return -1;
}
int32_t work::TaskPool::pause_task(uint64_t id)
{
    for (auto& task : this->running_)
    {
        if (task->get_id() == id)
        {
            task->pause();
            return 0;
        }
    }
    return -1;
}
int32_t work::TaskPool::resume_task(uint64_t id)
{
    for (auto& task : this->running_)
    {
        if (task->get_id() == id)
        {
            task->resume();
            return 0;
        }
    }
    return -1;
}

uint64_t work::TaskPool::add_hash(std::string path, dog_hash::HashCrypher& hash_crypher)
{
    uint64_t id = this->id_.load();
    this->id_.fetch_add(1);
    if (!std::filesystem::exists(std::filesystem::path(path)))
    {
        throw std::runtime_error("File not exist");
    }
    Task* task = new Task(id, path, hash_crypher);
    this->waitting_.emplace_back(task);
}
uint64_t work::TaskPool::add_encrypt(std::string input_path, std::string output_path, dog_cryption::Cryptor& cryptor, 
    dog_data::Data iv, bool with_config, bool with_iv, bool with_check)
{
    uint64_t id = this->id_.load();
    this->id_.fetch_add(1);
    Task* task = new Task(id, 1, input_path, output_path, cryptor, iv, with_config, with_iv, with_check);
    this->waitting_.emplace_back(task);
    return id;
}
uint64_t work::TaskPool::add_decrypt(std::string input_path, std::string output_path, dog_cryption::Cryptor& cryptor, 
    dog_data::Data iv, bool with_config, bool with_iv, bool with_check)
{
    uint64_t id = this->id_.load();
    this->id_.fetch_add(1);
    Task* task = new Task(id, -1, input_path, output_path, cryptor, iv, with_config, with_iv, with_check);
    this->waitting_.emplace_back(task);
    return id;
}

