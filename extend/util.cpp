#include "util.h"

void work::Timer::start()
{
    start_point_ = std::chrono::steady_clock::now();
}
void work::Timer::end()
{
    end_point_ = std::chrono::steady_clock::now();
}
void work::Timer::pause()
{
    if (!this->paused_)
    {
        end_point_ = std::chrono::steady_clock::now();
        this->times.push_back(std::chrono::duration_cast<std::chrono::microseconds>(end_point_ - start_point_).count());
        this->paused_ = true;
    }
}
void work::Timer::resume()
{
    start_point_ = std::chrono::steady_clock::now();
    this->paused_ = false;
}
double work::Timer::get_time()
{
    double now = 0;
    if (!this->paused_)
    {
        end_point_ = std::chrono::steady_clock::now();
        now = std::chrono::duration_cast<std::chrono::microseconds>(end_point_ - start_point_).count();
    }
    for (double time : this->times)
    {
        now += time;
    }
    return now;
}

work::PausableThread::~PausableThread()
{
    this->stop();
    this->thread_.join();
}
void work::PausableThread::start()
{
    if (running_) return;
    running_ = true;
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

    running_ = false;
}
double work::PausableThread::get_progress()
{
    return this->progress_.load();
}
int work::PausableThread::get_status()
{
    //0-running, 1-paused, 2-stopped
    if (running_ && !paused_) return 0;
    else if (running_ && paused_) return 1;
    else if (!running_) return 2;
}

void work::PausableThread::run(std::string type, Task* task, std::unordered_map<std::string, std::any>* params)
{
    if (type == "hash")
    {
        auto work = [this, params, task]()->void
            {
                dog_hash::HashCrypher hash_crypher = std::any_cast<dog_hash::HashCrypher>((*params)["hash_crypher"]);
                //std::cout << std::any_cast<std::string>((*params)["input"]) << std::endl;
                std::ifstream input = std::ifstream(std::any_cast<std::string>((*params)["input"]));
                task->timer.start();
                dog_hash::HashCrypher::streamHashp(hash_crypher, input, std::any_cast<dog_data::Data*>((*params)["result"]),
                    &this->mutex_, &this->cond_, &this->progress_, &this->running_, &this->paused_, &this->stop_);
                task->timer.end();
                this->stop();
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
                    std::ifstream input = std::ifstream(std::any_cast<std::string>((*params)["input"]), std::ios::binary);
                    std::ofstream output = std::ofstream(std::any_cast<std::string>((*params)["output"]), std::ios::binary);
                    bool with_config = std::any_cast<bool>((*params)["with_config"]);
                    bool with_iv = std::any_cast<bool>((*params)["with_iv"]);
                    bool with_check = std::any_cast<bool>((*params)["with_check"]);
                    dog_data::Data iv = std::any_cast<dog_data::Data>((*params)["iv"]);
                    task->timer.start();
                    cryptor.encryptp(input, output, with_config, with_iv, iv, with_check,
                        &this->mutex_, &this->cond_, &this->progress_, &this->running_, &this->paused_, &this->stop_);
                }
                catch (std::exception& e)
                {
                    std::string temp = "内部错误, 请保留日志并联系开发人员";
                    temp += e.what();
                    task->set_msg(temp);
                }
                task->timer.end();
                this->stop();
            };
        std::thread thread(work);
        this->thread_ = std::move(thread);
    }
    else if (type == "decrypt")
    {
        auto work = [this, params, task]()->void
            {
                try
                {
                    dog_cryption::Cryptor cryptor = std::any_cast<dog_cryption::Cryptor>((*params)["cryptor"]);
                    std::ifstream input = std::ifstream(std::any_cast<std::string>((*params)["input"]), std::ios::binary);
                    std::ofstream output = std::ofstream(std::any_cast<std::string>((*params)["output"]), std::ios::binary);
                    bool with_config = std::any_cast<bool>((*params)["with_config"]);
                    bool with_iv = std::any_cast<bool>((*params)["with_iv"]);
                    bool with_check = std::any_cast<bool>((*params)["with_check"]);
                    dog_data::Data iv = std::any_cast<dog_data::Data>((*params)["iv"]);
                    task->timer.start();
                    cryptor.decryptp(input, output, with_config, with_iv, iv, with_check,
                        &this->mutex_, &this->cond_, &this->progress_, &this->running_, &this->paused_, &this->stop_);
                }
                catch (dog_cryption::WrongKeyException& e)
                {
                    task->set_msg("密钥校验失败,请输入正确的密钥");
                }
                catch (dog_cryption::WrongConfigException& e)
                {
                    task->set_msg("前导加密配置错误,请确保配置字节不被修改");
                }
                catch (std::exception& e)
                {
                    std::string msg = "内部错误,请保留日志并联系开发人员";
                    msg += e.what();
                    task->set_msg(msg);
                }
                task->timer.end();
                this->stop();
            };
        std::thread thread(work);
        this->thread_ = std::move(thread);
    }
}

work::Task::Task(uint64_t id, std::string input, dog_hash::HashCrypher hash_crypher, std::unordered_map<std::string, std::any> output_params)
{
    this->id_ = id;
    this->params_ = new std::unordered_map<std::string, std::any>();
    this->type_ = "hash";
    (*this->params_)["input"] = input;
    (*this->params_)["hash_crypher"] = hash_crypher;
    (*this->params_)["result"] = &(this->result_);
    (*this->params_)["output_type"] = output_params["output_type"];
    if (std::any_cast<uint64_t>(output_params["output_type"]) == 2)
    {
        (*this->params_)["upper"] = output_params["upper"];
        this->output = std::any_cast<bool>(output_params["upper"]) ? "HEX 全大写16进制" : "HEX 全小写16进制";
    }
    else if (std::any_cast<uint64_t>(output_params["output_type"]) == 1)
    {
        (*this->params_)["replace0"] = output_params["replace0"];
        (*this->params_)["replace1"] = output_params["replace1"];
        (*this->params_)["replace2"] = output_params["replace2"];
        std::string temp = "Base64";
        temp += (std::any_cast<char>(output_params["replace0"]));
        temp += (std::any_cast<char>(output_params["replace1"]));
        temp += (std::any_cast<char>(output_params["replace2"]));
        this->output = temp;
    }
}
work::Task::Task(uint64_t id, int type, std::string input, std::string output, dog_cryption::Cryptor& cryptor, 
    dog_data::Data iv, bool with_config, bool with_iv, bool with_check)
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
    std::lock_guard<std::mutex> lock(this->mutex_);
    return this->id_;
}
work::Task::~Task()
{
    this->stop();
    delete this->params_;
    delete this->thread_;
}
int work::Task::get_status()
{
    return this->thread_ == nullptr ? -1 : this->thread_->get_status();
}
void work::Task::start()
{
    auto thread = new PausableThread();
    this->thread_ = thread;
    thread->run(this->type_, this, this->params_);
    thread->start();
}
void work::Task::pause()
{
    this->thread_->pause();
    this->timer.pause();
}
void work::Task::resume()
{
    this->thread_->resume();
    this->timer.resume();
}
void work::Task::stop()
{
    this->thread_->stop();
}
std::unordered_map<std::string, std::any> work::Task::get_info()
{
    std::lock_guard<std::mutex> lock(this->mutex_);
    std::unordered_map<std::string, std::any> res;
    res["id"] = this->id_;
    res["type"] = this->type_;
    res["status"] = this->thread_ == nullptr ? -1 : this->thread_->get_status();
    res["progress"] = this->thread_ == nullptr ? -1.0 : this->thread_->get_progress();
    if (this->type_ == "hash")
    {
        res["hash"] = std::any_cast<dog_hash::HashCrypher>(this->params_->at("hash_crypher")).get_config();
        res["input"] = this->params_->at("input");
        res["time"] = this->timer.get_time();
        res["output_type"] = this->output;
        if (std::any_cast<int>(res["status"]) == 2)
        {
            switch (std::any_cast<uint64_t>(this->params_->at("output_type")))
            {
            case 0:
            {
                res["result"] = this->result_.getUTF8String();
                break;
            }
            case 1:
            {
                char replace0 = std::any_cast<char>(this->params_->at("replace0"));
                char replace1 = std::any_cast<char>(this->params_->at("replace1"));
                char replace2 = std::any_cast<char>(this->params_->at("replace2"));
                res["result"] = this->result_.getBase64String(replace0, replace1, replace2);
                break;
            }
            case 2:
            {
                bool upper = std::any_cast<bool>(this->params_->at("upper"));
                res["result"] = this->result_.getHexString(upper);
                break;
            }
            }
            res["msg"] = "完成";
        }
        else
        {
            res["msg"] = "正在运行";
        }
    }
    else
    {
        res["config"] = std::any_cast<dog_cryption::Cryptor>(this->params_->at("cryptor")).get_config().to_string()
            + ((std::any_cast<bool>(this->params_->at("with_config"))) ? "_withConfig" : "_withoutConfig")
            + ((std::any_cast<bool>(this->params_->at("with_iv"))) ? "_withIV" : "_withoutIV")
            + ((std::any_cast<bool>(this->params_->at("with_check"))) ? "_withCheck" : "_withoutCheck");
        res["input"] = this->params_->at("input");
        res["output"] = this->params_->at("output");
        res["time"] = this->timer.get_time();
        res["msg"] = this->msg_;
    }
    return res;
}

void work::TaskPool::manage(TaskPool* task_pool)
{
    try
    {
        //2025.7.30 在优化情况下,这里的逻辑被莫名奇妙地省掉了,一直报错,加上了异常处理就正常了.
        int32_t flag = task_pool->flag_.load();
        while (flag != 0)
        {
            std::lock_guard<std::mutex> lock(task_pool->mutex_);
            if (flag == 1 && !task_pool->waitting_.empty() && task_pool->running_.size() < task_pool->max_)
            {
                Task* task = task_pool->waitting_.front();
                task_pool->waitting_.pop_front();
                task->start();
                task_pool->running_.emplace_back(task);
            }
        }
    }
    catch (std::exception& e)
    {
        std::cout << e.what() << std::endl;
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
std::vector<std::unordered_map<std::string, std::any>> work::TaskPool::get_all_running_task_info()
{
    std::lock_guard<std::mutex> lock(this->mutex_);
    std::vector<std::unordered_map<std::string, std::any>> res;
    std::vector<std::deque<work::Task*>::iterator> to_delete;
    for (auto it = this->running_.begin(); it != this->running_.end(); it++)
    {
        res.emplace_back((*it)->get_info());
        if ((*it)->get_status() == 2)
        {
            to_delete.emplace_back(it);
        }
    }
    for (auto task : to_delete)
    {
        Task* temp = *task;
        this->running_.erase(task);
        delete temp;
    }
    return res;
}
std::vector<std::unordered_map<std::string, std::any>> work::TaskPool::get_all_waitting_task_info()
{
    std::lock_guard<std::mutex> lock(this->mutex_);
    std::vector<std::unordered_map<std::string, std::any>> res;
    for (auto it = this->waitting_.begin(); it != this->waitting_.end(); it++)
    {
        res.emplace_back((*it)->get_info());
    }
    return res;
}
std::unordered_map<std::string, std::any> work::TaskPool::get_waitting_task_info(uint64_t id)
{
    std::lock_guard<std::mutex> lock(this->mutex_);
    std::unordered_map<std::string, std::any> res;
    std::deque<work::Task*>::iterator to_delete = this->waitting_.end();
    for (auto it = this->waitting_.begin(); it != this->waitting_.end(); it++)
    {
        res = (*it)->get_info();
        if ((*it)->get_status() == 2)
        {
            to_delete = it;
        }
    }
    if (to_delete != this->waitting_.end())
    {
        Task* temp = *to_delete;
        this->waitting_.erase(to_delete);
        delete temp;
    }
    return res;
}
std::unordered_map<std::string, std::any> work::TaskPool::get_running_task_info(uint64_t id)
{
    std::lock_guard<std::mutex> lock(this->mutex_);
    std::unordered_map<std::string, std::any> res;
    std::deque<work::Task*>::iterator to_delete = this->running_.end();
    for (auto it = this->running_.begin(); it != this->running_.end(); it++)
    {
        res = (*it)->get_info();
        if ((*it)->get_status() == 2)
        {
            to_delete = it;
        }
    }
    if (to_delete != this->running_.end())
    {
        Task* temp = *to_delete;
        this->running_.erase(to_delete);
        delete temp;
    }
    return res;
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

uint64_t work::TaskPool::add_hash(std::string path, dog_hash::HashCrypher& hash_crypher, std::unordered_map<std::string, std::any> output_params)
{
    uint64_t id = this->id_.load();
    this->id_.fetch_add(1);
    if (!std::filesystem::exists(std::filesystem::path(path)))
    {
        throw std::runtime_error("File not exist");
    }
    Task* task = new Task(id, path, hash_crypher, output_params);
    this->waitting_.emplace_back(task);
    return id;
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

