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

work::task::task(uint64_t id,std::string type)
{
    this->id = id;
    this->progress.store(0.0);
    this->status.store(-1);
    this->thread = nullptr;
    this->type = type;
    this->stimer.start();
}
work::task::task(task& other)
{
    this->id = other.id;
    this->progress.store(other.progress.load());
    this->status.store(other.status.load());
    this->msg = other.msg;
    this->result = other.result;
    this->thread = other.thread;
    this->stimer = other.stimer;
    this->type = other.type;
}
work::task::task(task&& other)
{
    std::lock_guard<std::mutex> lock(mutex);
    std::lock_guard<std::mutex> lock2(other.mutex);
    this->id = other.id;
    this->progress.store(other.progress.load());
    this->status.store(other.status.load());
    this->msg = std::move(other.msg);
    this->result = std::move(other.result);
    this->thread = std::move(other.thread);
    this->stimer = std::move(other.stimer);
    this->type = std::move(other.type);
}
work::task::task(task* other)
{
    this->id = other->id;
    this->progress.store(other->progress.load());
    this->status.store(other->status.load());
    this->msg = other->msg;
    this->result = other->result;
    this->thread = other->thread;
    this->stimer = other->stimer;
    this->type = other->type;
}
work::task::~task()
{
    if (this->thread != nullptr && this->thread->joinable())
    {
        this->thread->join();
    }
    delete this->thread;
    
}
uint64_t work::task::get_id() const
{
    return this->id;
}
double work::task::get_progress()
{
    return this->progress.load();
}
double work::task::get_micro_second()
{
    std::lock_guard<std::mutex> lock(mutex);
    return this->stimer.get_time();
}
int work::task::get_status()
{
    return this->status.load();
}
std::string work::task::get_msg()
{
    std::lock_guard<std::mutex> lock(mutex);
    return this->msg;
}
std::string work::task::get_type()
{
    std::lock_guard<std::mutex> lock(mutex);
    return this->type;
}
dog_data::Data work::task::get_result()
{
    std::lock_guard<std::mutex> lock(mutex);
    return this->result;
}
std::thread* work::task::get_thread()
{
    return this->thread;
}
bool work::operator==(const task& t1, const task& t2)
{
    if (t1.get_id() == t1.get_id())
    {
        return true;
    }
    return false;
}
void work::hash_running(task* t, std::string hash, uint64_t effect, std::string input, taskPool* pool)
{
    pool->add();
    try
    {
        t->start_timer();
        t->start_hash_task(hash, effect, input);
        t->success();
        t->set_msg("success");
    }
    catch (std::exception& e)
    {
        t->fail();
        t->set_msg(e.what());
    }
    pool->sub();
}
void work::encrypt_running(
    task* t, bool with_config, bool with_check, bool with_iv, 
    dog_data::Data iv_data, dog_cryption::CryptionConfig config, 
    std::string input, std::string output, taskPool* pool)
{
    pool->add();
    try
    {
        t->start_timer();
        t->start_encrypt_task(with_config, with_check, with_iv, iv_data, config, input, output);
        t->success();
        t->set_msg("success");
    }
    catch (std::exception& e)
    {
        t->fail();
        t->set_msg(e.what());
    }
    pool->sub();
}
void work::decrypt_running(
    task* t, bool with_config, bool with_check, bool with_iv, 
    dog_data::Data iv_data, dog_cryption::CryptionConfig config, 
    std::string input, std::string output, taskPool* pool)
{
    pool->add();
    try
    {
        t->start_timer();
        t->start_decrypt_task(with_config, with_check, with_iv, iv_data, config, input, output);
        t->success();
        t->set_msg("success");
    }
    catch (std::exception& e)
    {
        t->fail();
        t->set_msg(e.what());
    }
    pool->sub();
}

void work::task::start_timer()
{
    this->status.store(0);
    this->stimer.start();
}
void work::task::fail()
{
    this->status.store(-1);
    this->stimer.end();
}
void work::task::success()
{
    this->status.store(1);
    this->stimer.end();
}
void work::task::stop()
{
    this->progress.store(DBL_MIN * -1);
}
void work::task::set_msg(std::string msg)
{
    this->msg = msg;
}
void work::task::set_thread(std::thread* thread)
{
    this->thread = thread;
}

void work::task::start_hash_task(std::string hash, uint64_t effect, std::string input)
{
    dog_hash::HashCrypher hc(hash, effect);
    std::ifstream ifs(input, std::ios::binary);
    dog_hash::HashCrypher::streamHashp(hc, ifs, (&this->progress), &this->result);
}
void work::task::start_encrypt_task(bool with_config, bool with_check, bool with_iv, dog_data::Data iv,
    dog_cryption::CryptionConfig config, std::string input, std::string output)
{
    dog_cryption::Cryptor c(config);
    std::ifstream ifs(input, std::ios::binary);
    std::ofstream ofs(output, std::ios::binary);
    c.encryptp(ifs, ofs, with_config, with_iv, iv, with_check, &(this->progress));
}
void work::task::start_decrypt_task(bool with_config, bool with_check, bool with_iv, dog_data::Data iv,
    dog_cryption::CryptionConfig config, std::string input, std::string output)
{
    dog_cryption::Cryptor c(config);
    std::ifstream ifs(input, std::ios::binary);
    std::ofstream ofs(output, std::ios::binary);
    c.decryptp(ifs, ofs, with_config, with_iv, iv, with_check, &(this->progress));
}

work::taskPool::taskPool(uint64_t max_running)
{
    if (max_running > UINT64_MAX - 1) { throw std::runtime_error("max running too large"); }
    this->id.store(0);
    this->max_running.store(max_running);
    this->now_running.store(0);
    auto add_task = [this]()
        {
            while (this->running)
            {
                std::this_thread::sleep_for(std::chrono::seconds(5));
                if (this->now_running.load() >= this->max_running.load() || this->waiting.empty())
                {
                    continue;
                }
                auto args = this->waiting.front();
                this->waiting.pop_front();
                task* t = std::any_cast<task*>(args->at("task"));
                std::string type = std::any_cast<std::string>(args->at("type"));
                uint64_t effect = std::any_cast<uint64_t>(args->at("effect"));
                std::thread* thread = nullptr;
                if (type == "hash")
                {
                    std::string hash = std::any_cast<std::string>(args->at("hash"));
                    std::string input = std::any_cast<std::string>(args->at("input"));
                    thread = new std::thread(work::hash_running, t, hash, effect, input, this);
                }
                else if (type == "encrypt")
                {
                    bool with_config = std::any_cast<bool>(args->at("with_config"));
                    bool with_check = std::any_cast<bool>(args->at("with_check"));
                    bool with_iv = std::any_cast<bool>(args->at("with_iv"));
                    dog_data::Data iv = std::any_cast<dog_data::Data>(args->at("iv"));
                    dog_cryption::CryptionConfig config = std::any_cast<dog_cryption::CryptionConfig>(args->at("config"));
                    std::string input = std::any_cast<std::string>(args->at("input"));
                    std::string output = std::any_cast<std::string>(args->at("output"));
                    thread = new std::thread(work::encrypt_running, t, with_config, with_check, with_iv, iv, config, input, output, this);
                }
                else if (type == "decrypt")
                {
                    bool with_config = std::any_cast<bool>(args->at("with_config"));
                    bool with_check = std::any_cast<bool>(args->at("with_check"));
                    bool with_iv = std::any_cast<bool>(args->at("with_iv"));
                    dog_data::Data iv = std::any_cast<dog_data::Data>(args->at("iv"));
                    dog_cryption::CryptionConfig config = std::any_cast<dog_cryption::CryptionConfig>(args->at("config"));
                    std::string input = std::any_cast<std::string>(args->at("input"));
                    std::string output = std::any_cast<std::string>(args->at("output"));
                    thread = new std::thread(work::decrypt_running, t, with_config, with_check, with_iv, iv, config, input, output, this);
                }
                this->tasks.push_back(t);
                t->set_thread(thread);

            }
        };
}
work::taskPool::~taskPool()
{
    std::unique_lock<std::mutex> lock(pool_mutex); 
    this->running = false;
    for (auto& task : this->tasks) 
    {
        if (task->get_thread() && task->get_thread()->joinable())
        {
            task->stop();
            task->get_thread()->join();
        }
    }
}

work::taskInfo work::taskPool::get_task_info(uint64_t id)
{
    std::lock_guard<std::mutex> lock(pool_mutex);
    taskInfo ti;
    for (auto& task : this->tasks)
    {
        if (task->get_id() == id)
        {
            ti = taskInfo(task);
            if(ti.status != 0)
            {
                this->tasks.remove(task);
            }
            break;
        }
    }
    return ti;
}

void work::taskPool::add()
{
    this->now_running.store(this->now_running.load() + 1);
}
void work::taskPool::sub()
{
    this->now_running.store(this->now_running.load() - 1);
}

void work::taskPool::add_hash(std::string hash, uint64_t effect, std::string input)
{
    work::task* t = new work::task(this->id.load(), "hash");
    this->id.store(this->id.load() + 1);
    std::filesystem::path p(input);
    if (!std::filesystem::exists(p))
    {
        t->set_msg("file not exist");
        t->fail();
        return;
    }
    std::map<std::string, std::any>* args = new std::map<std::string, std::any>();
    args->at("type") = "hash";
    args->at("task") = t;
    args->at("hash") = hash;
    args->at("effect") = effect;
    args->at("input") = input;
    //args->at("pool") = this;
    this->waiting.push_back(args);
}
void work::taskPool::add_encrypt(
    bool with_config, bool with_check, bool with_iv, 
    dog_cryption::CryptionConfig config, std::string iv, int32_t type, 
    std::string input, std::string output)
{
    work::task* t = new work::task(this->id.load(), "encrypt");
    this->id.store(this->id.load() + 1);
    this->tasks.push_back(t);
    std::filesystem::path p(input);                                                                                                                                                                                                 
    if (!std::filesystem::exists(p))
    {
        t->set_msg("file not exist");
        t->fail();
        return;
    }
    dog_data::Data iv_data(iv, type);
    std::map<std::string, std::any>* args = new std::map<std::string, std::any>();
    args->at("type") = "encrypt";
    args->at("task") = t;
    args->at("with_config") = with_config;
    args->at("with_check") = with_check;
    args->at("with_iv") = with_iv;
    args->at("iv") = iv_data;
    args->at("config") = config;
    args->at("input") = input;
    args->at("output") = output;
    //args->at("pool") = this;
    this->waiting.push_back(args);
}
void work::taskPool::add_decrypt(
    bool with_config, bool with_check, bool with_iv, 
    dog_cryption::CryptionConfig config, std::string iv, int32_t type, 
    std::string input, std::string output)
{
    work::task* t = new work::task(this->id.load(), "decrypt");
    this->id.store(this->id.load() + 1);
    this->tasks.push_back(t);
    std::filesystem::path p(input);
    if (!std::filesystem::exists(p))
    {
        t->set_msg("file not exist");
        t->fail();
        return;
    }
    dog_data::Data iv_data(iv, type);
    std::map<std::string, std::any>* args = new std::map<std::string, std::any>();
    args->at("type") = "decrypt";
    args->at("task") = t;
    args->at("with_config") = with_config;
    args->at("with_check") = with_check;
    args->at("with_iv") = with_iv;
    args->at("iv") = iv_data;
    args->at("config") = config;
    args->at("input") = input;
    args->at("output") = output;
    //args->at("pool") = this;
    this->waiting.push_back(args);
}

work::taskInfo::taskInfo(task* t)
{
    this->id = t->get_id();
    this->progress = t->get_progress();
    this->microSecond = t->get_micro_second();
    this->status = t->get_status();
    this->msg = t->get_msg();
    this->result = t->get_result();
    this->type = t->get_type();
}

work::taskInfo::taskInfo()
{
    this->id = UINT64_MAX;
}
