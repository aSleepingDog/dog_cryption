#include "util.h"

void work::timer::start()
{
    startPoint = std::chrono::steady_clock::now();
}
void work::timer::end()
{
    endPoint = std::chrono::steady_clock::now();
}
double work::timer::getTime()
{
    endPoint = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(endPoint - startPoint).count();
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
uint64_t work::task::getId() const
{
    return this->id;
}
double work::task::getProgress()
{
    return this->progress.load();
}
double work::task::getMicroSecond()
{
    std::lock_guard<std::mutex> lock(mutex);
    return this->stimer.getTime();
}
int work::task::getStatus()
{
    return this->status.load();
}
std::string work::task::getMsg()
{
    std::lock_guard<std::mutex> lock(mutex);
    return this->msg;
}
std::string work::task::getType()
{
    std::lock_guard<std::mutex> lock(mutex);
    return this->type;
}
DogData::Data work::task::getResult()
{
    std::lock_guard<std::mutex> lock(mutex);
    return this->result;
}
std::thread* work::task::getThread()
{
    return this->thread;
}
bool work::operator==(const task& t1, const task& t2)
{
    if (t1.getId() == t1.getId())
    {
        return true;
    }
    return false;
}
void work::task::start()
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
void work::task::setMsg(std::string msg)
{
    this->msg = msg;
}
void work::task::setThread(std::thread* thread)
{
    this->thread = thread;
}
void work::task::startHash(std::string medhod, std::string path)
{
    DogHash::hash_crypher h(medhod);
    std::ifstream input(path, std::ios::binary);
    DogData::Data result;
    DogHash::hash_crypher::streamHashp(h, input, &(this->progress), &result);
    this->result = result;
}
void work::task::startEncrypt(DogCryption::cryption_config config, DogData::Data key, std::string input_path, std::string output_path)
{
    DogCryption::cryptor crypter(config);
    std::ifstream input(input_path, std::ios::binary);
    crypter.set_key(key);
    if (!input.is_open()) { throw std::runtime_error("input file not open"); }
    std::ofstream output(output_path, std::ios::binary);
    crypter.encryptp(input, output, &this->progress);
}
void work::task::startEncrypt(DogCryption::cryption_config config, DogData::Data key, std::string input_path, bool withConfig, std::string output_path)
{
    DogCryption::cryptor crypter(config);
    std::ifstream input(input_path, std::ios::binary);
    crypter.set_key(key);
    if (!input.is_open()) { throw std::runtime_error("input file not open"); }
    std::ofstream output(output_path, std::ios::binary);
    crypter.encryptp(input, output, withConfig, &this->progress);
}
void work::task::startDecrypt(DogCryption::cryption_config config, DogData::Data key, std::string input_path, std::string output_path)
{
    DogCryption::cryptor crypter(config);
    std::ifstream input(input_path, std::ios::binary);
    crypter.set_key(key);
    if (!input.is_open()) { throw std::runtime_error("input file not open"); }
    std::ofstream output(output_path, std::ios::binary);
    crypter.decryptp(input, output, &this->progress);
}
void work::task::startDecrypt(DogCryption::cryption_config config, DogData::Data key, std::string input_path, bool withConfig, std::string output_path)
{
    std::ifstream input(input_path, std::ios::binary);
    if (!input.is_open()) { throw std::runtime_error("input file not open"); }
    DogCryption::cryption_config thisConfig = config;
    if (withConfig) {thisConfig = DogCryption::cryption_config::get_cryption_config(input); }
    DogCryption::cryptor crypter(thisConfig);
    crypter.set_key(key);
    std::ofstream output(output_path, std::ios::binary);
    crypter.decryptp(input, output, withConfig, &this->progress);
}

work::taskPool::taskPool(uint64_t max_running)
{
    if (max_running > UINT64_MAX - 1) { throw std::runtime_error("max running too large"); }
    this->id.store(0);
    this->max_running.store(max_running);
    this->now_running.store(0);
}
work::taskPool::~taskPool()
{
    std::unique_lock<std::mutex> lock(pool_mutex); 
    for (auto& task : this->tasks) 
    {
        if (task->getThread() && task->getThread()->joinable()) 
        {
            task->stop();
            task->getThread()->join();
        }
    }
}
uint64_t work::taskPool::add_hash_task(std::string method, std::string path)
{
    std::lock_guard<std::mutex> lock(pool_mutex);
    if (this->now_running.load() >= this->max_running.load()) { return UINT64_MAX; }
    uint64_t id = this->id.load();
    task* t = new task(id, "hash");
    this->now_running.store(this->now_running.load() + 1);
    this->id.store(this->id.load() + 1);
    auto work = [t, method, path,this]() 
        {
            try
            {
                t->start();
                t->startHash(method, path);
                t->success();
                t->setMsg("success get hash");
            }
            catch (std::exception& e)
            {
                t->fail();
                t->setMsg(e.what());
            }
            this->now_running.store(this->now_running.load() - 1);
        };
    std::thread *t1 = new std::thread(work);
    t->setThread(t1);
    this->tasks.emplace_back(std::move(t));
    return id;
}
uint64_t work::taskPool::add_encrypt_task(DogCryption::cryption_config config, DogData::Data key, std::string input_path, std::string output_path)
{
    std::lock_guard<std::mutex> lock(pool_mutex);
    if (this->now_running.load() >= this->max_running.load()) { return UINT64_MAX; }
    uint64_t id = this->id.load();
    task* t = new task(id, "encrypt");
    this->now_running.store(this->now_running.load() + 1);
    this->id.store(this->id.load() + 1);
    this->now_running.store(this->now_running.load() + 1);
    auto work = [t, config, key, input_path, output_path, this]()
        {
            try
            {
                t->start();
                t->startEncrypt(config, key, input_path, output_path);
                t->success();
                t->setMsg("output in " + output_path);
            }
            catch (std::exception& e)
            {
                t->fail();
                t->setMsg(e.what());
            }
            this->now_running.store(this->now_running.load() - 1);
        };
    std::thread *t1 = new std::thread(work);
    t->setThread(t1);
    this->tasks.emplace_back(std::move(t));
    return id;

}
uint64_t work::taskPool::add_encrypt_task(DogCryption::cryption_config config, DogData::Data key, std::string input_path, bool withConfig, std::string output_path)
{
    std::lock_guard<std::mutex> lock(pool_mutex);
    if (this->now_running.load() >= this->max_running.load()) { return UINT64_MAX; }
    uint64_t id = this->id.load();
    task* t = new task(id, "encrypt");
    this->now_running.store(this->now_running.load() + 1);
    this->id.store(this->id.load() + 1);
    auto work = [t, config, key, input_path, withConfig, output_path, this]()
        {
            try
            {
                t->start();
                t->startEncrypt(config, key, input_path, withConfig, output_path);
                t->success();
                t->setMsg("output in " + output_path);
            }
            catch (std::exception& e)
            {
                t->fail();
                t->setMsg(e.what());
            }
            this->now_running.store(this->now_running.load() - 1);
        };
    std::thread *t1 = new std::thread(work);
    t->setThread(t1);
    this->tasks.emplace_back(t);
    return id;
}
uint64_t work::taskPool::add_decrypt_task(DogCryption::cryption_config config, DogData::Data key, std::string input_path, std::string output_path)
{
    std::lock_guard<std::mutex> lock(pool_mutex);
    if (this->now_running.load() >= this->max_running.load()) { return UINT64_MAX; }
    uint64_t id = this->id.load();
    task* t = new task(id, "decrypt");
    this->now_running.store(this->now_running.load() + 1);
    this->id.store(this->id.load() + 1);
    auto work = [t, config, key, input_path, output_path, this]()
        {
            try
            {
                t->start();
                t->startDecrypt(config, key, input_path, output_path);
                t->success();
                t->setMsg("output in " + output_path);
            }
            catch (std::exception& e)
            {
                t->fail();
                t->setMsg(e.what());
            }
            this->now_running.store(this->now_running.load() - 1);
        };
    std::thread *t1 = new std::thread(work);
    t->setThread(t1);
    this->tasks.emplace_back(t);
    return id;
}
uint64_t work::taskPool::add_decrypt_task(DogCryption::cryption_config config, DogData::Data key, std::string input_path, bool withConfig, std::string output_path)
{
    std::lock_guard<std::mutex> lock(pool_mutex);
    if (this->now_running.load() >= this->max_running.load()) { return UINT64_MAX; }
    uint64_t id = this->id.load();
    task* t = new task(id, "decrypt");
    this->now_running.store(this->now_running.load() + 1);
    this->id.store(this->id.load() + 1);
    auto work = [t, config, key, input_path, withConfig, output_path, this]()
        {
            try
            {
                t->start();
                t->startDecrypt(config, key, input_path, withConfig, output_path);
                t->success();
                t->setMsg("output in " + output_path);
            }
            catch (std::exception& e)
            {
                t->fail();
                t->setMsg(e.what());
            }
            this->now_running.store(this->now_running.load() - 1);
            
        };
    std::thread *t1 = new std::thread(work);
    t->setThread(t1);
    this->tasks.emplace_back(t);
    return id;
}

work::taskInfo work::taskPool::get_task_info(uint64_t id)
{
    std::lock_guard<std::mutex> lock(pool_mutex);
    taskInfo ti;
    for (auto& task : this->tasks)
    {
        if (task->getId() == id)
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

work::taskInfo::taskInfo(task* t)
{
    this->id = t->getId();
    this->progress = t->getProgress();
    this->microSecond = t->getMicroSecond();
    this->status = t->getStatus();
    this->msg = t->getMsg();
    this->result = t->getResult();
    this->type = t->getType();
}

work::taskInfo::taskInfo()
{
    this->id = UINT64_MAX;
}
