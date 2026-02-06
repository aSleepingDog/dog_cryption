#include "asyncion/thread/thread.h"

dog_torch::asyncion::thread::PauseableDetail::PauseableDetail(dog_torch::asyncion::State s, double p, uint64_t c)
	: state(s), progress(p), cost(c)
{
}

dog_torch::asyncion::thread::PauseableChannel::PauseableChannel()
{
    condition_variable_ = std::make_unique<std::condition_variable>();
}
dog_torch::asyncion::thread::PauseableChannel::~PauseableChannel()
{
    if (this->condition_variable_)
    {
        this->cancel();
    }
}
dog_torch::asyncion::thread::PauseableChannel::PauseableChannel(PauseableChannel&& pc) noexcept
{
    std::scoped_lock lock(pc.mutex_, this->mutex_);
    this->state_ = pc.state_.load();
    this->progress_ = pc.progress_.load();
    this->clock_ = std::move(pc.clock_);
    this->condition_variable_ = std::move(pc.condition_variable_);
    this->condition_variable_.reset();
}
dog_torch::asyncion::thread::PauseableChannel& dog_torch::asyncion::thread::PauseableChannel::operator=(PauseableChannel&& pc) noexcept
{
    std::scoped_lock lock(pc.mutex_, this->mutex_);
    this->state_ = pc.state_.load();
    this->progress_ = pc.progress_.load();
    this->clock_ = std::move(pc.clock_);
    this->condition_variable_ = std::move(pc.condition_variable_);
    this->condition_variable_.reset();
    return *this;
}
void dog_torch::asyncion::thread::PauseableChannel::start()
{
    std::unique_lock lock(this->mutex_);
    this->state_ = State::Running;
	this->clock_.reset();
	this->clock_.start();
}
void dog_torch::asyncion::thread::PauseableChannel::pause()
{
    std::unique_lock lock(this->mutex_);
    this->state_ = State::Paused;
	this->clock_.pause();
}
void dog_torch::asyncion::thread::PauseableChannel::resume()
{
    std::unique_lock lock(this->mutex_);
    this->state_ = State::Running;
    this->condition_variable_->notify_one();
    this->clock_.resume();
}
bool dog_torch::asyncion::thread::PauseableChannel::is_paused()
{
    std::unique_lock lock(this->mutex_);
    return this->state_ == State::Paused;
}
void dog_torch::asyncion::thread::PauseableChannel::complete()
{
    std::unique_lock lock(this->mutex_);
    this->state_ = State::Completely;
    this->progress_ = 1.0;
    this->clock_.stop();
	this->condition_variable_->notify_all();
}
void dog_torch::asyncion::thread::PauseableChannel::cancel()
{
    std::unique_lock lock(this->mutex_);
    this->state_ = State::Completely;
    this->progress_ = 1.0;
    this->clock_.stop();
    this->condition_variable_->notify_all();
}
bool dog_torch::asyncion::thread::PauseableChannel::is_stopped()
{
    return this->state_ == State::Completely || this->state_ == State::Cancelled;
}
void dog_torch::asyncion::thread::PauseableChannel::wait()
{
    std::unique_lock lock(this->mutex_);
    this->state_ = State::Waiting;
    this->clock_.pause();
}
bool dog_torch::asyncion::thread::PauseableChannel::should_pause()
{
    std::unique_lock<std::mutex> lock(this->mutex_);
    if (this->state_ == State::Paused)
    {
        this->condition_variable_->wait(lock, [this]()->bool
            {
                return !(this->state_ == State::Paused);
            });
    }
    return this->state_ == State::Cancelled;
}
void dog_torch::asyncion::thread::PauseableChannel::add_progress(double value)
{
	this->progress_ += value;
}
void dog_torch::asyncion::thread::PauseableChannel::set_progress(double value)
{
	this->progress_ = value;
}
double dog_torch::asyncion::thread::PauseableChannel::get_progress()
{
    return this->progress_;
}
uint64_t dog_torch::asyncion::thread::PauseableChannel::get_ms_time() const
{
    return clock_.get_cost();
}
dog_torch::asyncion::State dog_torch::asyncion::thread::PauseableChannel::get_state()
{
    return this->state_;
}
dog_torch::asyncion::thread::PauseableDetail dog_torch::asyncion::thread::PauseableChannel::to_detail()
{
    std::unique_lock lock(this->mutex_);
    return PauseableDetail(
        this->state_.load(),
        this->progress_.load(),
        this->clock_.get_cost()
    );
}


