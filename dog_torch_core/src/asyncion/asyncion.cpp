#include "asyncion/asyncion.h"

std::string dog_torch::asyncion::State_to_str(State code)
{
    switch (code)
    {
    case State::Ready:
        return "Ready";
    case State::Running:
        return "Running";
    case State::Paused:
        return "Paused";
    case State::Waiting:
        return "Waitting";
    case State::Stopped:
        return "Stopped";
    }
}

#ifdef SHARED
template class dog_torch::asyncion::Clock<std::chrono::nanoseconds>;
template class dog_torch::asyncion::Clock<std::chrono::microseconds>;
template class dog_torch::asyncion::Clock<std::chrono::milliseconds>;
template class dog_torch::asyncion::Clock<std::chrono::seconds>;
template class dog_torch::asyncion::Clock<std::chrono::minutes>;
template class dog_torch::asyncion::Clock<std::chrono::hours>;
template class dog_torch::asyncion::Clock<std::chrono::days>;
template class dog_torch::asyncion::Clock<std::chrono::weeks>;
#endif // SHARED
