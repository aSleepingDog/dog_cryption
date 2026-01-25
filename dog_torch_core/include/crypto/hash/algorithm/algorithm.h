#pragma once
#ifdef SHARED
#include "export.h"
#else
#define DOG_CRYPTION_API
#endif
#include <mutex>
#include <thread>
#include <atomic>
#include <iostream>
#include <condition_variable>

#include "SHA2.h"
#include "SM3.h"
#include "crypto/hash/hash.h"

namespace dog_torch::crypto::hash::algorithm
{
	DOG_CRYPTION_API const std::vector<Config> get_all_algorithms();
}