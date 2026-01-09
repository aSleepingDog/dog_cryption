#pragma once
#ifdef SHARED
	#include "export.h"
#else
	#define DOG_CRYPTION_API
#endif

#include <queue>
#include <array>
#include <regex>
#include <string>
#include <vector>
#include <memory>
#include <cstring>
#include <utility>
#include <complex>
#include <iostream>
#include <algorithm>
#include <exception>
#include <functional>

#include "utils/Exception.h"
namespace dog_torch::math::galois_field
{
	DOG_CRYPTION_API uint8_t GF2_mult(uint8_t a, uint8_t b, uint16_t n);
}