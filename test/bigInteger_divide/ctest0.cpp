#include <iostream>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <format>
#include <exception>

#include "math/number.h"
#include "asyncion/asyncion.h"

int main()
{
	using dog_torch::math::number::BigInteger;
	using dog_torch::asyncion::Clock;

	std::ifstream fa("inputA.txt", std::ios::in);
	std::ifstream fb("inputB.txt", std::ios::in);
	std::ofstream fki("output_divide_Knuth_C.txt");

	std::string a, b;
	Clock<std::chrono::milliseconds> clock;
	clock.reset();
	clock.start();
	clock.pause();

	uint64_t i = 0;
	while (getline(fa, a) && getline(fb, b))
	{
		std::cout << i << std::endl;
		BigInteger an(a);
		BigInteger bn(b);

		clock.resume();
		BigInteger result = BigInteger::divideKnuth(a, b);
		clock.pause();
		fki << result.to_num_string(16) << std::endl;
		i++;
	}
	clock.stop();
	double cost = clock.get_cost();
	fki << std::format("divide_time:{:.6f}ms", cost) << std::endl;

}