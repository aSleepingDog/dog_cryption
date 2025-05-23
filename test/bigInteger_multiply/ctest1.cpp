#include <iostream>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <format>
#include <thread>
#include <memory>
#include <functional>

#include "../../lib/big_number.h"


class test_thread : public std::jthread
{
private:
	std::unique_ptr<std::ifstream> inputA, inputB;
	std::unique_ptr<std::ofstream> output;
	std::function<dog_number::BigInteger(dog_number::BigInteger, dog_number::BigInteger)> multiply;
	std::string name;
	double total_time = 0;
public:
	test_thread(
		std::function<dog_number::BigInteger(dog_number::BigInteger, dog_number::BigInteger)> multiply,
		const char* inputA, const char* inputB,
		const char* output,
		const char* name
	)
	{
		this->name = name;
		this->inputA = std::make_unique<std::ifstream>(inputA, std::ios::in);
		this->inputB = std::make_unique<std::ifstream>(inputB, std::ios::in);
		this->output = std::make_unique<std::ofstream>(output, std::ios::out);
		this->multiply = multiply;
		std::jthread(&test_thread::test, this).swap(*this);
	}
	void test()
	{
		auto start = std::chrono::high_resolution_clock::now();
		auto end = std::chrono::high_resolution_clock::now();
		std::chrono::duration<double, std::milli> duration = end - start;

		std::string a, b;

		while (getline(*inputA, a) && getline(*inputB, b))
		{
			dog_number::BigInteger A(a, 10), B(b, 10);

			start = std::chrono::high_resolution_clock::now();
			dog_number::BigInteger C = multiply(A, B);
			end = std::chrono::high_resolution_clock::now();
			duration = end - start;
			this->total_time += duration.count();
			*output << C.getDEC() << std::endl;

		}
		*output << std::format("multiply_time:{:.12f}ms", this->total_time) << std::endl;
		printf("%s is finish\n", this->name.c_str());
		output->close();
	}

	~test_thread()
	{
		this->inputA.reset();
		this->inputB.reset();
		this->output.reset();
	}
};


int main()
{
	using namespace std;
	using namespace dog_number;

	ifstream fa("inputA.txt", ios::in);
	ifstream fb("inputB.txt", ios::in);

	if (!fa.is_open() || !fb.is_open())
	{
		throw std::runtime_error("Error: file not found\n错误：文件打开失败");
		return 1;
	}

	test_thread test_Distribute(
		function<BigInteger(BigInteger, BigInteger)>(BigInteger::multiplyDistribute),
		"inputA.txt", "inputB.txt", "output_multiply_Distribute_C.txt", "Distribute"
	);

	test_thread test_Karatsuba0(
		function<BigInteger(BigInteger, BigInteger)>(BigInteger::multiplyKaratsuba0),
		"inputA.txt", "inputB.txt", "output_multiply_Karatsuba0_C.txt", "Karatsuba0"
	);

	test_thread test_Karatsuba1(
		function<BigInteger(BigInteger, BigInteger)>(BigInteger::multiplyKaratsuba1),
		"inputA.txt", "inputB.txt", "output_multiply_Karatsuba1_C.txt", "Karatsuba1"
	);

	test_thread test_FFT0(
		function<BigInteger(BigInteger, BigInteger)>(BigInteger::multiplyFFT0),
		"inputA.txt", "inputB.txt", "output_multiply_FFT0_C.txt", "FFT0"
	);

	test_thread test_FFT1(
		function<BigInteger(BigInteger, BigInteger)>(BigInteger::multiplyFFT1),
		"inputA.txt", "inputB.txt", "output_multiply_FFT1_C.txt", "FFT1"
	);

	test_thread test_FNTT0(
		function<BigInteger(BigInteger, BigInteger)>(BigInteger::multiplyFNTT0),
		"inputA.txt", "inputB.txt", "output_multiply_FNTT0_C.txt", "FNTT0"
	);

	test_thread test_FNTT1(
		function<BigInteger(BigInteger, BigInteger)>(BigInteger::multiplyFNTT1),
		"inputA.txt", "inputB.txt", "output_multiply_FNTT1_C.txt", "FNTT1"
	);

	test_Distribute.join();
	test_Karatsuba0.join();
	test_Karatsuba1.join();
	test_FFT0.join();
	test_FFT1.join();
	test_FNTT0.join();
	test_FNTT1.join();

	return 0;
}