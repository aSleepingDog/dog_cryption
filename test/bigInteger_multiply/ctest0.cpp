#include <iostream>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <format>
#include <exception>

#include "../../lib/big_number.h"


int main0()
{
	using namespace std;
	using namespace dog_number;
	
	ifstream fa("inputA.txt", ios::in);
	ifstream fb("inputB.txt", ios::in);

	if (!fa.is_open() || !fb.is_open())
	{
		throw runtime_error("Error: file not found\n错误：文件打开失败");
	}

	ofstream f_Distribute_out("output_multiply_Distribute_C.txt", ios::out);
	ofstream f_Karatsuba0_out("output_multiply_Karatsuba0_C.txt", ios::out);
	ofstream f_Karatsuba1_out("output_multiply_Karatsuba1_C.txt", ios::out);
	ofstream f_FFT0_out("output_multiply_FFT0_C.txt", ios::out);
	ofstream f_FFT1_out("output_multiply_FFT1_C.txt", ios::out);
	ofstream f_FNTT0_out("output_multiply_FNTT0_C.txt", ios::out);
	ofstream f_FNTT1_out("output_multiply_FNTT1_C.txt", ios::out);

	auto start = chrono::high_resolution_clock::now();
	auto end = chrono::high_resolution_clock::now();
	std::chrono::duration<double, std::milli> duration = end - start;

	double 
		total_multiple_Distribute_time = 0,
		total_multiple_Karatsuba0_time = 0,
		total_multiple_Karatsuba1_time = 0,
		total_multiple_FFT0_time = 0,
		total_multiple_FFT1_time = 0,
		total_multiple_FNTT0_time = 0,
		total_multiple_FNTT1_time = 0;
	Ullong n = 0;

	std::string a, b;

	while (getline(fa, a) && getline(fb, b))
	{
		BigInteger A(a, 10), B(b, 10);

		printf("%u\r", ++n);

		start = chrono::high_resolution_clock::now();
		BigInteger C = BigInteger::multiplyDistribute(A, B);
		end = chrono::high_resolution_clock::now();
		duration = end - start;
		total_multiple_Distribute_time += duration.count();
		f_Distribute_out << C.getDEC() << endl;

		start = chrono::high_resolution_clock::now();
		C = BigInteger::multiplyKaratsuba0(A, B);
		end = chrono::high_resolution_clock::now();
		duration = end - start;
		total_multiple_Karatsuba0_time += duration.count();
		f_Karatsuba0_out << C.getDEC() << endl;

		start = chrono::high_resolution_clock::now();
		C = BigInteger::multiplyKaratsuba1(A, B);
		end = chrono::high_resolution_clock::now();
		duration = end - start;
		total_multiple_Karatsuba1_time += duration.count();
		f_Karatsuba1_out << C.getDEC() << endl;

		start = chrono::high_resolution_clock::now();
		C = BigInteger::multiplyFFT0(A, B);
		end = chrono::high_resolution_clock::now();
		duration = end - start;
		total_multiple_FFT0_time += duration.count();
		f_FFT0_out << C.getDEC() << endl;

		start = chrono::high_resolution_clock::now();
		C = BigInteger::multiplyFFT1(A, B);
		end = chrono::high_resolution_clock::now();
		duration = end - start;
		total_multiple_FFT1_time += duration.count();
		f_FFT1_out << C.getDEC() << endl;

		start = chrono::high_resolution_clock::now();
		C = BigInteger::multiplyFNTT0(A, B);
		end = chrono::high_resolution_clock::now();
		duration = end - start;
		total_multiple_FNTT0_time += duration.count();
		f_FNTT0_out << C.getDEC() << endl;

		start = chrono::high_resolution_clock::now();
		C = BigInteger::multiplyFNTT1(A, B);
		end = chrono::high_resolution_clock::now();
		duration = end - start;
		total_multiple_FNTT1_time += duration.count();
		f_FNTT1_out << C.getDEC() << endl;

	}

	f_Distribute_out << std::format("multiply_time:{:.6f}ms", total_multiple_Distribute_time) << endl;
	f_Karatsuba0_out << std::format("multiply_time:{:.6f}ms", total_multiple_Karatsuba0_time) << endl;
	f_Karatsuba1_out << std::format("multiply_time:{:.6f}ms", total_multiple_Karatsuba1_time) << endl;
	f_FFT0_out << std::format("multiply_time:{:.6f}ms", total_multiple_FFT0_time) << endl;
	f_FFT1_out << std::format("multiply_time:{:.6f}ms", total_multiple_FFT1_time) << endl;
	f_FNTT0_out << std::format("multiply_time:{:.6f}ms", total_multiple_FNTT0_time) << endl;
    f_FNTT1_out << std::format("multiply_time:{:.6f}ms", total_multiple_FNTT1_time) << endl;

	return 0;
}