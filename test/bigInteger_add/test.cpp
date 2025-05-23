#include <iostream>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <format>

#include "../../lib/big_number.h"

int main()
{
	using namespace std;
	using namespace dog_number;

	ifstream fa("inputA.txt", ios::in);
	ifstream fb("inputB.txt", ios::in);

	ofstream fadd("output_add_C.txt", ios::out);
	ofstream fsub("output_sub_C.txt", ios::out);

	auto start = std::chrono::high_resolution_clock::now();
	auto end = std::chrono::high_resolution_clock::now();
	std::chrono::duration<double, std::milli> duration = end - start;

	double total_add_time = 0, total_selfadd_time = 0, total_sub_time = 0, total_selfsub_time = 0;

	std::string a, b;
	while (getline(fa, a) && getline(fb, b))
	{
		BigInteger A1(a, 10), A2 = A1, B(b, 10);

		start = std::chrono::high_resolution_clock::now();
		BigInteger add = A1 + B;
		end = std::chrono::high_resolution_clock::now();
        duration = end - start;
        total_add_time += duration.count();

		start = std::chrono::high_resolution_clock::now();
		BigInteger sub = A1 - B;
		end = std::chrono::high_resolution_clock::now();
		duration = end - start;
		total_sub_time += duration.count();

		start = std::chrono::high_resolution_clock::now();
        A1 += B;
		end = std::chrono::high_resolution_clock::now();
		duration = end - start;
		total_selfadd_time += duration.count();
		bool selfadd_equal = (A1 == add);

        start = std::chrono::high_resolution_clock::now();
		A2 -= B;
		end = std::chrono::high_resolution_clock::now();
		duration = end - start;
		total_selfsub_time += duration.count();
		bool selfsub_equal = (A2 == sub);

		fadd << add.getDEC() << "-" << ((selfadd_equal == true) ? "True" : "False") << endl;
        fsub << sub.getDEC() << "-" << ((selfsub_equal == true) ? "True" : "False") << endl;

	}

	fadd << std::format("add_time:{:.6f}ms", total_add_time) << endl;
	fadd << std::format("selfadd_time:{:.6f}ms", total_selfadd_time) << endl;

	fsub << std::format("sub_time:{:.6f}ms", total_sub_time) << endl;
	fsub << std::format("selfsub_time:{:.6f}ms", total_selfsub_time) << endl;

	return 0;
}