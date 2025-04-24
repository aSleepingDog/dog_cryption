#include <iostream>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <format>

#include "../../lib/big_number.h"


int main()
{
	
	using namespace std;
	using namespace DogNumber;

	auto start = std::chrono::high_resolution_clock::now();
	auto end = std::chrono::high_resolution_clock::now();
	std::chrono::duration<double, std::milli> duration = end - start;

	ifstream fb("input_bin.txt", ios::in);
	ofstream fb2h("output_b2h_C.txt", ios::out);
	ofstream fb2d("output_b2d_C.txt", ios::out);

	ifstream fo("input_oct.txt", ios::in);
	ofstream fo2h("output_o2h_C.txt", ios::out);
	ofstream fo2d("output_o2d_C.txt", ios::out);

	ifstream fd("input_dec.txt", ios::in);
	ofstream fd2h("output_d2h_C.txt", ios::out);
	ofstream fd2d("output_d2d_C.txt", ios::out);

	ifstream fh("input_hex.txt", ios::in);
	ofstream fh2h("output_h2h_C.txt", ios::out);
	ofstream fh2d("output_h2d_C.txt", ios::out);

	std::string input;

	double total_time_input_b = 0, total_time_output_b2h = 0, total_time_output_b2d = 0;

	while (std::getline(fb, input))
	{
		start = std::chrono::high_resolution_clock::now();
		BigInteger n(input, 2);
		end = std::chrono::high_resolution_clock::now();
		duration = end - start;
		total_time_input_b += duration.count();

		start = std::chrono::high_resolution_clock::now();
		std::string output_b2h = n.getUpHEX();
		end = std::chrono::high_resolution_clock::now();
		duration = end - start;
		total_time_output_b2h += duration.count();
		fb2h << output_b2h << endl;

		start = std::chrono::high_resolution_clock::now();
		std::string output_b2d = n.getDEC();
		end = std::chrono::high_resolution_clock::now();
		duration = end - start;
		total_time_output_b2d += duration.count();
		fb2d << output_b2d << endl;

	}
	fb2h << std::format("input_time:{:.6f}ms", total_time_input_b) << endl;
	fb2h << std::format("output_time:{:.6f}ms", total_time_output_b2h) << endl;

	fb2d << std::format("input_time:{:.6f}ms", total_time_input_b) << endl;
	fb2d << std::format("output_time:{:.6f}ms", total_time_output_b2d) << endl;

	double total_time_input_o = 0, total_time_output_o2h = 0, total_time_output_o2d = 0;

	while (std::getline(fo, input))
	{
		start = std::chrono::high_resolution_clock::now();
		BigInteger n(input, 8);
		end = std::chrono::high_resolution_clock::now();
		duration = end - start;
		total_time_input_o += duration.count();

		start = std::chrono::high_resolution_clock::now();
		std::string output_o2h = n.getUpHEX();
		end = std::chrono::high_resolution_clock::now();
		duration = end - start;
		total_time_output_o2h += duration.count();
		fo2h << output_o2h << endl;

		start = std::chrono::high_resolution_clock::now();
		std::string output_o2d = n.getDEC();
		end = std::chrono::high_resolution_clock::now();
		duration = end - start;
		total_time_output_o2d += duration.count();
		fo2d << output_o2d << endl;
	}
	fo2h << std::format("input_time:{:.6f}ms", total_time_input_o) << endl;
	fo2h << std::format("output_time:{:.6f}ms", total_time_output_o2h) << endl;

	fo2d << std::format("input_time:{:.6f}ms", total_time_input_o) << endl;
	fo2d << std::format("output_time:{:.6f}ms", total_time_output_o2d) << endl;

	double total_time_input_d = 0, total_time_output_d2h = 0, total_time_output_d2d = 0;
	while (std::getline(fd, input))
	{
		start = std::chrono::high_resolution_clock::now();
		BigInteger n(input, 10);
		end = std::chrono::high_resolution_clock::now();
		duration = end - start;
		total_time_input_d += duration.count();

		start = std::chrono::high_resolution_clock::now();
		std::string output_d2h = n.getUpHEX();
		end = std::chrono::high_resolution_clock::now();
		duration = end - start;
		total_time_output_d2h += duration.count();
		fd2h << output_d2h << endl;

		start = std::chrono::high_resolution_clock::now();
		std::string output_d2d = n.getDEC();
		end = std::chrono::high_resolution_clock::now();
		duration = end - start;
		total_time_output_d2d += duration.count();
		fd2d << output_d2d << endl;
	}
	fd2h << std::format("input_time:{:.6f}ms", total_time_input_d) << endl;
	fd2h << std::format("output_time:{:.6f}ms", total_time_output_d2h) << endl;
	fd2d << std::format("input_time:{:.6f}ms", total_time_input_d) << endl;
	fd2d << std::format("output_time:{:.6f}ms", total_time_output_d2d) << endl;

	double total_time_input_h = 0, total_time_output_h2h = 0, total_time_output_h2d = 0;

	while (std::getline(fh, input))
	{
		start = std::chrono::high_resolution_clock::now();
		BigInteger n(input, 16);
		end = std::chrono::high_resolution_clock::now();
		duration = end - start;
		total_time_input_h += duration.count();

		start = std::chrono::high_resolution_clock::now();
		std::string output_h2h = n.getUpHEX();
		end = std::chrono::high_resolution_clock::now();
		duration = end - start;
		total_time_output_h2h += duration.count();
		fh2h << output_h2h << endl;

		start = std::chrono::high_resolution_clock::now();
		std::string output_h2d = n.getDEC();
		end = std::chrono::high_resolution_clock::now();
		duration = end - start;
		total_time_output_h2d += duration.count();
		fh2d << output_h2d << endl;
	}
	fh2h << std::format("input_time:{:.6f}ms", total_time_input_h) << endl;
	fh2h << std::format("output_time:{:.6f}ms", total_time_output_h2h) << endl;
	fh2d << std::format("input_time:{:.6f}ms", total_time_input_h) << endl;
	fh2d << std::format("output_time:{:.6f}ms", total_time_output_h2d) << endl;

	return 0;
}