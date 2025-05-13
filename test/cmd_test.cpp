#include "../lib/dog_cryption.h"

#include <iostream>

#include <fstream>
#include <format>

int main()
{
	using namespace DogData;
	Data d = "0123";
	DogData::print::space(d);
	Data d1 = d.bit_right_move_rise(15);
	DogData::print::space(d1);
	d.bit_right_move_rise_self(15);
	DogData::print::space(d);

}