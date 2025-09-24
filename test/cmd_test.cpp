#include "../libcryption/include/cryption/dog_cryption.h"
#include "../libtask/include/task/task.h"

#include <iostream>
#include <print> 
#include <fstream>
#include <format>
#include <filesystem>

#include <cmath>



int main()
{
	//std::unordered_map<std::string, std::any> object;
	//object["0"] = nullptr;
	//object["1"] = true;
	//object["2"] = 125.0;
	//object["3"] = -45.0;
	//object["4"] = -84.2;
	//object["5"] = "123456789";
	//std::vector<std::any> vec = { object["0"],object["1"], object["2"], object["3"], object["4"], object["5"] };
	//object["6"] = vec;
	//auto o2 = object;
	//object["7"] = o2;
	//std::cout << dog_data::json::to_json_str(object, true) << std::endl;

	std::string jsonStr = R"(
{
    "address": {
        "cupidatat_c8c": -54035216.66514077,
        "esse_561": false,
        "consequat4": "aute et in",
        "enim_f80": "ipsum et",
        "elit_7": false
    },
    "phoneNumbers": [
        {
            "type": "consectetur commodo Duis nisi",
            "number": "proident ullamco anim"
        }
    ],
    "age": 29427114.02109617,
    "name": "officia in sunt"
}
)";
	auto cit = jsonStr.cbegin();
	auto o3 = dog_data::json::object_from_json_str(jsonStr,cit);
    std::cout << dog_data::json::to_json_str(o3, true) << std::endl;
    return 0;
}