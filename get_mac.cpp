#include <iostream>
#include <string>
#include <fstream>

std::string get_mac(const std::string& interface) {
    std::string result;
    std::ifstream file("/sys/class/net/" + interface + "/address");

    if (file.is_open()) {
        std::getline(file, result);
        file.close();
    } else {
        result = "Error: Unable to open the file.";
    }

    return result;
}
