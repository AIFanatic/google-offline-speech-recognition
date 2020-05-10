#include <string>
#include <vector>
#include <iostream>

extern "C" {
    const char *std_string_to_char(std::string &str) {
        return str.c_str();
    }

    const char *const_std_string_to_char(const std::string &str) {
        return str.c_str();
    }

    const int std_vector_pointer_get_size(const std::vector<int>& input) {
        return static_cast<int>(input.size());
    }

    const int* std_vector_pointer_get_data_pointer(const std::vector<int>& input) {
        return input.data();
    }

    const char* std_istream_to_char(std::istream &stream) {
        std::istreambuf_iterator<char> eos;
        std::string s(std::istreambuf_iterator<char>(stream), eos);
        return s.c_str();
    }
}