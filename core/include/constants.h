#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <vector>
#include <string>
#include "alloc.h"

constexpr const char* FILE_PATH = "../data/creds.bin";

using SecureCharBuffer = std::vector<unsigned char, SecureAllocator<unsigned char>>;
using SecureString = std::basic_string<char, std::char_traits<char>, SecureAllocator<char>>;
using CharBuffer = std::vector<unsigned char>;

#endif 