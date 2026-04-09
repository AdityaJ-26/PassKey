#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <vector>
#include <string>
#include "alloc.h"


/* -------------------------------------------------- */
// file paths
/* -------------------------------------------------- */
namespace filepath {
	constexpr const char* DATA = "../data/creds.bin";
	constexpr const char* KEY = "../data/key.bin";
	constexpr const char* PHRASE = "../data/phrase.bin";
}


/* -------------------------------------------------- */
// name aliases
/* -------------------------------------------------- */
namespace buffer {
	using SecureCharBuffer = std::vector<unsigned char, SecureAllocator<unsigned char>>;
	using SecureString = std::basic_string<char, std::char_traits<char>, SecureAllocator<char>>;
	using CharBuffer = std::vector<unsigned char>;
}

#endif 