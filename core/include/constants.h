#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <vector>
#include <string>
#include "alloc.h"


enum FileTypes {
	vault = 0,
	userSettings = 1,
	key = 2,
	pass = 3
};


/* -------------------------------------------------- */
// name aliases
/* -------------------------------------------------- */
using SecureCharBuffer = std::vector<unsigned char, SecureAllocator<unsigned char>>;
using SecureString = std::basic_string<char, std::char_traits<char>, SecureAllocator<char>>;
using CharBuffer = std::vector<unsigned char>;


/* -------------------------------------------------- */
// numeric constants
/* -------------------------------------------------- */

// 8 * 4 - uint64_t length variable | 24 * 2 - nonce size | 30 - username | 20 - password | 1 - passProtected
constexpr uint64_t PADDING_SIZE = 161;

#endif  // ! CONTANTS_H 