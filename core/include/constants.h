#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <vector>
#include <string>
#include "alloc.h"

/* -------------------------------------------------- */
// name aliases
/* -------------------------------------------------- */
using SecureCharBuffer = std::vector<unsigned char, SecureAllocator<unsigned char>>;
using SecureString = std::basic_string<char, std::char_traits<char>, SecureAllocator<char>>;
using CharBuffer = std::vector<unsigned char>;


/* -------------------------------------------------- */
// numeric constants
/* -------------------------------------------------- */

/* 
* 8 bytes * 4 - uint64_t length variable 
* 24 bytes * 2 - nonce size 
* 30 bytes - username 
* 20 bytes - password 
*/
constexpr uint64_t DATA_BUFFER_SIZE = 160;
constexpr uint64_t META_BUFFER_SIZE = 32;

#endif  // ! CONTANTS_H 