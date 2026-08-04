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
* 24 bytes * 2 - nonce size 
* 8 bytes * 2 - nonce.size() variable
* 8 bytes * 2 - uint64_t username.size() & password.size()
* 160 bytes - username, password, padding
*/
constexpr uint64_t DATA_BUFFER_SIZE = 256;

/*
* 8 bytes - uint64_t data_index
* 48 bytes - metadata, metadata.size(), padding
*/
constexpr uint64_t META_BUFFER_SIZE = 64;

#endif  // ! CONTANTS_H 