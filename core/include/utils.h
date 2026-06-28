#ifndef UTILS_H
#define UTILS_H

#include "sodium.h"

#include "constants.h"
#include "data.h"

void init();
void input( CharBuffer* );
void input( SecureCharBuffer* );

std::ostream& operator <<( std::ostream&, const SecureCharBuffer& );
std::ostream& operator <<( std::ostream&, const CharBuffer& );

template <typename T>
void zero(T& data) {
	sodium_memzero(data.data(), data.size());
}

#endif // ! UTILS_H