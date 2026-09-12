#ifndef UTILS_H
#define UTILS_H

#include "constants.h"

void input( CharBuffer& );
void input( SecureCharBuffer& );

std::ostream& operator <<( std::ostream&, const SecureCharBuffer& );
std::ostream& operator <<( std::ostream&, const CharBuffer& );

/* -------------------------------------------------- */
// zeroing methods()
/* -------------------------------------------------- */
// calls sodium inbuild memzero() to ensure data clearing
template <typename BUFFER>
void zero(BUFFER& data) {
	sodium_memzero(data.data(), data.size());
}

CharBuffer toLower(CharBuffer);

void printHex(const CharBuffer);
void printHex(const SecureCharBuffer);


#endif // ! UTILS_H