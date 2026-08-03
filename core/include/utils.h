#ifndef UTILS_H
#define UTILS_H

#include "sodium/utils.h"

#include "constants.h"
#include "data.h"

void init();
void input( CharBuffer& );
void input( SecureCharBuffer& );

std::ostream& operator <<( std::ostream&, const SecureCharBuffer& );
std::ostream& operator <<( std::ostream&, const CharBuffer& );

void zero(CharBuffer&);
void zero(SecureCharBuffer&);
void zero(SecureString&);

void printHex(const CharBuffer);
void printHex(const SecureCharBuffer);

CharBuffer toLower(CharBuffer);

#endif // ! UTILS_H