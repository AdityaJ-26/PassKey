#ifndef UTILS_H
#define UTILS_H

#include "constants.h"

void init();
void input( CharBuffer& );
void input( SecureCharBuffer& );

std::ostream& operator <<( std::ostream&, const SecureCharBuffer& );
std::ostream& operator <<( std::ostream&, const CharBuffer& );

void zero(CharBuffer&);
void zero(SecureCharBuffer&);
void zero(SecureString&);

CharBuffer toLower(CharBuffer);

void printHex(const CharBuffer);
void printHex(const SecureCharBuffer);


#endif // ! UTILS_H