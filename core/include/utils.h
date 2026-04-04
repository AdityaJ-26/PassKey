#ifndef UTILS_H
#define UTILS_H

#include "sodium.h"

#include "constants.h"
#include "data.h"

void init();
void input( CharBuffer* );
void input( SecureCharBuffer* );
void encrypt( const SecureCharBuffer&, const SecureCharBuffer&, const CharBuffer&, const CharBuffer& );

std::ostream& operator <<( std::ostream&, const SecureCharBuffer& );
std::ostream& operator <<( std::ostream&, const CharBuffer& );

#endif // UTILS_H