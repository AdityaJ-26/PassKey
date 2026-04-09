#ifndef UTILS_H
#define UTILS_H

#include "sodium.h"

#include "constants.h"
#include "data.h"

void init();
void input( buffer::CharBuffer* );
void input( buffer::SecureCharBuffer* );

std::ostream& operator <<( std::ostream&, const buffer::SecureCharBuffer& );
std::ostream& operator <<( std::ostream&, const buffer::CharBuffer& );

#endif // UTILS_H