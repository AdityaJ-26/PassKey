#ifndef PASS_H
#define PASS_H

#include "constants.h"
#include <string>

const std::string PHRASE{ "authentication check" };

void store(const buffer::CharBuffer&, const buffer::CharBuffer&, const buffer::CharBuffer&);
buffer::SecureCharBuffer generatePassKey(const buffer::SecureString&, const buffer::CharBuffer&);
void initUser();

void retrieve(buffer::SecureCharBuffer&, buffer::CharBuffer&, buffer::CharBuffer&);
void storePhrase(const buffer::SecureCharBuffer&);
bool phraseAuthenticate(const buffer::SecureCharBuffer&);

buffer::SecureCharBuffer loadUser();

#endif // ! PASS_H