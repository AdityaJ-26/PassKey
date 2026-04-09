#include <iostream>
#include <string>

#include "error.h"
#include "utils.h"

/* -------------------------------------------------- */
// sodium init
/* -------------------------------------------------- */
void init()
{
	if (sodium_init() < 0)
	{
		throw Error{ "_lib_error : error initialising libsodium" };
	}
}


/* -------------------------------------------------- */
// buffer::CharBuffer / buffer::SecureCharBuffer input methods
/* -------------------------------------------------- */
void input( buffer::SecureCharBuffer* user )
{
	buffer::SecureString input;
	std::getline(std::cin, input, '\n');

	*user = buffer::SecureCharBuffer(input.begin(), input.end());
}

void input( buffer::CharBuffer* data ) 
{
	std::string input;
	std::cin.ignore();
	std::getline(std::cin, input, '\n');
	
	*data = buffer::CharBuffer(input.begin(), input.end());
}


/* -------------------------------------------------- */
// operator<< overload for Buffers
/* -------------------------------------------------- */
std::ostream& operator <<( std::ostream& out, const buffer::SecureCharBuffer& data ) 
{
	for (const char& c : data) 
	{
		out << c;
	}
	out << std::endl;
	return out;
}

std::ostream& operator <<( std::ostream& out, const buffer::CharBuffer& data ) 
{
	for (const char& c : data) 
	{
		out << c;
	}
	out << std::endl;
	return out;
}