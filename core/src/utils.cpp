#include <iostream>
#include <string>
#include <fstream>

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
void input( SecureCharBuffer* user )
{
	SecureString input;
	std::getline(std::cin, input, '\n');

	*user = SecureCharBuffer(input.begin(), input.end());
}

void input( CharBuffer* data ) 
{
	std::string input;
	std::cin.ignore();
	std::getline(std::cin, input, '\n');
	
	*data = CharBuffer(input.begin(), input.end());
}


/* -------------------------------------------------- */
// operator<< overload for Buffers
/* -------------------------------------------------- */
std::ostream& operator <<( std::ostream& out, const SecureCharBuffer& data ) 
{
	for (const char& c : data) 
	{
		out << c;
	}
	out << std::endl;
	return out;
}

std::ostream& operator <<( std::ostream& out, const CharBuffer& data ) 
{
	for (const char& c : data) 
	{
		out << c;
	}
	out << std::endl;
	return out;
}