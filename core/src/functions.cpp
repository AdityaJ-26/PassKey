#include <iostream>
#include <string>

#include "sodium.h"

#include "../include/functions.h"

void input(CharBuffer* user) {
	std::string input;

	std::cout << "Enter : ";
	std::cin >> input;

	*user = CharBuffer(input.begin(), input.end());
}