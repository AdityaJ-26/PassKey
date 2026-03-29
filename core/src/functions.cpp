#include <iostream>
#include <string>

#include "sodium.h"

#include "functions.h"

void input(SecureCharBuffer* user) {
	SecureString input;

	std::cout << "Enter : ";
	std::cin >> input;

	*user = SecureCharBuffer(input.begin(), input.end());
}