/*
* ------------------------- PASSKEY -------------------------
*	 Secure, Offline, Hardware Key based Password Manager
* -----------------------------------------------------------
*/

/* ----- Compiler -----
* Language : C++
* CXX-STANDARD : C++20
* Compiler : g++
* Compiler Version : 15.2.0 
*/

/* ----- Libraries -----
* Library Name : libsodium
* Library Version : v1.0.21-stable
*/

/* ----- Features -----
* key storage in external USB device, and USB device is required to access vault
* uses secure memory allocation for data protection [see alloc.h for custom allocator]
* stores data encrypted locally in binary (.bin) files
* creadentials are loaded into memory only when requested, increasing security
*/

#include <iostream>
#include <string>

#include "error.h"
#include "cli.h"

static void init() {
	if (sodium_init() < 0) {
		throw Error{ "_lib_error : error initialising libsodium" };
	}
}

int main(void) {
	CLI* app;
	app = new CLI();
	try {
		init();
		
		std::cout << "\033[2J\033[H";
		app->printCLI();
		app->printSoftwareInfo();
		std::cout << "Press Enter to Continue...";
		char c = getchar();
		std::cout << "\033[2J\033[H";
		
		app->printCLI();
		while (app->running) {
			app->printHeader();
			std::string input;
			std::cin >> input;
			app->processInput(input);
		}
	}
	catch (Error& e) 
	{
		std::cout << e.what() << std::endl;
	}
	catch (std::exception& e) 

	{
		std::cout << e.what();
	}
	catch (...)
	{
		std::cout << "unexpected error" << std::endl;
	}
	delete app;
	app = nullptr;
	std::cout << "Press Enter to Continue...";
	std::cin.ignore();
	char c = getchar();
	return 0;
}
