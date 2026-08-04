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

#include "utils.h"
#include "error.h"
#include "system.h"

int main(void) 
{
	System* app;
	try {
		app = new System();
		init();

		app->loadUser();
		if (!app->unlockKey())
		{
			exit(0);
		}

		char choice;
		while (true) 
		{
			std::cout << "1. Enter New Credentials\n";
			std::cout << "2. Display Metadata List\n";
			std::cout << "3. Search Creadential\n";
			std::cout << "4. Logout and Exit\n";
			std::cout << "Enter Choice: ";
			std::cin >> choice;

			switch (choice)
			{
				case '1':
					app->addEntry();
					break;
				case '2':
					app->displayMetadataList();
					break;
				case '3':
					app->searchEntry();
					break;
				case '4':
					std::cout << "Exiting\n";
					std::cout << "Press Enter to Continue";
					std::getchar();
					std::getchar();
					break;
				default:
					std::cout << "Invalid Choice\n" << "Try Again\n";
			}
			if (choice == '4') break;
		}
		app->exit();

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
	return 0;
}