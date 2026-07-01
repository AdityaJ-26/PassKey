/*
* -------------------------- PASSKEY ----------------------------
* Secure, Offline, Hardware Key based Password Manager
* ---------------------------------------------------------------

* additional external libraries - libsodium v1.0.21 stable-msvc
* uses secure memory allocation for security purpose [see alloc.h for custom allocator]
* secure memory allocators can interfere with debugging features [mostly works fine, problematic while viewing secure allocated data]
*/

#include <iostream>
#include <string>

#include "utils.h"
#include "error.h"
#include "system.h"

int main(void) 
{
	try {
		init();

		System* app = new System();

		app->loadUser();
		app->unlockKey();

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
					app->newEntry();
					break;
				case '2':
					app->displayMetaList();
					break;
				case '3':
					app->displayEntry();
					break;
				default:
					std::cout << "Invalid Choice\n" << "Try Again\n";
			}
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
	return 0;
}