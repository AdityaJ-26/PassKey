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

		if (!app->loadUser()) {
			char c;
			std::cout << "No user exists..\n";
			std::cout << "Create New User (y/n) : ";
			std::cin >> c;
			std::cin.ignore();

			switch (c) {
			case 'y':
			{
				std::string name;
				std::cout << "Enter Name : ";
				std::getline(std::cin, name, '\n');
				
				std::string hardware_path;
				std::cout << "Enter hardware path : ";
				std::cin >> hardware_path;

				app->createNewUser(name, hardware_path);

				SecureString password;
				std::cout << "Enter password : ";
				std::cin >> password;

				app->createVaultKey(password);
				break;
			}
			case 'n':
				std::cout << "Exiting..";
				std::cout << "Press Enter to Continue..";
				c = std::getchar();
				::exit(0);
			default:
				std::cout << "Invalid Option, Exiting..";
				::exit(0);
			}
		}

		SecureString password;
		std::cout << "Enter Password : ";
		std::cin >> password;

		if (!app->unlockKey(password))
		{
			std::cout << "Incorrect Password...\n";
			std::cout << "Exiting..\n";
			zero(password);
			exit(0);
		}

		zero(password);

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
				{
					CharBuffer metadata;
					std::cout << "Enter metadata : ";
					input(metadata);

					SecureCharBuffer username;
					std::cout << "Enter Username : ";
					input(username);

					SecureCharBuffer password;
					std::cout << "Enter Password : ";
					input(password);

					app->addEntry(metadata, username, password);

					zero(username);
					zero(password);
					zero(metadata);
					break;
				}

				case '2':
					app->displayMetadataList();
					break;

				case '3': {
					SecureCharBuffer username;
					SecureCharBuffer password;

					CharBuffer metadata;
					std::cout << "Enter metadata : ";
					input(metadata);

					if (!app->searchEntry(metadata, username, password)) {
						std::cout << "No matching entry\n";
					}

					std::cout << "Username : " << username;
					std::cout << "Password : " << password;

					zero(username);
					zero(password);
					zero(metadata);
					break;
				}
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