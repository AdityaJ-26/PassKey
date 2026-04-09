#include <iostream>
#include <string>

#include "sodium.h"
#include "core.h"
#include "user.h"
#include "encrypt.h"

int main(void) 
{
	init();

	int choice{ 0 };

	buffer::SecureCharBuffer key(crypto_secretbox_KEYBYTES);

	std::cout << "new user(y/n) : ";
	try 
	{
		switch (getchar()) 
		{
			case 'y':
				initUser();
			case 'n':
				key = loadUser();
				break;
			default:
				std::cout << "Invalid Choice..";
				std::cout << "Press Enter to Continue";
				getchar();
				exit(0);
		}
	}
	catch (Error& e)
	{
		std::cout << e.what() << std::endl;
		exit(-1);
	}
	catch (...) 
	{
		std::cout << "_unexpected_error " << std::endl;
	}


	// menu
	while (true) 
	{

		std::cout << "======= MENU =======" << std::endl;
		std::cout << "1. Enter Credentials" << std::endl;
		std::cout << "2. Display" << std::endl;
		std::cout << "3. Decrypt" << std::endl;
		std::cin >> choice;

		switch (choice)
		{
			case 1:
			try {
				buffer::SecureCharBuffer pass;
				buffer::SecureCharBuffer user;
				buffer::CharBuffer metadata;
				std::cout << "Enter MetaData : ";
				input(&metadata);
				std::cout << "Enter Username : ";
				input(&user);
				std::cout << "Enter Password : ";
				input(&pass);

				encrypt(user, pass, key, metadata);
				sodium_memzero(metadata.data(), metadata.size());
				break;
			}
			catch (Error& e) {
				std::cerr << "error(data input) : " << e.what() << std::endl;
				exit(-1);
			}
			case 2:
			try {
				std::fstream file;
				file.open(filepath::DATA, std::ios::binary | std::ios::in);
				if (!file.is_open()) 
				{
					throw Error{ "_file_error : failed to load data file" };
				}

				Data temp;
				while (true)
				{
					if (!temp.read(file)) break;
					std::cout << "--------------------\n";
					std::cout << temp.getMetaData();
				}
				std::cout << "--------------------\n";
				file.close();
			}
			catch (Error& e) {
				std::cerr << "error(metadata display) : " << e.what() << std::endl;
				exit(-1);
			}
			break;
			case 3:
			try 
			{
				buffer::SecureCharBuffer user;
				buffer::SecureCharBuffer pass;
				buffer::CharBuffer metadata;
				std::cout << "Enter Metadata of Password to show details : ";
				input(&metadata);
				bool found = false;

				{
					std::fstream file;
					file.open(filepath::DATA, std::ios::binary | std::ios::in);

					Data temp;
					while (true) 
					{
						if (!temp.read(file)) break;
						if (temp.getMetaData() == metadata) 
						{
							found = true;
							temp.decrypt(pass, user, key);
							break;
						}
					}
					file.close();
				}
				sodium_memzero(metadata.data(), metadata.size());

				if (found) 
				{
					std::cout << "Password : " << pass;
					std::cout << "UserName : " << user;
					pass.clear();
					user.clear();
				}
				break;
			}
			catch (Error& e) 
			{
				std::cerr << "error(decrypting data) : " << e.what() << std::endl;
				char c = getchar();
				exit(-1);
			}
			catch (std::bad_alloc& e) 
			{
				std::cout << e.what();
				char c = getchar();
				exit(-1);
			}
		}
		if (choice == 0) break;
	}

	return 0;
}