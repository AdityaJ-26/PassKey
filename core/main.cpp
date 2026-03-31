#include <iostream>
#include <string>

#include "sodium.h"
#include "core.h"

int main(void) 
{
	init();

	int choice{ 0 };
	
	SecureCharBuffer pass;
	SecureCharBuffer user;
	CharBuffer metadata;
	
	CharBuffer key(crypto_secretbox_KEYBYTES);
	crypto_secretbox_keygen(key.data());

	std::vector<Data> passwords;

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
				std::cout << "Enter MetaData : ";
				input( &metadata );
				std::cout << "Enter Username : ";
				input( &user );
				std::cout << "Enter Password : ";
				input( &pass );
				
				encrypt( user, pass, passwords, key, metadata );
				user.clear();
				pass.clear();
				break;

			case 2:
				for (const auto& x : passwords) {
					std::cout << x.getMetaData() << std::endl;
				}
				std::cout << "-----------------" << std::endl;
				break;

			case 3:
				CharBuffer metadata;
				std::cout << "Enter username of password to show details : ";
				input( &metadata );
				for (const auto& x : passwords) 
				{
					if (x.getMetaData() == metadata) {
						decrypt(x, pass, user, key);
					}
					//std::cout << "UserName : " << user << std::endl;
					//std::cout << "Password : " << pass << std::endl;
				}
				user.clear();
				pass.clear();
				break;
		}
		if (choice == 0) break;
	}

	return 0;
}