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
				
				encrypt( user, pass, key, metadata );
				user.clear();
				pass.clear();
				metadata.clear();
				break;

			case 2:
			{
				std::fstream file;
				file.open(FILE_PATH, std::ios::binary | std::ios::in);

				Data temp;
				while (temp.read(file)) 
				{
					std::cout << "--------------------\n";
					std::cout << temp.getMetaData();
				}
				std::cout << "--------------------\n";
				file.close();
			}
				break;

			case 3:
			try 
			{
				std::cout << "Enter Metadata of Password to show details : ";
				input(&metadata);
				bool found = false;

				{
					std::fstream file;
					file.open(FILE_PATH, std::ios::binary | std::ios::in);

					Data temp;
					while (temp.read(file)) 
					{
						if (temp.getMetaData() == metadata) 
						{
							found = true;
							temp.decrypt(pass, user, key);
							break;
						}
					}
					file.close();
				}

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
				std::cout << e.what();
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