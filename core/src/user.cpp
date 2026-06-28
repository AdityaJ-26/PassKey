#include <fstream>

#include "sodium.h"

#include "user.h"
#include "constants.h"
#include "error.h"
#include "utils.h"


/* -------------------------------------------------- */
// user functions
/* -------------------------------------------------- */
User::User()
{ }

const std::string& User::getName() const {
	return this->name;
}

std::string& User::nameRef() {
	return this->name;
}

// update it so that new user dont' get the prompt for cannot load user
//bool User::checkUser() 
//{
//	while (!files->loadUserSettings(name)) {
//		std::cout << "   Cannot Load User...\n";
//		std::cout << "1. Create New User\n";
//		std::cout << "2. Retry\n";
//		std::cout << "3. Exit\n";
//
//		int choice;
//		std::cin >> choice;
//		std::cout << "Enter choice : ";
//		switch (choice)
//		{
//			case 1:
//				delete files;
//				createUser();
//				return;
//			case 2:
//				break;
//			case 3:
//				exit(0);
//			default:
//				break;
//		}
//	}
//}
//
//void User::createUser() 
//{
//	init();
//
//	std::string name;
//	std::cout << "Enter Name : ";
//	std::cin >> name;
//
//	std::string hardwarePath;
//	std::cout << "Enter Hardware Path: ";
//	std::cin >> hardwarePath;
//
//	delete files;
//	files->createUserFile();
//	files->storeUserData(hardwarePath, name);
//}



/* -------------------------------------------------- */
// reads Key, salt, nonce
/* -------------------------------------------------- */



/* -------------------------------------------------- */
// Encryption key access
/* -------------------------------------------------- */

/*
* decrypts encryption_key using password
*/
SecureCharBuffer User::loadUser()
{
	SecureCharBuffer encrption_key;

}