#include <string>

#include "system.h"
#include "alloc.h"
#include "security.h"
#include "utils.h"


System::System() :
	sys_files(new FileHandles()),
	user(new User())
{
	loadMetadata();
}

int System::insert(CharBuffer& data) 
{
	int index{ 0 };
	while (index < meta_list.size()) 
	{
		if (meta_list[index] < data)
		{
			index++;
		}
		else
			break;
	}
	meta_list.insert(meta_list.begin() + index, data);
	return index;
}

int System::find(const CharBuffer& data) const
{
	int low = 0;
	int high = meta_list.size();

	while (low <= high) 
	{
		int mid = (high - low) / 2 + low / 2;
		if (meta_list[mid] > data) 
		{
			high = mid - 1;
		}
		else if (meta_list[mid] < data)
		{
			low = mid + 1;
		}
		else
		{
			return mid;
		}
	}
	return -1;
}

void System::loadMetadata() 
{
	CharBuffer data;
	int offset{ 0 };
	while (sys_files->readMetadata(data, offset) != -1) 
	{
		offset++;
		this->meta_list.push_back(data);
	}
}

void System::displayMetaList() const
{
	for (const auto& meta : meta_list) 
	{
		std::cout << meta << std::endl;
	}
}

void System::createKey()
{
	CharBuffer nonce = generateNonce();
	CharBuffer salt(crypto_pwhash_SALTBYTES);
	randombytes(salt.data(), salt.size());

	SecureString password;
	std::cout << "Enter password : ";
	std::cin >> password;

	SecureCharBuffer key = generateEncryptionKey(password, salt, nonce);
	sys_files->storeKeyData(key, salt, nonce);

	zero(salt);
	zero(nonce);
}

void System::loadUser()
{
	if (sys_files->retrieveUserSettings(user->nameRef())) 
	{
		std::cout << "Welcome " << user->getName() << std::endl;
		std::cout << "Press Enter to Continue..";
		std::getchar();
	}
	else {
		std::cout << "No user exists..\n";
		std::cout << "Create New User (y/n) : ";
		char c;
		std::cin >> c;
		std::cin.ignore();
		switch (c) {
			case 'y':
				createNewUser();
				break;
			case 'n':
				std::cout << "Exiting..";
				std::cout << "Press Enter to Continue..";
				std::getchar();
				exit(0);
			default:
				std::cout << "Invalid Option, Exiting..";
		}
	}
}

void System::createNewUser() 
{
	sys_files->initUser();
	sys_files->generateUserFile();
	std::string hardware_path;
	std::string name;

	std::cout << "Enter UserName : ";
	std::getline(std::cin, name, '\n');

	std::cout << "Enter Hardware Path : ";
	std::cin >> hardware_path;

	if (!sys_files->verifyDirectory(hardware_path)) {
		std::cout << "Entered Hardware Path cannot be found.. \n";
		std::cout << "Connect the hardware key and try again\n";

		int choice;
		while (true) {
			std::cout << "1. Exit\n";
			std::cout << "2. Retry Connection";
			std::cout << "Enter Choice : ";
			std::cin >> choice;

			if (choice == 1) break;
			else if (choice == 2 && sys_files->verifyDirectory(hardware_path)) 
			{
				std::cout << "Hardware Key not detected, try again\n";
			}
		}
	}
	sys_files->storeUserData(hardware_path, name);
	std::cout << "New User Created\n";

	createKey();
}

void System::unlockKey() {
	SecureString password;
	std::cout << "Enter Vault Password : ";
	std::cin >> password;

	CharBuffer nonce;
	CharBuffer salt;
	SecureCharBuffer enc_key;

	sys_files->retrieveKeyData(enc_key, salt, nonce);

	if (unlock(enc_key, password, salt, nonce, vault_key)) {
		std::cout << "Correct Password\n";
	}
	else {
		std::cout << "Incorrect Password, try again\n";
	}
	zero(nonce);
	zero(salt);
}

void System::newEntry() {
	SecureCharBuffer password;
	SecureCharBuffer username;
	CharBuffer metadata;

	std::cout << "Enter Metadata : ";
	input(metadata);
	std::cout << "Enter Username : ";
	input(username);
	std::cout << "Enter Password : ";
	input(password);

	Data* data = new Data(username, password, vault_key);
	CharBuffer user_nonce, pass_nonce;
	data->getEncryptedData(password, pass_nonce, username, user_nonce);
	delete data;

	int data_offset = sys_files->storeCredentials(password, pass_nonce, username, user_nonce);
	int offset = insert(metadata);
	toLower(metadata);																				// normalise metadata
	sys_files->storeMetadata(metadata, data_offset, offset);
}

void System::displayEntry() 
{
	CharBuffer metadata;
	std::cout << "Enter metadata : ";
	input(metadata);

	int index = find(metadata);
	if (index == -1) {
		std::cout << "No matching entry\n";
		return;
	}
	int offset = sys_files->getOffset(index);

	SecureCharBuffer password;
	SecureCharBuffer username;
	CharBuffer user_nonce;
	CharBuffer pass_nonce;

	sys_files->retrieveCredentials(password, pass_nonce, username, user_nonce, offset);

	Data* data = new Data(password, pass_nonce, username, user_nonce);
	data->decrypt(password, username, vault_key);

	std::cout << "Username : " << username << std::endl;
	std::cout << "Password : " << password << std::endl;
	delete data;
}