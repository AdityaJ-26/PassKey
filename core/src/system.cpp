#include <string>

#include "system.h"
#include "alloc.h"
#include "security.h"
#include "utils.h"
#include "data.h"

/* -------------------------------------------------- */
// constructor / destructor
/* -------------------------------------------------- */
System::System() :
	sys_files(new FileHandles()),
	user(new User()),
	metadata_list(std::vector<CharBuffer>())
{}

System::~System() {
	delete sys_files;
	metadata_list.clear();
	delete user;
}

/*
* creates and stores vault_key
* the key is stored in encrypted form in hardware device
*/
void System::createVaultKey() {
	CharBuffer nonce = generateNonce();
	CharBuffer salt(crypto_pwhash_SALTBYTES);
	randombytes(salt.data(), salt.size());

	SecureString password;
	std::cout << "Enter password : ";
	std::cin >> password;

	SecureCharBuffer encrypted_vault_key = generateVaultKey(password, salt, nonce);
	sys_files->storeKeyData(encrypted_vault_key, salt, nonce);

	zero(salt);
	zero(nonce);
}

/* -------------------------------------------------- */
// metadata, metadata_list operations
/* -------------------------------------------------- */
/*
* insert into metadata_list based on chronological order
* this decreases time to search metadata from list to O(logN) using binary search, N = no. of metadata
*/
int System::insert(CharBuffer& data) {
	int index{ 0 };
	while (index < metadata_list.size()) {
		if (toLower(metadata_list[index]) < toLower(data)) {
			index++;
		}
		else
			break;
	}
	metadata_list.insert(metadata_list.begin() + index, data);

	return index;
}

/*
* binary search to get metadata index from metadata_list
*/
int System::find(const CharBuffer& data) const {
	int low = 0;
	int high = metadata_list.size() - 1;

	while (low <= high) {
		int mid = (high - low) / 2 + low;

		if (toLower(metadata_list[mid]) > toLower(data)) {
			high = mid - 1;
		}
		else if (toLower(metadata_list[mid]) < toLower(data)) {
			low = mid + 1;
		}
		else {
			return mid;
		}
	}
	return -1;
}

/*
* reads metadata from file into meta_list in sorted order for fast accessing
*/
void System::loadMetadata() {
	CharBuffer data;
	int offset{ 0 };
	while (sys_files->readMetadata(data, offset) != 1) {
		offset++;
		this->metadata_list.push_back(data);
	}
}


/* -------------------------------------------------- */
// user operations
/* -------------------------------------------------- */
void System::createNewUser() {
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
			std::cout << "2. Retry Connection\n";
			std::cout << "Enter Choice : ";
			std::cin.ignore();
			std::cin >> choice;

			if (choice == 1) {
				::exit(0);
			}
			else if (choice == 2 && sys_files->verifyDirectory(hardware_path)) {
				break;
			}
			else {
				std::cout << "Hardware Key not detected, try again\n";
			}
		}
	}
	sys_files->storeUserData(hardware_path, name);
	std::cout << "New User Created\n";
	sys_files->createKeyFile(hardware_path);
	createVaultKey();
}
void System::loadUser() {
	sys_files->initFiles();

	if (sys_files->loadUserSettings(user->nameRef())) {
		std::cout << "Welcome " << user->getName() << std::endl;
		std::cout << "Press Enter to Continue..";
		char c = std::getchar();
	}
	else {
		char c;
		std::cout << "No user exists..\n";
		std::cout << "Create New User (y/n) : ";
		std::cin >> c;
		std::cin.ignore();

		switch (c) {
			case 'y':
				createNewUser();
				break;
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
	// loads metadata_list
	loadMetadata();
}

/*
* loads key_data from key.bin [vault_key_file] and decrypts it with provided password and loads the decrypted key into System::vault_key
*/
bool System::unlockKey() { 
	SecureString password;
	std::cout << "Enter Vault Password : ";
	std::cin >> password;

	CharBuffer nonce;
	CharBuffer salt;
	SecureCharBuffer enc_key;

	sys_files->retrieveKeyData(enc_key, salt, nonce);

	bool unlocked = false;
	if (unlockVaultKey(enc_key, password, salt, nonce, vault_key)) {
		unlocked = true;
		std::cout << "Correct Password\n";
	}
	else {
		std::cout << "Incorrect Password, try again\n";
	}

	zero(nonce);
	zero(salt);
	return unlocked;
}

/* -------------------------------------------------- */
// user interactions operations
/* -------------------------------------------------- */
void System::addEntry() {
	SecureCharBuffer password;
	SecureCharBuffer username;
	CharBuffer metadata;

	std::cout << "Enter Metadata : ";
	input(metadata);
	std::cout << "Enter Username : ";
	input(username);
	std::cout << "Enter Password : ";
	input(password);
	
	Data data(username, password, vault_key);
	CharBuffer user_nonce, pass_nonce;
	data.getEncryptedData(password, pass_nonce, username, user_nonce);

	int64_t data_offset = sys_files->storeCredentials(password, pass_nonce, username, user_nonce);
	int offset = insert(metadata);
	sys_files->storeMetadata(metadata, data_offset, offset);
}

void System::searchEntry() {
	CharBuffer metadata;
	std::cout << "Enter metadata : ";
	input(metadata);

	int index = find(metadata);
	if (index == -1) {
		std::cout << "No matching entry\n";
		return;
	}
	uint64_t offset = sys_files->getOffset(index);

	SecureCharBuffer password;
	SecureCharBuffer username;
	CharBuffer user_nonce;
	CharBuffer pass_nonce;

	sys_files->retrieveCredentials(password, pass_nonce, username, user_nonce, offset);
	Data data(password, pass_nonce, username, user_nonce);
	data.decrypt(password, username, vault_key);

	zero(user_nonce);
	zero(pass_nonce);

	std::cout << "Username : " << username << std::endl;
	std::cout << "Password : " << password << std::endl;
}

void System::displayMetadataList() const {
	for (const auto& meta : metadata_list) {
		std::cout << meta << std::endl;
	}
}

void System::exit() {
	delete this;
}