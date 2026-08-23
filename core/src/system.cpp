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
	user = nullptr;
	sys_files = nullptr;
}

const std::string& System::name() const {
	return user->nameRef();
}

/*
* creates and stores vault_key
* the key is stored in encrypted form in hardware device
*/
void System::createVaultKey(const SecureString& password) {
	CharBuffer nonce = generateNonce();
	CharBuffer salt(crypto_pwhash_SALTBYTES);
	randombytes(salt.data(), salt.size());

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
int System::insert(const CharBuffer& data) {
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
int System::createNewUser(const std::string& name, const std::string& hardware_path) {
	sys_files->generateUserFile();

	sys_files->storeUserData(hardware_path, name);
	sys_files->createKeyFile(hardware_path);
	return 0;
}


int System::loadUser() {
	sys_files->initFiles();

	int status = sys_files->loadUserSettings(user->nameRef());
	return status;
}


/*
* loads key_data from key.bin [vault_key_file] and decrypts it with provided password and loads the decrypted key into System::vault_key
*/
int System::unlockKey(const SecureString& password) { 
	CharBuffer nonce;
	CharBuffer salt;
	SecureCharBuffer enc_key;

	int exit_code = 0;
	sys_files->retrieveKeyData(enc_key, salt, nonce);

	if (!unlockVaultKey(enc_key, password, salt, nonce, vault_key)) {
		exit_code = 1;
	}
	else {
		exit_code = 0;
	}

	zero(nonce);
	zero(salt);
	return exit_code;
}



/* -------------------------------------------------- */
// user interactions operations
/* -------------------------------------------------- */
void System::addEntry(const CharBuffer& metadata, const SecureCharBuffer& username, const SecureCharBuffer& password) {
	Data data(username, password, vault_key);
	CharBuffer user_nonce, pass_nonce;

	SecureCharBuffer encrypted_password;
	SecureCharBuffer encrypted_username;
	data.getEncryptedData(encrypted_password, pass_nonce, encrypted_username, user_nonce);

	int64_t data_offset = sys_files->storeCredentials(encrypted_password, pass_nonce, encrypted_username, user_nonce);
	int offset = insert(metadata);
	sys_files->storeMetadata(metadata, data_offset, offset);
}


bool System::searchEntry(const CharBuffer& metadata, SecureCharBuffer& username, SecureCharBuffer& password) {
	int index = find(metadata);

	if (index == -1) {
		return false;
	}
	uint64_t offset = sys_files->getOffset(index);

	CharBuffer user_nonce;
	CharBuffer pass_nonce;

	sys_files->retrieveCredentials(password, pass_nonce, username, user_nonce, offset);
	Data data(password, pass_nonce, username, user_nonce);
	data.decrypt(password, username, vault_key);

	zero(user_nonce);
	zero(pass_nonce);
	return true;
}


void System::displayMetadataList() const {
	for (const auto& meta : metadata_list) {
		std::cout << "-> " << meta;
	}
}