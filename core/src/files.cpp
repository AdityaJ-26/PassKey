#include "files.h"
#include "error.h"


FileHandles::FileHandles() = default;


FileHandles::~FileHandles() {
	user.flush();
	user.close();

	vault.flush();
	vault.close();

	meta.flush();
	meta.close();
}


bool FileHandles::verifyDirectory(const std::string& path) const {
	std::filesystem::path file_path = path;
	file_path = file_path.parent_path();

	// current directory
	if (file_path.empty()) {
		return true;
	}

	if (std::filesystem::exists(file_path) && is_directory(file_path)) {
		return true;
	}
	else {
		return false;
	}
}


/* -------------------------------------------------- */
// read and write functions
/* -------------------------------------------------- */

// write functions writes CharBuffer and SecureCharBuffer in binary files as [ buffer.size() ][ buffer ]
template <typename T>
void FileHandles::write(std::fstream& file, const T& msg) {
	if (!file.is_open()) {
		throw Error{ "_file_error : null file pointer" };
	}
	uint64_t len = msg.size();
	file.write(reinterpret_cast<const char*>(&len), sizeof(len));
	file.write(reinterpret_cast<const char*>(msg.data()), len);
}

template <typename T>
bool FileHandles::read(std::fstream& file, T& msg) {
	if (!file.is_open()) {
		throw Error{ "_file_error : null file pointer" };
	}
	uint64_t len{ 0 };
	if (!file.read(reinterpret_cast<char*>(&len), sizeof(len))) {
		return false;
	}
	msg.resize(len);
	file.read(reinterpret_cast<char*>(msg.data()), len);
	return true;
}

template <typename T>
T FileHandles::read(std::fstream& file) {
	T msg;
	if (!file.is_open()) {
		throw Error{ "_file_error : null file pointer" };
	}
	uint64_t len{ 0 };
	if (!file.read(reinterpret_cast<char*>(&len), sizeof(len))) {
		throw Error{ "_read_error : error reading data from file" };
	}
	msg.resize(len);
	file.read(reinterpret_cast<char*>(msg.data()), len);
	return msg;
}



/* -------------------------------------------------- */
// key functions
/* -------------------------------------------------- */

void FileHandles::createKeyFile(const std::string& path) {
	this->key_path = path;
	if (!std::filesystem::exists(key_path.parent_path()) && is_directory(key_path.parent_path())	) {
		std::filesystem::create_directories(key_path.parent_path());
	}
	std::fstream key_file;
	key_file.open(key_path, std::ios::binary | std::ios::out);
	key_file.close();
}


// opens key file and if key_path not loaded, loads user and if user not load
void FileHandles::openKeyFile(std::fstream& key_file) {
	if (key_file.is_open()) {
		return;
	}

	if (key_path.empty()) {
		std::string name;
		if (loadUserSettings(name) == false) {
			std::cout << "Hardware Device Not Connected..." << std::endl;
			return;
		}
	}

	key_file.open(key_path, std::ios::binary | std::ios::in | std::ios::out);
	if (!key_file.is_open()) {
		throw Error{ "_file_error : failed to access key file" };
	}
}


/*
* stores the salt used to derive key from password, nonce for master key decryption, and encryption_key
* order 
	size(enc_key) -> key ->
	size(salt) -> salt ->
	size(nonce) -> nonce
	    
*/
void FileHandles::storeKeyData(const SecureCharBuffer& enc_key, const CharBuffer& salt, const CharBuffer& nonce) {
	std::fstream key_file;
	openKeyFile(key_file);

	write(key_file, enc_key);
	write(key_file, salt);
	write(key_file, nonce);

	key_file.flush();
	key_file.close();
}


void FileHandles::retrieveKeyData(SecureCharBuffer& enc_key, CharBuffer& salt, CharBuffer& nonce) {
	std::fstream key_file;
	key_file.open(key_path, std::ios::binary | std::ios::in);

	read(key_file, enc_key);
	read(key_file, salt);
	read(key_file, nonce);
	key_file.close();
}



/* -------------------------------------------------- */
// user functions
/* -------------------------------------------------- */

// opens (creates if not found) vault and metadata file
void FileHandles::initFiles() {
	if (!std::filesystem::exists(vault_path.parent_path())) {
		std::filesystem::create_directories(vault_path.parent_path());
	}
	vault.open(vault_path, std::ios::binary | std::ios::in | std::ios::app);
	if (vault.is_open()) {
		vault.open(vault_path, std::ios::binary | std::ios::out);
		vault.close();
		vault.open(vault_path, std::ios::binary | std::ios::in | std::ios::out);
	}

	if (!std::filesystem::exists(meta_path.parent_path())) {
		std::filesystem::create_directories(meta_path.parent_path());
	}
	meta.open(meta_path, std::ios::binary | std::ios::in);
	if (meta.is_open()) {
		meta.open(meta_path, std::ios::binary | std::ios::out);
		meta.close();
		meta.open(meta_path, std::ios::binary | std::ios::in);
	}
}


void FileHandles::generateUserFile() {
	if (!std::filesystem::exists(user_settings.parent_path())) {
		std::filesystem::create_directories(user_settings.parent_path());
	}
	user.open(user_settings, std::ios::binary | std::ios::out);
	user.close();

	user.open(user_settings, std::ios::binary | std::ios::in | std::ios::out);
	if (!user.is_open()) {
		throw Error{ "_file_error : error creating user_file" };
	}
}


/*
* store user_name and vault_key path in user.bin
* format = [ field.size() ][ field.data() ]
*/
void FileHandles::storeUserData(const std::string& hardwareKeyPath, const std::string& name) {
	if (!user.is_open()) {
		generateUserFile();
	}

	std::string field;
	field = "name";
	write(user, field);
	write(user, name);

	field = "hardware_path";
	write(user, field);
	write(user, hardwareKeyPath);
	user.flush();
}


bool FileHandles::loadUserSettings(std::string& name) {
	if (!std::filesystem::exists(user_settings)) {
		return false;
	}
	if (!user.is_open()) {
		user.open(user_settings, std::ios::binary | std::ios::in | std::ios::out);
	}

	user.seekg(0, std::ios::beg);
	bool loaded = false;
	std::string data;
	while (true) {
		if (read(user, data)) {
			if (data == "name") {
				read(user, data);
				name = data;
			}
			else if (data == "hardware_path") {
				read(user, data);
				key_path = data;
				loaded = true;
			}
		}
		else {
			break;
		}
	}
	return loaded;
}



/* -------------------------------------------------- */
// storing and reading credentials
/* -------------------------------------------------- */

/*
* stores the metadata in sorted order maintained by System::metadata_list, along with corresponding credentials offset in vault.bin
* order [ credential_offset ] [ metadata.size() ] [ metadata ] [ padding ]

* uses temporary file to copy the original metadata file entries along with new metadata inserted in sorted position
* as new credential entries are rare compared to accessing/searching for stored credential, using this method to maintain sorted order for fast accessing
*/
void FileHandles::storeMetadata(const CharBuffer& metadata, uint64_t data_index, int offset) {
	meta.clear();
	std::fstream temp_file;
	temp_file.open(meta_path.parent_path() / "temp.bin", std::ios::binary | std::ios::out);

	if (!temp_file.is_open()) {
		throw Error{ "_file_error : cannot access files for data entry" };
	}

	char* buffer = new char[META_BUFFER_SIZE];
	uint64_t offset_count{ 0 };

	meta.seekg(0, std::ios::beg);
	
	while (true) {
		if (offset_count == offset) {
			temp_file.write(reinterpret_cast<const char*>(&data_index), sizeof(data_index));
			write(temp_file, metadata);
			CharBuffer padding(META_BUFFER_SIZE - (sizeof(data_index) + sizeof(uint64_t) + metadata.size()));
			randombytes(padding.data(), padding.size());
			temp_file.write(reinterpret_cast<const char*>(padding.data()), padding.size());
		}

		if (!meta.read(reinterpret_cast<char*>(buffer), META_BUFFER_SIZE)) {
			break;
		}

		offset_count++;
		temp_file.write(buffer, META_BUFFER_SIZE);
	}

	if (offset_count < offset) {
		temp_file.write(reinterpret_cast<const char*>(&data_index), sizeof(data_index));
		write(temp_file, metadata);
		CharBuffer padding(META_BUFFER_SIZE - (sizeof(data_index) + sizeof(uint64_t) + metadata.size()));
		randombytes(padding.data(), padding.size());
		temp_file.write(reinterpret_cast<const char*>(padding.data()), padding.size());
	}

	temp_file.close();
	meta.close();

	std::filesystem::path new_path = meta_path.parent_path() / "temp.bin";
	std::filesystem::remove(meta_path);
	std::filesystem::rename(new_path, meta_path);

	meta.open(meta_path, std::ios::binary | std::ios::in);
	delete buffer;
}


/*
* using meta.clear() as meta is getting to EOF while loading metadata into meta_list, this sets the eofbit and if the last read operation fails,
  it sets failbit that stops all seek() operations on fstream and fails the system
*/
uint64_t FileHandles::getOffset(int offset) {
	meta.clear();
	meta.seekg(offset * META_BUFFER_SIZE, std::ios::beg);
	uint64_t data_offset{ 0 };
	meta.read(reinterpret_cast<char*>(&data_offset), sizeof(data_offset));
	return data_offset;
}


uint64_t FileHandles::readMetadata(CharBuffer& metadata, int offset) {
	uint64_t data_offset{ 1 };
	meta.seekg(offset * META_BUFFER_SIZE, std::ios::beg);
	metadata.clear();
	if (!meta.read(reinterpret_cast<char*>(&data_offset), sizeof(data_offset))) {
		return data_offset;
	}
	read(meta, metadata);
	return data_offset;
}


/*
* vault file storing
* order
	len(pass) -> pass ->
	len(pass_nonce) -> pass_nonce ->
	len(user) -> user ->
	len(user_nonce) -> user_nonce
	padding
*/
uint64_t FileHandles::storeCredentials(
	const SecureCharBuffer& enc_pass, const CharBuffer& pass_nonce,
	const SecureCharBuffer& enc_user, const CharBuffer& user_nonce) 
{
	vault.seekp(0, std::ios::end);
	uint64_t pointer_offset = static_cast<std::streamoff>(vault.tellp());
	
	write(vault, enc_pass);
	write(vault, pass_nonce);
	write(vault, enc_user);
	write(vault, user_nonce);

	vault.flush();
	return pointer_offset;
}


/* -------------------------------------------------- */
// read data(creds)
/* -------------------------------------------------- */
bool FileHandles::retrieveCredentials(
	SecureCharBuffer& enc_pass, CharBuffer& pass_nonce,
	SecureCharBuffer& enc_user, CharBuffer& user_nonce,
	uint64_t offset) 
{
	vault.seekg(offset, std::ios::beg); // move to indexed data
	return
		read(vault, enc_pass) &&
		read(vault, pass_nonce) &&
		read(vault, enc_user) &&
		read(vault, user_nonce);
}