#include "files.h"
#include "error.h"


FileHandles::FileHandles() = default;

FileHandles::~FileHandles() 
{
	user.flush();
	user.close();

	vault.flush();
	vault.close();
}

bool FileHandles::verifyDirectory(std::string& path) const
{
	if (std::filesystem::exists(path)) return true;
	else return false;
}

/* -------------------------------------------------- */
// read and write functions
/* -------------------------------------------------- */
template <typename T>
void FileHandles::write(std::fstream& file, const T& msg)
{
	if (!file) 
	{
		throw Error{ "_file_error : null file pointer" };
	}

	uint64_t len = msg.size();
	file.write(reinterpret_cast<const char*>(&len), sizeof(len));
	file.write(reinterpret_cast<const char*>(msg.data()), len);
}

template <typename T>
bool FileHandles::read(std::fstream& file, T& msg) 
{
	if (!file) 
	{
		throw Error{ "_file_error : null file pointer" };
	}
	uint64_t len{ 0 };
	if (!file.read(reinterpret_cast<char*>(&len), sizeof(len))) 
	{
		throw Error{ "_read_error : error reading data from file" };
	}
	msg.resize(len);
	file.read(reinterpret_cast<char*>(msg.data()), len);
	return true;
}

template <typename T>
T FileHandles::read(std::fstream& file) 
{
	T msg;
	if (!file) 
	{
		throw Error{ "_file_error : null file pointer" };
	}
	uint64_t len{ 0 };
	if (!file.read(reinterpret_cast<char*>(&len), sizeof(len))) 
	{
		throw Error{ "_read_error : error reading data from file" };
	}
	msg.resize(len);
	file.read(reinterpret_cast<char*>(msg.data()), len);
	return msg;
}


/* -------------------------------------------------- */
// key functions
/* -------------------------------------------------- */

// opens key file and if key_path not loaded, loads user and if user not load
void FileHandles::openKeyFile(std::fstream& key_file)
{
	std::string name;

	if (key_file.is_open())
	{
		return;
	}

	if (key_path.empty())
	{
		if (retrieveUserSettings(name) == false)
		{
			std::cout << "Hardware Device Not Connected..." << std::endl;
			return;
		}
	}

	key_file.open(key_path, std::ios::binary | std::ios::in);
	if (!key_file.is_open())
	{
		throw Error{ "_file_error : failed to access key file" };
	}
}

/*
* stores the salt used to derive key from password, nonce for master key decryption, and encryption_key
* order size(salt) -> salt ->
	  size(nonce) -> nonce ->
	  size(enc_key) -> key
*/
void FileHandles::storeKeyData(const SecureCharBuffer& enc_key, const CharBuffer& salt, const CharBuffer& nonce)
{
	std::fstream key_file;
	openKeyFile(key_file);

	write(key_file, salt);
	write(key_file, nonce);
	write(key_file, enc_key);

	key_file.flush();
	key_file.close();
}

void FileHandles::retrieveKeyData(SecureCharBuffer& enc_key, CharBuffer& salt, CharBuffer& nonce)
{
	std::fstream key_file;
	openKeyFile(key_file);

	if (read(key_file, salt) &&
		read(key_file, nonce) &&
		read(key_file, enc_key)
		)
	{
		throw Error{ "_file_error : corrupted key file" };
	}
}


/* -------------------------------------------------- */
// user functions
/* -------------------------------------------------- */
void FileHandles::initUser() 
{
	if (!std::filesystem::exists(vault_path.parent_path())) 
	{
		std::filesystem::create_directories(vault_path.parent_path());
	}
	if (!std::filesystem::exists(meta_path.parent_path()))
	{
		std::filesystem::create_directories(meta_path.parent_path());
	}

	vault.open(vault_path, std::ios::binary | std::ios::in | std::ios::app);
	if (vault.is_open()) {
		vault.open(vault_path, std::ios::binary | std::ios::out);
		vault.close();
		vault.open(vault_path, std::ios::binary | std::ios::in | std::ios::app);
	}

	meta.open(meta_path, std::ios::binary | std::ios::in);
	if (meta.is_open()) {
		meta.open(meta_path, std::ios::binary | std::ios::out);
		meta.close();
		meta.open(meta_path, std::ios::binary | std::ios::in);
	}
}

void FileHandles::generateUserFile()
{
	if (!std::filesystem::exists(user_settings.parent_path()))
	{
		std::filesystem::create_directories(user_settings.parent_path());
	}
	user.open(user_settings, std::ios::out);
	user.close();

	user.open(user_settings, std::ios::in | std::ios::out);
	if (!user.is_open())
	{
		throw Error{ "_file_error : error creating user_file" };
	}
}

void FileHandles::storeUserData(const std::string& hardwareKeyPath, const std::string& name)
{
	if (!user.is_open())
	{
		generateUserFile();
	}
	std::string temp;
	temp = "name,";
	write(user, temp);
	temp = "hardware_path,";
	write(user, name + ";");
	write(user, temp);
	write(user, hardwareKeyPath + ";");
	user.flush();
}

bool FileHandles::retrieveUserSettings(std::string& name) 
{
	this->user.open(user_settings, std::ios::in | std::ios::out);
	if (!user.is_open()) 
	{
		return false;
	}
	
	std::string data;
	user.seekp(0, std::ios::beg);

	bool loaded = false;
	name.clear();
	while (std::getline(user, data, ';')) 
	{
		std::stringstream sts{ data };
		std::string header; 

		std::getline(sts, header, ',');
		if (header == "name") {
			std::getline(sts, header, ',');
			name = header;
		}
		else if (header == "hardware_path") 
		{
			std::getline(sts, header, ',');
			this->key_path = header;
			loaded = true;
		}
	}
	if (loaded) 
	{
		if (name.empty()) 
		{
			name = "User";
		}
	}
	return loaded;
}


/* -------------------------------------------------- */
// storing and reading credentials
/* -------------------------------------------------- */

/*
* stores in order
	data_offset -> metadata
* uses temporary file to store data with new metadata insertion at correct sorted position
* reads as buffers and write till correct index is found
* as new credential entries are rare inserting new entry uses this method
*/
void FileHandles::storeMetadata(const CharBuffer& metadata, int data_offset, int offset) 
{
	std::filesystem::path new_path = meta_path.parent_path() / "temp.bin";
	std::fstream temp_meta;
	temp_meta.open(new_path, std::ios::binary | std::ios::out);

	if (temp_meta.is_open() == false) 
	{
		throw Error{ "_file_error : cannot access files for data entry" };
	}

	char* buffer = new char(META_BUFFER_SIZE);
	uint64_t offset_count{ 0 };
	uint64_t data_index = data_offset / DATA_BUFFER_SIZE;

	meta.seekg(0, std::ios::beg);
	while (meta.read(buffer, sizeof(buffer))) 
	{
		if (offset_count == offset) 
		{
			temp_meta.write(reinterpret_cast<const char*>(&data_index), sizeof(data_index));
			write(temp_meta, metadata);
		}
		offset_count++;
		temp_meta.write(buffer, sizeof(buffer));
	}

	if (offset_count < offset) {
		temp_meta.write(reinterpret_cast<const char*>(&data_index), sizeof(data_index));
		write(temp_meta, metadata);
	}

	temp_meta.close();
	meta.close();

	std::filesystem::remove(meta_path);
	std::filesystem::rename(new_path, meta_path);
	meta.open(meta_path, std::ios::binary | std::ios::in);
}

int FileHandles::getOffset(int offset)
{
	meta.seekg(offset * META_BUFFER_SIZE, std::ios::beg);
	uint64_t data_offset;
	meta.read(reinterpret_cast<char*>(&data_offset), sizeof(data_offset));
	return data_offset;
}

int FileHandles::readMetadata(CharBuffer& metadata, int offset) 
{
	uint64_t data_offset{ 0 };
	meta.seekg(offset * META_BUFFER_SIZE, std::ios::beg);
	if (!meta.read(reinterpret_cast<char*>(&data_offset), sizeof(data_offset))) 
	{
		return -1;
	}
	metadata = read<CharBuffer>(meta);
	return data_offset;
}

/*
* store data in order
	len(pass) -> pass ->
	len(pass_nonce) -> pass_nonce ->
	len(user) -> user ->
	len(user_nonce) -> user_nonce
*/
int FileHandles::storeCredentials(
	const SecureCharBuffer& enc_pass, const CharBuffer& pass_nonce, 
	const SecureCharBuffer& enc_user, const CharBuffer& user_nonce) 
{
	int pointer_offset = vault.tellp();
	vault.seekp(0, std::ios::end);
	write(vault, enc_pass);
	write(vault, pass_nonce);
	write(vault, enc_user);
	write(vault, user_nonce);

	// for padding of data to use with metadata indexing
	uint64_t data_size =
		enc_pass.size() +
		enc_user.size() +
		(crypto_secretbox_NONCEBYTES * 2) +
		(4 * 8);
	CharBuffer padding;
	randombytes(padding.data(), DATA_BUFFER_SIZE - data_size);
	write(vault, padding);

	return pointer_offset;
}


/* -------------------------------------------------- */
// read data(creds)
/* -------------------------------------------------- */
bool FileHandles::retrieveCredentials(
	SecureCharBuffer& enc_pass, CharBuffer& pass_nonce, 
	SecureCharBuffer& enc_user, CharBuffer& user_nonce,
	int offset)
{
	vault.seekg(offset * DATA_BUFFER_SIZE, std::ios::beg); // move to indexed data
	return
		read(vault, enc_pass) &&
		read(vault, pass_nonce) &&
		read(vault, enc_user) &&
		read(vault, user_nonce);
}