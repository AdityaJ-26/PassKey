#include "files.h"
#include "utils.h"
#include "error.h"


FileHandles::FileHandles() = default;

FileHandles::~FileHandles() 
{
	user.flush();
	user.close();

	vault.flush();
	vault.close();
}

void FileHandles::createUserFile()
{
	if (!std::filesystem::exists(user_settings.parent_path())) 
	{
		std::filesystem::create_directory(user_settings.parent_path());
	}

	user.open(user_settings, std::ios::in | std::ios::out);
	if (!user.is_open()) 
	{
		throw Error{ "_file_error : error creating user_file" };
	}
}


/* -------------------------------------------------- */
// read and write functions
/* -------------------------------------------------- */
template <typename T>
void FileHandles::write(std::fstream& file, const T& msg)
{
	if (!file) {
		throw Error{ "_file_error : null file pointer" };
	}

	uint64_t len = msg.size();
	file.write(reinterpret_cast<const char*>(&len), sizeof(len));
	file.write(reinterpret_cast<const char*>(msg.data()), len);
}

template <typename T>
bool FileHandles::read(std::fstream& file, T& msg) {
	if (!file) {
		throw Error{ "_file_error : null file pointer" };
	}
	uint64_t len{ 0 };
	if (!file.read(reinterpret_cast<char*>(&len), sizeof(len))) {
		throw Error{ "_read_error : error reading data from file" };
	}
	msg.resize(len);
	file.read(reinterpret_cast<char*>(msg.data()), len);
	return true;
}

template <typename T>
T FileHandles::read(std::fstream& file) {
	if (!file) {
		throw Error{ "_file_error : null file pointer" };
	}
	uint64_t len{ 0 };
	if (!file.read(reinterpret_cast<char*>(&len), sizeof(len))) {
		throw Error{ "_read_error : error reading data from file" };
	}
	msg.resize(len);
	file.read(reinterpret_cast<char*>(msg.data()), len);
	return true;
}


bool FileHandles::loadUserSettings(std::string& name) 
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
		return loaded;
	}
	else
	{
		return false;
	}
}


void FileHandles::storeUserData(const std::string& hardwareKeyPath, const std::string& name) {
	if (!user.is_open()) {
		createUserFile();
	}
	write(user, "name,");
	write(user, name + ";");
	write(user, "hardware_path,");
	write(user, hardwareKeyPath + ";");
	user.flush();
}


void FileHandles::openKeyFile(std::fstream& key_file) 
{
	std::string name;

	if (key_file.is_open()) 
	{
		return;
	}

	if (key_path.empty()) 
	{
		if (loadUserSettings(name) == false) 
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
void FileHandles::storeKeyData(const CharBuffer& enc_key, const CharBuffer& salt, const CharBuffer& nonce)
{
	std::fstream key_file;
	openKeyFile(key_file);
	
	write(key_file, salt);
	write(key_file, nonce);
	write(key_file, enc_key);
	
	key_file.flush();
	key_file.close();
}


void FileHandles::retrieveUserData(SecureCharBuffer& enc_key, CharBuffer& salt, CharBuffer& nonce)
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