#ifndef SYSTEM_H
#define SYSTEM_H

#include "files.h"
#include "user.h"

class System {
	private:
		FileHandles* sys_files;
		User* user;
		SecureCharBuffer vault_key;
		std::vector<CharBuffer> metadata_list;

	private:
		int insert(const CharBuffer&);
		int find(const CharBuffer&) const;

	public:
		System();
		~System();

		const std::string& name() const;
		void createNewUser(const std::string&, const std::string&);
		int loadUser();
		
		int createVaultKey(const SecureString&, const std::string&);
		int unlockKey(const SecureString&);

		void loadMetadata();
		void displayMetadataList() const;

		void addEntry(const CharBuffer&, const SecureCharBuffer&, const SecureCharBuffer&);
		int searchEntry(const CharBuffer&, SecureCharBuffer&, SecureCharBuffer&);
};

# endif // ! SYSTEM_H