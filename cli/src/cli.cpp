#include <vector>
#include <string>

#include "cli.h"
#include "utils.h"
#include "constants.h"

CLI::CLI() : running(true), system(new System()), loggedIn(false)
{}

CLI::~CLI() {
	delete system;
	system = nullptr;
}

void CLI::processInput(const std::string& command) {
	if (command.size() == 0) {
		return;
	}
	else if (command == "help") {
		printHelpMenu();
	}
	else if (command == "login") {
		int status = system->loadUser();

		if (status == 0) {
			std::cout << "No user found...\n"
				      << "Create New User...\n";
			return;
		}

		SecureString password;
		std::cout << "Enter Master Password : ";
		std::cin >> password;

		status = system->unlockKey(password);
		zero(password);

		if (status == 1) {
			std::cout << "Wrong Password...\n"
					  << "Try Again..\n";
		}
		else {
			std::cout << "Correct Password...\n"
					  << "Unlocked Vault...\n";
			std::cout << "Welcome " << system->name() << "\n";
			system->loadMetadata();
			loggedIn = true;
		}
	}
	else if (command == "clear") {
		std::cout << "\033[2J\033[H";
		printCLI();
	}
	else if (command == "exit") {
		running = false;
		system->clear();
		std::cout << "User Logged Out...\n";
	}
	else if (command == "new") {
		std::string name;
		std::string hardware_path;

		std::cout << "Enter Name : ";
		std::cin.ignore();
		std::getline(std::cin, name, '\n');
		std::cout << "Enter Hardware Path : ";
		std::cin >> hardware_path;

		if (system->createNewUser(name, hardware_path) != 0) {
			std::cout << "Entered Hardware Path cannot be found...\n"
					  << "Connect the hardware key and try again...\n";
		}
		else {
			SecureString password;
			std::cout << "Set Master Password : ";
			std::cin >> password;
			system->createVaultKey(password);
			zero(password);
			std::cout << "New User Created\n"
					  << "Login to Proceed..\n";
		}
	}
	else if (!loggedIn) {
		std::cout << "Error...\n"
				  << "Login to Continue..\n";
		return;
	}
	else if (command == "add") {
		CharBuffer metadata;
		SecureCharBuffer username;
		SecureCharBuffer password;

		std::cout << "Enter metadata : ";
		input(metadata);
		std::cout << "Enter username : ";
		input(username);
		std::cout << "Enter password : ";
		input(password);

		system->addEntry(metadata, username, password);

		zero(metadata);
		zero(username);
		zero(password);
	}
	else if (command == "ls") {
		system->displayMetadataList();
	}
	else if (command == "search") {
		CharBuffer metadata;
		std::cout << "Enter metadata : ";
		input(metadata);

		SecureCharBuffer username;
		SecureCharBuffer password;
		if (!system->searchEntry(metadata, username, password)) {
			std::cout << "No matching entry found..\n";
		}
		else {
			std::cout << "Username : " << username
					  << "Password : " << password;
		}
		zero(metadata);
	}
}

void CLI::printCLI() const {
		std::cout << std::setw(50) << "______              _   __           \n"
				  << std::setw(50) << "| ___ \\            | | / /           \n"
				  << std::setw(50) << "| |_/ /_ _ ___ ___ | |/ /  ___ _   _ \n"
				  << std::setw(50) << "|  __/ _` / __/ __||    \\ / _ \\ | | |\n"
				  << std::setw(50) << "| | | (_| \\__ \\__ \\| |\\  \\  __/ |_| |\n"
				  << std::setw(50) << "\\_|  \\__,_|___/___/\\_| \\_/\\___|\\__, |\n"
				  << std::setw(50) << "                                __/ |\n"
				  << std::setw(50) << "                               |___/ \n";
}

void CLI::printHeader() const {
	std::cout << "\npasskey > ";
}

void CLI::printHelpMenu() const {
	std::cout << std::setw(35) << "CLI COMMANDS\n"
			  << "---------------------------------------------------------\n"
			  << "new : create new user\n"
              << "login : login and unlock vault\n"
		      << "exit : logout and exit program\n"
		      << "add : for adding new credentials\n"
			  << "ls : display list of stored credential's metadata\n"
			  << "search : display credentials\n"
			  << "clear : clear terminal\n"
		      << "---------------------------------------------------------\n";
}

void CLI::printSoftwareInfo() const {
	std::cout << std::setw(40) << "Secure Password Manager\n"
			  << "---------------------------------------------------------\n"
		      << "Version : v0.1.0\n"
			  << "Type 'help' to see available commands.\n"
		      << "---------------------------------------------------------\n"
		      << "\n\n";
}
