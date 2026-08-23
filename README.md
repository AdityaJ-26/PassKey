                                ██████╗  █████╗ ███████╗███████╗██╗  ██╗███████╗██╗   ██╗
                                ██╔══██╗██╔══██╗██╔════╝██╔════╝██║ ██╔╝██╔════╝╚██╗ ██╔╝
                                ██████╔╝███████║███████╗███████╗█████╔╝ █████╗   ╚████╔╝
                                ██╔═══╝ ██╔══██║╚════██║╚════██║██╔═██╗ ██╔══╝    ╚██╔╝
                                ██║     ██║  ██║███████║███████║██║  ██╗███████╗   ██║
                                ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝
![Build](https://img.shields.io/badge/build-passing-brightgreen)
![Tests](https://img.shields.io/badge/test-pending-lightgrey)
![Version](https://img.shields.io/badge/version-v0.1.0-blue)
![Status](https://img.shields.io/badge/status-beta-orange)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-blueviolet)
=========================================================================
## About
PassKey is a **Hardware Key based Offline Password Manager**.<br>

Provides full control over data as there is no cloud storage. Stores the vault locally on user's device encrypted using vault_key.<br>

The vault_key is stored on external hardware device in encrypted form. To access credentials, the hardware device and the master_password is required, providing Two-Step authentication.<br>

Check the software [release](https://github.com/AdityaJ-26/PassKey/releases)

## Structure
```
[PassKey]
  |
  |-----core                             # software core implementation
  |     |
  |     |-----include
  |     |     |
  |     |     |-----(.h)                 # public headers
  |     | 
  |     |-----src                        # private headers and implementations .cpp files
  |     |     |
  |     |     |-----(.h/.cpp)
  |     |
  |     |-----CMakeLists.txt             # core subdirectory CML
  |
  |-----cli                              # cli implementation, abstracts core
  |     |
  |     |-----src
  |           |
  |           |-----cli.cpp/cli.h
  |
  |-----main.cpp                         # main()
  |
  |-----CMakeLists.txt                   # root CML
  |
  |-----third_party                      # stores third_party libs (libsodium)
  |
  |-----README.md
  |-----.gitignore
```

## How to Build
program contains CML for CMake build generation, use below commands in root directory

- For Linux
```
# to generate build files
cmake -S . -B build

# to generate executables
cmake --build build

# to execute
./build/passkey
```

- For Windows
```
# to generate build files
# choose one between Debug and Release, if using Visual Studio you can skip this 
cmake -S . -B build -DCMAKE_BUILD_TYPE=(Debug/Release)

# to generate executable
cmake --build build

# how to execute
./build/Debug/passkey
```
