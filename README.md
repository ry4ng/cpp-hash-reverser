# cpp-hash-reverser

A simple brute-force hash cracker written in C++.

## Todo

-   optimise OpenSSL (EVP) impl
-   optimise OpenSSL (Depricated)
-   thousand delimiter for `numberOfPossibilities`
-   improve command line flags/args
-   progress indicator (progress bar or "most sig bit")
-   multi-threading / multi-processing
-   clean up this readme

## Install

### MacOS

```
$ brew install openssl
$ brew install libomp # for omp processing
$ brew --prefix openssl # shows where openssl is located
$ brew install gcc # clang doesn't support omp out of the box need gcc
$ brew info gcc
```

#### MacOS (GCC) - OpenMP Support

```
/usr/local/Cellar/gcc/14.2.0/bin

$ export PATH="/usr/local/Cellar/gcc/14.2.0/bin:$PATH"

$ g++-14 -std=c++11 -fopenmp main.cpp c-sha256.cpp SG-SHA256.cpp SG-O-SHA256.cpp -lcrypto -o out/main -Wno-deprecated-declarations

$ g++-14 -std=c++11 -fopenmp main.cpp c-sha256.cpp SG-SHA256.cpp SG-O-SHA256.cpp -o out/main -Wno-deprecated-declarations -I/usr/local/opt/openssl@3/include -L/usr/local/opt/openssl@3/lib -lcrypto
```

### Windows

1. Install MiniGW from

-   https://github.com/niXman/mingw-builds-binaries/releases
-   `x86_64-14.2.0-release-posix-seh-ucrt-rt_v12-rev0.7z`
-   Unzip the file and add the `bin` directory to `PATH` enviornment variable
-   e.g. `C:\Users\Ryan\Downloads\mingw64\bin`

## Compile

### Windows - _Multi-threaded_

```
g++ -I"C:\Users\Ryan\workspace\vcpkg\installed\x64-windows\include" main-mt.cpp c-sha256.cpp SG-SHA256.cpp SG-O-SHA256.cpp -L"C:\Users\Ryan\workspace\vcpkg\installed\x64-windows\lib" -lcrypto -o out/main -Wno-deprecated-declarations
```

### MacOS

```bash
 g++ -std=c++11 main.cpp c-sha256.cpp SG-SHA256.cpp SG-O-SHA256.cpp -lcrypto -o out/main -Wno-deprecated-declarations
```

### MacOS - _Multi-threaded_

```bash
 g++ -std=c++11 main-mt.cpp c-sha256.cpp SG-SHA256.cpp SG-O-SHA256.cpp -lcrypto -o out/main -Wno-deprecated-declarations
```

## Running

### MacOS - Benchmarking

```bash
caffeinate /usr/bin/time ./out/main e2c56a1f4ee4641ed347092f34ba53eab0f144332872408985bda44d4ffbc8fa 1 4
```

### Windows

```bash
./out/main a8e8dfffc20660dec4a5c857630cb096ed53b3bd51e1879f8b27fa4f4a94b9c7 1 4
```

## SHA256 Implementations

### Custom

### System-Glitch (SG)

https://github.com/System-Glitch/SHA256/tree/master

### System-Glitch (SG-Optimised)

Modified version of:
https://github.com/System-Glitch/SHA256/tree/master

### OpenSSL (Deprecated and EVP Method)

https://github.com/openssl/openssl/tree/master
