# cpp-hash-reverser

A simple brute-force hash cracker written in C++.

## Todo 

- optimise OpenSSL (EVP) impl
- optimise OpenSSL (Depricated) 
- thousand delimiter for `numberOfPossibilities`
- improve command line flags/args
- progress indicator (progress bar or "most sig bit")
- multi-threading / multi-processing 
- clean up this readme 

## Install 

MacOS
```
$ brew install openssl
$ brew install libomp # for omp processing 
$ brew --prefix openssl # shows where openssl is located
$ brew install gcc # clang doesn't support omp out of the box need gcc
$ brew info gcc
```

MacOS (GCC) - OpenMP Support 
```
/usr/local/Cellar/gcc/14.2.0/bin

$ export PATH="/usr/local/Cellar/gcc/14.2.0/bin:$PATH"

$ g++-14 -std=c++11 -fopenmp main.cpp c-sha256.cpp SG-SHA256.cpp SG-O-SHA256.cpp -lcrypto -o out/main -Wno-deprecated-declarations

$ g++-14 -std=c++11 -fopenmp main.cpp c-sha256.cpp SG-SHA256.cpp SG-O-SHA256.cpp -o out/main -Wno-deprecated-declarations -I/usr/local/opt/openssl@3/include -L/usr/local/opt/openssl@3/lib -lcrypto
```

## Compile

MacOS / Windows 
```bash
$ g++ -std=c++11 main.cpp C-SHA256.cpp SG-SHA256.cpp -o out/main
```

MacOS / Windows (With OpenSSL)
```bash
$ g++ -std=c++11 main.cpp C-SHA256.cpp SG-SHA256.cpp -lcrypto -o out/main
```

MacOS / Windows (With OpenSSL and warning supression)
```bash
 g++ -std=c++11 main.cpp c-sha256.cpp SG-SHA256.cpp SG-O-SHA256.cpp -lcrypto -o out/main -Wno-deprecated-declarations 
```

MacOS / Windows (With OpenSSL and warning supression) - *Multi-threaded*
```bash
 g++ -std=c++11 main-mt.cpp c-sha256.cpp SG-SHA256.cpp SG-O-SHA256.cpp -lcrypto -o out/main -Wno-deprecated-declarations 
```

## Running 

MacOS - Benchmarking 
```bash
caffeinate /usr/bin/time ./out/main e2c56a1f4ee4641ed347092f34ba53eab0f144332872408985bda44d4ffbc8fa 1 4
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
