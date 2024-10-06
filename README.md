# cpp-hash-reverser

A simple brute-force hash cracker written in C++.

## Install 

MacOS
```
$ brew install openssl
$ brew --prefix openssl # shows where openssl is located
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
$ g++ -std=c++11 main.cpp c-sha256.cpp SG-SHA256.cpp -lcrypto -o out/main -Wno-deprecated-declarations
```

## SHA256 Implementations

### Custom

### System-Glitch (SG)

https://github.com/System-Glitch/SHA256/tree/master

### OpenSSL (Deprecated and EVP Method)

https://github.com/openssl/openssl/tree/master
