#include <iostream>
#include "sha256.h"

std::string hash(std::string plaintext);

int main(int argc, char *argv[]) {

    // Check an arguement has been passed
    if (argc <= 1) {
        std::cout << "No hash provided, quitting." << std::endl;
        return 0;
    }

    std::string targetHash = argv[1];
    std::cout << "Attempting to reverse SHA-256 Hash: [" << targetHash << "]" << std::endl;

    std::string input = "abc";
    std::string digest = hash(input);
    
    std::cout << "SHA-256 hash of '" << input << "': " << digest << std::endl;
    
    return 0;
}

std::string hash(std::string plaintext) {
    // Create a SHA256 object and hash the input
    SHA256 sha256;
    sha256.update(reinterpret_cast<const uint8_t*>(plaintext.c_str()), plaintext.length());
    std::string hash = sha256.digest();
    return hash;
}