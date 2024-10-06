#include <iostream>
#include "sha256.h"
#include <vector>


std::string hash(std::string plaintext);
void displayCounter(std::vector<int> counter);

char keyspace[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"£$%^&*()_+-=[]{};'#:@~\\|,<.>/?";

int main(int argc, char *argv[]) {

    // Check an arguement (hash) has been passed
    // TODO: Include input verification (i.e. conformant to hash format)
    if (argc <= 1) {
        std::cout << "No hash provided, quitting." << std::endl;
        return 0;
    }

    std::string targetHash = argv[1];
    std::string guessedHash = "";

    // std::cout << "Attempting to reverse SHA-256 Hash: [" << targetHash << "]" << std::endl;

    // Keyspace to try 
    // char keyspace[] = "abc";
    char keyspace[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"£$%^&*()_+-=[]{};'#:@~\\|,<.>/?";
    // char keyspace[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    // 2nd attempt 
    int maxLenth = 4;
    for (int length = 1;length <= maxLenth; ++length) {
        std::vector<int> counter(length, 0); 

        while (true) {
            std::string currentString; 
            for (int i = 0; i < length; i++) {
                currentString += keyspace[counter[i]];
            }
            std::cout << currentString << std::endl;
            std::string digest = hash(currentString);
            std::cout << digest << std::endl;

            int posInCounter = length - 1;
            while(posInCounter >= 0) {
                counter[posInCounter] = counter[posInCounter] + 1; 

                if (counter[posInCounter] == strlen(keyspace)) {
                    counter[posInCounter] = 0;
                    posInCounter--;
                } else {
                    break;
                }
            }

            if (posInCounter < 0) {
                break;
            }
        }

        // for (int i = 0; i < counter.size(); ++i) {
        //     std::cout << counter[i] << std::endl;
        // }

        std::cout << "" << std::endl;
    }

    // 1st attempt 
    // char guess[128] = "";
    // std::vector<int> indices(1, 0);
    
    // int i = 0;
    // int j = 0;
    // while (guessedHash != targetHash) {

    //     std::cout << "ind: " << keyspace[indices[i]] << std::endl;

    //     guess[j] = keyspace[i];
    //     guess[j-1] = keyspace[j-1];

    //     std::cout << "i: " << i << std::endl;
    //     std::cout << "j: " << j << std::endl;
    //     std::cout << guess << "\n" << std::endl;
        
    //     if (i == strlen(keyspace) - 1) {
    //         i = 0;
    //         j++;
    //         std::cout << "=================" << std::endl;
    //     } else {
    //         i++;
    //     }
     
    //     if (j == 3) {
    //         break;
    //     }
    // }

    std::string input = "abc";
    std::string digest = hash(input);
    
    // std::cout << "SHA-256 hash of '" << input << "': " << digest << std::endl;
    
    return 0;
}

std::string hash(std::string plaintext) {
    // Create a SHA256 object and hash the input
    SHA256 sha256;
    sha256.update(reinterpret_cast<const uint8_t*>(plaintext.c_str()), plaintext.length());
    std::string hash = sha256.digest();
    return hash;
}

void displayCounter(std::vector<int> counter) {
    // Display content of the counter 
    std::cout << "[";
    for (int i = 0; i < counter.size(); ++i) {
        std::cout << counter[i];
        // If it's not the last element, print a comma and space
        if (i < counter.size() - 1) {
            std::cout << ", ";
        }
    }
    std::cout << "]" << std::endl;
}