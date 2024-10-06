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
    char keyspace[] = "ab";
    // char keyspace[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"£$%^&*()_+-=[]{};'#:@~\\|,<.>/?";

    // 2nd attempt 
    int maxLenth = 3;
    for (int length = 1;length <= maxLenth; ++length) {
        std::vector<int> counter(length, 0); 

        std::cout << "=============\nLength: " << length << std::endl;
        // std::cout << "counter: " << counter.size() << std::endl;
        // displayCounter(counter);

        while (true) {
            std::string currentString; 
            // std::cout << "entering 3rd loop" << std::endl;
            for (int i = 0; i < length; i++) {
                std::cout << "i: " << i << std::endl;
                currentString += keyspace[counter[i]];
                displayCounter(counter);
            }
            std::cout << currentString << std::endl;

            int pos = length - 1;
            std::cout << "pos: " << pos << std::endl;
            while(pos >= 0) {
                counter[pos] = counter[pos] + 1; 

                if (counter[pos] == strlen(keyspace)) {
                    counter[pos] = 0;
                    pos--;
                } else {
                    break;
                }
            }

            if (pos < 0) {
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