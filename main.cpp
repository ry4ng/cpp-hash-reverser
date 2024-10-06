#include <iostream>
#include <vector>
#include <string.h>
#include <cmath>
#include "sha256.h" // custom include

std::string hash(std::string plaintext);

// defaults
char keyspace[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"£$%^&*()_+-=[]{};'#:@~\\|,<.>/?";
bool verbose = false;

// testing hashes
// "U Can't Crack This - MC Bruteforcer"
// e2c56a1f4ee4641ed347092f34ba53eab0f144332872408985bda44d4ffbc8fa

int main(int argc, char *argv[])
{
    // Check an arguement (hash) has been passed
    // TODO: Include input verification (i.e. conformant to hash format)
    if (argc <= 1)
    {
        std::cout << "No hash provided, quitting." << std::endl;
        return 0;
    }

    // Keyspace to try
    // char keyspace[] = "abc";
    char keyspace[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"£$%^&*()_+-=[]{};'#:@~\\|,<.>/?";
    // char keyspace[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    int minLength = 2;
    int maxLength = 2;
    bool matchFound = false;
    std::string matchDigest;
    std::string matchPlaintext;
    verbose = false;

    // get values from arguments
    // TODO: More argument validation (avoid seg faults etc.)
    std::string targetHash = argv[1];
    minLength = atoi(argv[2]);
    maxLength = atoi(argv[3]);

    std::cout << "\nAttempting to reverse SHA-256 Hash [" << targetHash << "]\n"
              << std::endl;

    // caclulate total bruteforce possibilities
    long long numberOfPossibilities = 0;
    for (int length = minLength; length <= maxLength; ++length)
    {
        numberOfPossibilities += pow(strlen(keyspace), length);
    }

    // output parameters
    std::cout << "Min length: [" << minLength << "]" << std::endl;
    std::cout << "Max length: [" << maxLength << "]" << std::endl;
    std::cout << "Key space: [" << keyspace << "]" << std::endl;
    std::cout << "Verbose: [" << verbose << "]" << std::endl;
    std::cout << "Possibilities: [" << numberOfPossibilities << "]" << std::endl;

    // 2nd attempt
    // begin main loop
    for (int length = minLength; length <= maxLength; ++length)
    {
        if (matchFound)
        {
            break;
        }
        std::vector<int> counter(length, 0);

        while (true)
        {
            // generate the next string to hash
            std::string currentString;
            for (int i = 0; i < length; i++)
            {
                currentString += keyspace[counter[i]];
            }

            // hash the string
            std::string digest = hash(currentString);

            // check for match
            if (digest == targetHash)
            {
                matchFound = true;
                matchDigest = digest;
                matchPlaintext = currentString;
                break;
            }

            // verbose output
            if (verbose)
            {
                std::cout << currentString << std::endl;
                std::cout << digest << std::endl;
            }

            int posInCounter = length - 1;
            while (posInCounter >= 0)
            {
                counter[posInCounter] = counter[posInCounter] + 1;

                if (counter[posInCounter] == strlen(keyspace))
                {
                    counter[posInCounter] = 0;
                    posInCounter--;
                }
                else
                {
                    break;
                }
            }

            if (posInCounter < 0)
            {
                break;
            }
        }
    }

    if (matchFound)
    {
        std::cout << "\nMatch found!" << std::endl;
        std::cout << "Hash: [" << matchDigest << "]" << std::endl;
        std::cout << "Plaintext: [" << matchPlaintext << "]\n"
                  << std::endl;
    }
    else
    {
        std::cout << "\nNo matches found!\n"
                  << std::endl;
    }

    return 0;
}

std::string hash(std::string plaintext)
{
    // Create a SHA256 object and hash the input
    SHA256 sha256;
    sha256.update(reinterpret_cast<const uint8_t *>(plaintext.c_str()), plaintext.length());
    std::string hash = sha256.digest();
    return hash;
}