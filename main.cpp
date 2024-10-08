#include <iostream>
#include <vector>
#include <cmath>
#include <sstream>
#include <iomanip>
#include <string.h>
// SHA-256 Implemenations
#include "C-SHA256.h"    // custom
#include "SG-SHA256.h" // sg impl
#include "SG-O-SHA256.h" // sg (optimised) impl
#include <openssl/sha.h> // openssl impl
#include <openssl/evp.h> // openssl impl (new evp api)

std::string customV2Hash(const std::string& plaintext);
std::string sgHash(std::string plaintext);
std::string opensslV2Hash(const std::string& plaintext);
std::string opensslHashEvp(std::string plaintext);
std::string sgOHash(std::string& plaintext);

// defaults
char keyspace[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"£$%^&*()_+-=[]{};'#:@~\\|,<.>/?";
bool verbose = false;

// testing hashes
// "U Can't Crack This - MC Bruteforcer": e2c56a1f4ee4641ed347092f34ba53eab0f144332872408985bda44d4ffbc8fa
// "bbb":3e744b9dc39389baf0c5a0660589b8402f3dbb49b89b3e75f2c9355852a3c677
// "ddgg":a8e8dfffc20660dec4a5c857630cb096ed53b3bd51e1879f8b27fa4f4a94b9c7
// "//??":83d9855c183d7d1b1fc38363b5b5cbad7bfca54a3167d53d111503aafb90a5ce

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
    // char keyspace[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"£$%^&*()_+-=[]{};'#:@~\\|,<.>/?";
    char keyspace[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

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

            std::string digest;
            // digest = customV2Hash(currentString); // Custom
            // digest = sgHash(currentString); // SG
            // digest = opensslV2Hash(currentString); // OpenSSL 
            // digest = opensslHashEvp(currentString); // OpenSSL (EVP)
            digest = sgOHash(currentString); // SG

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

std::string customV2Hash(const std::string& plaintext)
{
    // C_SHA256 optimised 
    // Impl not yet optimised 
    
    // Create a SHA256 object and hash the input
    C_SHA256 sha256;
    sha256.update(reinterpret_cast<const uint8_t *>(plaintext.c_str()), plaintext.length());
    return sha256.digest();
}

std::string sgHash(std::string plaintext)
{
    // Create a SHA256 object and hash the input
    SG_SHA256 sha;
    sha.update(plaintext);
    return SG_SHA256::toString(sha.digest());
}

std::string opensslV2Hash(const std::string& plaintext) 
{
    // Impl optimised 
    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, plaintext.c_str(), plaintext.size());
    SHA256_Final(hash, &sha256);

    // Using a character array instead of stringstream for better performance
    constexpr char hexChars[] = "0123456789abcdef";
    std::string hashStr(SHA256_DIGEST_LENGTH * 2, '0');

    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        hashStr[2 * i] = hexChars[(hash[i] >> 4) & 0xF];
        hashStr[2 * i + 1] = hexChars[hash[i] & 0xF];
    }

    return hashStr;
}

std::string opensslHashEvp(std::string plaintext) 
{
    // TODO: Optimise this implementation 
    // Create an EVP_MD_CTX for context handling
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    
    // Initialize the context to use SHA-256
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);

    // Update the context with the data to be hashed
    EVP_DigestUpdate(ctx, plaintext.c_str(), plaintext.size());

    unsigned char hash[EVP_MAX_MD_SIZE];  // Buffer to store the resulting hash
    unsigned int hashLength = 0;          // To store the actual length of the hash
    
    EVP_DigestFinal_ex(ctx, hash, &hashLength);

    // Free the context
    EVP_MD_CTX_free(ctx);

    // Convert the hash to a hexadecimal string
    std::stringstream ss;
    for (unsigned int i = 0; i < hashLength; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}

std::string sgOHash(std::string& plaintext)
{
    // Create a SHA256 object and hash the input
    SG_O_SHA256 sha;
    sha.update(plaintext);
    return SG_O_SHA256::toString(sha.digest());
}