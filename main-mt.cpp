#include <iostream>
#include <vector>
#include <cmath>
#include <sstream>
#include <iomanip>
#include <string.h>
#include <thread>
#include <mutex>
#include <atomic>

// SHA-256 Implementations
#include "C-SHA256.h"    // custom
#include "SG-SHA256.h"    // sg impl
#include "SG-O-SHA256.h"  // sg (optimised) impl
#include <openssl/sha.h>  // openssl impl
#include <openssl/evp.h>  // openssl impl (new evp api)

std::string opensslHashEvp(EVP_MD_CTX* ctx, const std::string& plaintext);

// Auxiliary functions
EVP_MD_CTX* createContext();
void cleanupContext(EVP_MD_CTX* ctx);

char keyspace[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
std::atomic<bool> matchFound(false);
std::mutex outputMutex;

void bruteForceTask(const std::string& targetHash, int minLength, int maxLength, EVP_MD_CTX* ctx, long long startIndex, long long endIndex) {
    long long keyspaceSize = strlen(keyspace);

    for (long long currentIndex = startIndex; currentIndex < endIndex && !matchFound; ++currentIndex) {
        // Calculate the current string from the currentIndex
        long long tempIndex = currentIndex;
        std::string currentString;
        int length = minLength;

        while (tempIndex > 0 || length <= maxLength) {
            currentString.insert(currentString.begin(), keyspace[tempIndex % keyspaceSize]);
            tempIndex /= keyspaceSize;
            if (tempIndex == 0 && currentString.length() >= minLength) {
                break;
            }
        }

        // Hash the current string
        std::string digest = opensslHashEvp(ctx, currentString);

        // Check for match
        if (digest == targetHash) {
            matchFound = true;
            std::lock_guard<std::mutex> lock(outputMutex);
            std::cout << "\nMatch found!" << std::endl;
            std::cout << "Hash: [" << digest << "]" << std::endl;
            std::cout << "Plaintext: [" << currentString << "]\n" << std::endl;
            return;
        }
    }
}

int main(int argc, char* argv[]) {
    // Check an argument (hash) has been passed
    if (argc <= 1) {
        std::cout << "No hash provided, quitting." << std::endl;
        return 0;
    }

    // Get values from arguments
    std::string targetHash = argv[1];
    int minLength = (argc > 2) ? atoi(argv[2]) : 1;
    int maxLength = (argc > 3) ? atoi(argv[3]) : 4;

    // caclulate total bruteforce possibilities
    long long numberOfPossibilities = 0;
    for (int length = minLength; length <= maxLength; ++length)
    {
        numberOfPossibilities += pow(strlen(keyspace), length);
    }

    // Output parameters
    std::cout << "\nAttempting to reverse SHA-256 Hash [" << targetHash << "]\n" << std::endl;
    std::cout << "Min length: [" << minLength << "]" << std::endl;
    std::cout << "Max length: [" << maxLength << "]" << std::endl;
    std::cout << "Key space: [" << keyspace << "]" << std::endl;
    std::cout << "Possibilities: [" << numberOfPossibilities << "]" << std::endl;

    // Calculate total number of combinations for all lengths
    long long totalCombinations = 0;
    long long keyspaceSize = strlen(keyspace);
    for (int length = minLength; length <= maxLength; ++length) {
        totalCombinations += pow(keyspaceSize, length);
    }

    // Number of threads
    int numThreads = std::thread::hardware_concurrency();
    // numThreads = 12;
    if (numThreads == 0) numThreads = 4; // Default to 4 threads if unable to determine

    std::cout << "Using " << numThreads << " threads." << std::endl;

    // Calculate the range of indices for each thread
    long long chunkSize = totalCombinations / numThreads;
    std::vector<std::thread> threads;
    std::vector<EVP_MD_CTX*> contexts(numThreads);

    for (int i = 0; i < numThreads; ++i) {
        contexts[i] = createContext();
        long long startIndex = i * chunkSize;
        long long endIndex = (i == numThreads - 1) ? totalCombinations : startIndex + chunkSize;
        threads.emplace_back(bruteForceTask, targetHash, minLength, maxLength, contexts[i], startIndex, endIndex);
    }

    // Wait for all threads to finish
    for (auto& t : threads) {
        t.join();
    }

    // Cleanup contexts
    for (auto ctx : contexts) {
        cleanupContext(ctx);
    }

    if (!matchFound) {
        std::cout << "\nNo matches found!\n" << std::endl;
    }

    return 0;
}

std::string opensslHashEvp(EVP_MD_CTX* ctx, const std::string& plaintext) {
    // Update the context with the data to be hashed
    EVP_DigestUpdate(ctx, plaintext.c_str(), plaintext.size());

    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int hashLength = 0;

    // Finalise the digest calculation
    EVP_DigestFinal_ex(ctx, hash, &hashLength);

    constexpr char hexChars[] = "0123456789abcdef";
    thread_local char hexBuffer[SHA256_DIGEST_LENGTH * 2 + 1]; // +1 for null terminator

    // Convert the hash to a hexadecimal string
    for (unsigned int i = 0; i < hashLength; ++i) {
        hexBuffer[2 * i] = hexChars[(hash[i] >> 4) & 0xF];
        hexBuffer[2 * i + 1] = hexChars[hash[i] & 0xF];
    }

    // Null-terminate the buffer
    hexBuffer[hashLength * 2] = '\0';

    // Reinitialize for the next hash
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);

    return std::string(hexBuffer);
}

EVP_MD_CTX* createContext() {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize digest");
    }
    return ctx;
}

void cleanupContext(EVP_MD_CTX* ctx) {
    EVP_MD_CTX_free(ctx);
}