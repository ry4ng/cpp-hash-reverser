#include <atomic>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string.h>
#include <thread>
#include <vector>

// SHA-256 Implementations
#include "C-SHA256.h"    // custom
#include "SG-SHA256.h"   // sg impl
#include "SG-O-SHA256.h" // sg (optimised) impl
#include <openssl/sha.h> // openssl impl
#include <openssl/evp.h> // openssl impl (new evp api)

std::string opensslHashEvp(EVP_MD_CTX *ctx, const std::string &plaintext);

// Auxiliary functions
EVP_MD_CTX *createContext();
void cleanupContext(EVP_MD_CTX *ctx);
std::string formatHashesPerSecond(double hashesPerSecond);

// Keyspace containing possible characters for brute-force
char keyspace[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
// Atomic boolean to indicate if a match has been found (shared across threads)
std::atomic<bool> matchFound(false);
// Mutex to protect output to the console (to avoid overlapping prints)
std::mutex outputMutex;
// Atomic variable to track progress (number of hashes computed)
std::atomic<long long> progress(0);
// Variables to track peak and average hashes per second
std::atomic<double> peakHashesPerSecond(0.0);
// Global variable to store end time
std::chrono::time_point<std::chrono::high_resolution_clock> endTime;

void updateProgress(long long totalCombinations, std::chrono::time_point<std::chrono::high_resolution_clock> startTime)
{
    const int barWidth = 40; // Width of the progress bar
    while (!matchFound && progress.load() < totalCombinations)
    {
        long long currentProgress = progress.load();
        double percentage = (static_cast<double>(currentProgress) / totalCombinations) * 100;
        int pos = static_cast<int>((currentProgress * barWidth) / totalCombinations);

        auto currentTime = std::chrono::high_resolution_clock::now();
        auto elapsedMilliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(currentTime - startTime).count();
        double elapsedSeconds = elapsedMilliseconds / 1000.0;

        // Calculate hashes per second
        long long currentHashes = progress.load();
        double hashesPerSecond = (elapsedSeconds > 0) ? static_cast<double>(currentHashes) / elapsedSeconds : 0.0;

        // Update peak hash rate
        if (hashesPerSecond > peakHashesPerSecond.load())
        {
            peakHashesPerSecond.store(hashesPerSecond);
        }

        // Calculate elapsed time in days, hours, minutes, seconds, milliseconds
        long long days = elapsedMilliseconds / 86400000;
        long long hours = (elapsedMilliseconds % 86400000) / 3600000;
        long long minutes = (elapsedMilliseconds % 3600000) / 60000;
        long long seconds = (elapsedMilliseconds % 60000) / 1000;
        long long milliseconds = elapsedMilliseconds % 1000;

        std::ostringstream elapsedTimeStr;
        if (days > 0)
            elapsedTimeStr << days << "d ";
        if (hours > 0 || days > 0)
            elapsedTimeStr << hours << "h ";
        if (minutes > 0 || hours > 0 || days > 0)
            elapsedTimeStr << minutes << "m ";
        elapsedTimeStr << seconds << "s " << milliseconds << "ms";

        std::cout << "\rProgress: [";
        for (int i = 0; i < barWidth; ++i)
        {
            if (i < pos)
            {
                std::cout << "=";
            }
            else if (i == pos)
            {
                std::cout << ">";
            }
            else
            {
                std::cout << " ";
            }
        }
        std::cout << "] " << std::fixed << std::setprecision(2) << percentage << "%";
        std::cout << " | Time Elapsed: " << elapsedTimeStr.str();
        std::cout << " | Hashes/sec: " << formatHashesPerSecond(hashesPerSecond) << std::flush;

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    // Print final progress if all combinations have been checked or match is found
    if (progress.load() >= totalCombinations)
    {
        endTime = std::chrono::high_resolution_clock::now();
        auto totalElapsedMilliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
        double totalElapsedSeconds = totalElapsedMilliseconds / 1000.0;

        // Calculate elapsed time in days, hours, minutes, seconds, milliseconds
        long long days = totalElapsedMilliseconds / 86400000;
        long long hours = (totalElapsedMilliseconds % 86400000) / 3600000;
        long long minutes = (totalElapsedMilliseconds % 3600000) / 60000;
        long long seconds = (totalElapsedMilliseconds % 60000) / 1000;
        long long milliseconds = totalElapsedMilliseconds % 1000;

        std::ostringstream elapsedTimeStr;
        if (days > 0)
            elapsedTimeStr << days << "d ";
        if (hours > 0 || days > 0)
            elapsedTimeStr << hours << "h ";
        if (minutes > 0 || hours > 0 || days > 0)
            elapsedTimeStr << minutes << "m ";
        elapsedTimeStr << seconds << "s " << milliseconds << "ms";

        std::cout << "\rProgress: [";
        for (int i = 0; i < barWidth; ++i)
        {
            std::cout << "=";
        }
        std::cout << "] 100.00% | Time Elapsed: " << elapsedTimeStr.str() << std::endl;
    }
}

// Function that performs the brute-force task for each thread
void bruteForceTask(const std::string &targetHash, int minLength, int maxLength, EVP_MD_CTX *ctx, long long startIndex, long long endIndex, bool doProgress)
{
    long long keyspaceSize = strlen(keyspace);

    for (long long currentIndex = startIndex; currentIndex < endIndex && !matchFound; ++currentIndex)
    {
        // Calculate the current string from the currentIndex
        long long tempIndex = currentIndex;
        std::string currentString;
        int length = minLength;

        // Generate the string corresponding to currentIndex
        while (tempIndex > 0 || length <= maxLength)
        {
            currentString.insert(currentString.begin(), keyspace[tempIndex % keyspaceSize]);
            tempIndex /= keyspaceSize;
            if (tempIndex == 0 && currentString.length() >= minLength)
            {
                break;
            }
        }

        // Hash the current string using OpenSSL EVP API
        std::string digest = opensslHashEvp(ctx, currentString);

        // Check if the generated hash matches the target hash
        if (digest == targetHash)
        {
            matchFound = true;                             // Update the atomic flag to indicate that a match is found
            std::lock_guard<std::mutex> lock(outputMutex); // Lock the output to prevent race conditions
            std::cout << "\n\nMatch found!" << std::endl;
            std::cout << "Hash: [" << digest << "]" << std::endl;
            std::cout << "Plaintext: [" << currentString << "]\n"
                      << std::endl;
            return;
        }

        // From a quick test, this does not seem to impact performance 
        if (currentIndex % 100 == 0)
        {
            // Increment the number of hashes computed
            progress.fetch_add(100);
        }
    }
}

int main(int argc, char *argv[])
{
    // Check if a hash has been provided as an argument
    if (argc <= 1)
    {
        std::cout << "No hash provided, quitting." << std::endl;
        return 0;
    }

    // Get target hash and length parameters from command line arguments
    std::string targetHash = argv[1];
    int minLength = (argc > 2) ? atoi(argv[2]) : 1;
    int maxLength = (argc > 3) ? atoi(argv[3]) : 4;
    bool doProgress = false; // flag to output progress whilst brute-forcing (false = increased performance)

    // Calculate total brute-force possibilities for all lengths
    long long numberOfPossibilities = 0;
    for (int length = minLength; length <= maxLength; ++length)
    {
        numberOfPossibilities += pow(strlen(keyspace), length);
    }

    // Output the parameters being used
    std::cout << "\nAttempting to reverse SHA-256 Hash [" << targetHash << "]\n"
              << std::endl;
    std::cout << "Key space:\t\t[" << keyspace << "]" << std::endl;
    std::cout << "Min length:\t\t[" << minLength << "]" << std::endl;
    std::cout << "Max length:\t\t[" << maxLength << "]" << std::endl;
    std::cout << "Possibilities:\t\t[" << numberOfPossibilities << "]" << std::endl;

    // Calculate total number of combinations for all lengths
    long long totalCombinations = 0;
    long long keyspaceSize = strlen(keyspace);
    for (int length = minLength; length <= maxLength; ++length)
    {
        totalCombinations += pow(keyspaceSize, length);
    }

    // Determine the number of threads to use
    int numThreads = std::thread::hardware_concurrency();
    if (numThreads == 0) numThreads = 4; // Default to 4 threads if unable to determine
    numThreads--;       // stops program from maxing out computer resources
    std::cout << "Threads available:\t[" << std::thread::hardware_concurrency() << "]" << std::endl;
    std::cout << "Threads utilising:\t[" << numThreads << "]" << std::endl;

    // Calculate the range of indices for each thread to process
    long long chunkSize = totalCombinations / numThreads;
    std::cout << "Thread chunk size:\t[" << chunkSize << "]" << std::endl;
    std::vector<std::thread> threads;
    std::vector<EVP_MD_CTX *> contexts(numThreads);

    // Start hash computation timer
    auto startTime = std::chrono::high_resolution_clock::now();

    // Create threads and assign each a range of indices
    for (int i = 0; i < numThreads; ++i)
    {
        contexts[i] = createContext();
        long long startIndex = i * chunkSize;
        long long endIndex = (i == numThreads - 1) ? totalCombinations : startIndex + chunkSize;
        threads.emplace_back(bruteForceTask, targetHash, minLength, maxLength, contexts[i], startIndex, endIndex, doProgress);
    }

    if (doProgress)
    {
        std::cout << std::endl;
        // Create a thread to update the progress bar
        std::thread progressThread(updateProgress, totalCombinations, startTime);
        // Wait for the progress thread to complete
        progressThread.join();
    }

    // Wait for all threads to complete their work
    for (auto &t : threads)
    {
        t.join();
    }

    // Finish hash computation timer
    endTime = std::chrono::high_resolution_clock::now();

    // Cleanup OpenSSL contexts
    for (auto ctx : contexts)
    {
        cleanupContext(ctx);
    }

    // If no match was found, indicate this to the user
    if (!matchFound)
    {
        std::cout << "\nNo matches found!\n"
                  << std::endl;
    }

    // PERFORMANCE SUMMARY
    auto endTime = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> elapsedDuration = endTime - startTime; // Elapsed time in milliseconds as a floating-point value
    double totalElapsedMilliseconds = elapsedDuration.count(); // Total time in milliseconds
    double totalElapsedSeconds = totalElapsedMilliseconds / 1000.0; // Total time in seconds

    // Calculate average hash rate using precise elapsed milliseconds
    double averageHashesPerSecond = (totalElapsedMilliseconds > 0) ? (static_cast<double>(progress.load()) / (totalElapsedMilliseconds / 1000.0)) : 0.0;

    // Calculate elapsed time in days, hours, minutes, seconds, milliseconds
    long long days = static_cast<long long>(totalElapsedMilliseconds) / 86400000;
    long long hours = (static_cast<long long>(totalElapsedMilliseconds) % 86400000) / 3600000;
    long long minutes = (static_cast<long long>(totalElapsedMilliseconds) % 3600000) / 60000;
    long long seconds = (static_cast<long long>(totalElapsedMilliseconds) % 60000) / 1000;
    double milliseconds = fmod(totalElapsedMilliseconds, 1000.0); // Use floating-point to retain precision

    std::ostringstream elapsedTimeStr;
    if (days > 0)
        elapsedTimeStr << days << "d ";
    if (hours > 0 || days > 0)
        elapsedTimeStr << hours << "h ";
    if (minutes > 0 || hours > 0 || days > 0)
        elapsedTimeStr << minutes << "m ";
    elapsedTimeStr << seconds << "s " << std::fixed << std::setprecision(2) << milliseconds << "ms";

    // Print summary
    std::cout << "Total Time Elapsed:\t[" << elapsedTimeStr.str() << "]" << std::endl;
    std::cout << "Average Hashes/sec:\t[" << formatHashesPerSecond(averageHashesPerSecond) << "]" << std::endl;
    if (doProgress) {
        std::cout << "Peak Hashes/sec:\t[" << formatHashesPerSecond(peakHashesPerSecond.load()) << "]\n" << std::endl;
    } else {
        std::cout << std::endl;
    }

    return 0;
}

// Function to hash plaintext using OpenSSL EVP API
std::string opensslHashEvp(EVP_MD_CTX *ctx, const std::string &plaintext)
{
    // Update the context with the data to be hashed
    EVP_DigestUpdate(ctx, plaintext.c_str(), plaintext.size());

    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int hashLength = 0;

    // Finalise the digest calculation
    EVP_DigestFinal_ex(ctx, hash, &hashLength);

    constexpr char hexChars[] = "0123456789abcdef";
    thread_local char hexBuffer[SHA256_DIGEST_LENGTH * 2 + 1]; // +1 for null terminator

    // Convert the hash to a hexadecimal string
    for (unsigned int i = 0; i < hashLength; ++i)
    {
        hexBuffer[2 * i] = hexChars[(hash[i] >> 4) & 0xF];
        hexBuffer[2 * i + 1] = hexChars[hash[i] & 0xF];
    }

    // Null-terminate the buffer
    hexBuffer[hashLength * 2] = '\0';

    // Reinitialize the context for the next hash
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);

    return std::string(hexBuffer);
}

// Function to create an OpenSSL EVP context
EVP_MD_CTX *createContext()
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr)
    {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1)
    {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize digest");
    }
    return ctx;
}

// Function to clean up an OpenSSL EVP context
void cleanupContext(EVP_MD_CTX *ctx)
{
    EVP_MD_CTX_free(ctx);
}

// Function to format hashes per second with appropriate units
std::string formatHashesPerSecond(double hashesPerSecond)
{
    std::ostringstream formatted;
    if (hashesPerSecond >= 1e9)
    {
        formatted << std::fixed << std::setprecision(2) << (hashesPerSecond / 1e9) << " G";
    }
    else if (hashesPerSecond >= 1e6)
    {
        formatted << std::fixed << std::setprecision(2) << (hashesPerSecond / 1e6) << " M";
    }
    else if (hashesPerSecond >= 1e3)
    {
        formatted << std::fixed << std::setprecision(2) << (hashesPerSecond / 1e3) << " K";
    }
    else
    {
        formatted << std::fixed << std::setprecision(2) << hashesPerSecond;
    }
    formatted << " H/s";
    return formatted.str();
}