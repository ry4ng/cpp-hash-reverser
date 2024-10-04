#ifndef SHA256_H
#define SHA256_H

#include <string>
#include <cstdint>

class SHA256 {
public:
    SHA256(); // Constructor
    void update(const uint8_t *data, size_t length); // Updates the hash with data
    std::string digest(); // Finalizes the hash and returns the result

private:
    void reset(); // Resets the internal state of the hash
    void transform(const uint8_t *chunk); // Processes each 512-bit chunk of data
    std::string toHexString(const uint8_t *digest); // Converts the hash to a hex string

    uint32_t h[8]; // Hash values
    uint64_t bitLength; // Total length of the input in bits
    uint8_t buffer[64]; // Input buffer
    size_t bufferLength; // Length of the buffer

    static const uint32_t k[64]; // Constants used in the SHA-256 algorithm
    static const uint32_t initialHash[8]; // Initial hash values

    // Rotates bits to the right
    inline uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }
};

#endif
