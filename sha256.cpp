#include "sha256.h"
#include <sstream>
#include <iomanip>
#include <cstring>

// SHA-256 constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
const uint32_t SHA256::k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Initial hash values for SHA-256
const uint32_t SHA256::initialHash[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// Constructor
SHA256::SHA256() {
    reset();
}

// Resets the internal state of the hash
void SHA256::reset() {
    memcpy(h, initialHash, sizeof(initialHash));
    bitLength = 0;
    bufferLength = 0;
}

// Updates the hash with a chunk of data
void SHA256::update(const uint8_t *data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        buffer[bufferLength++] = data[i];
        bitLength += 8;
        if (bufferLength == 64) {
            transform(buffer);
            bufferLength = 0;
        }
    }
}

// Finalizes the hash and returns the result as a hex string
std::string SHA256::digest() {
    uint8_t padding[64] = { 0x80 };
    size_t paddingLength = (bufferLength < 56) ? (56 - bufferLength) : (120 - bufferLength);
    uint64_t lengthBits = bitLength;

    // Pad with 0x80 followed by zeros, and then append the bitLength (64-bit big-endian)
    update(padding, paddingLength);

    uint8_t lengthBytes[8];
    for (int i = 0; i < 8; ++i) {
        lengthBytes[i] = (lengthBits >> (56 - i * 8)) & 0xff;
    }
    update(lengthBytes, 8);

    uint8_t hashDigest[32];
    for (int i = 0; i < 8; ++i) {
        hashDigest[i * 4] = (h[i] >> 24) & 0xff;
        hashDigest[i * 4 + 1] = (h[i] >> 16) & 0xff;
        hashDigest[i * 4 + 2] = (h[i] >> 8) & 0xff;
        hashDigest[i * 4 + 3] = h[i] & 0xff;
    }

    return toHexString(hashDigest);
}

// Processes a 512-bit chunk of data
void SHA256::transform(const uint8_t *chunk) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, temp_h;

    for (int i = 0; i < 16; ++i) {
        w[i] = (chunk[i * 4] << 24) | (chunk[i * 4 + 1] << 16) | (chunk[i * 4 + 2] << 8) | (chunk[i * 4 + 3]);
    }

    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = h[0]; b = h[1]; c = h[2]; d = h[3];
    e = h[4]; f = h[5]; g = h[6]; temp_h = h[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = temp_h + s1 + ch + k[i] + w[i];
        uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + maj;

        temp_h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += temp_h;
}

// Converts the hash digest to a hexadecimal string
std::string SHA256::toHexString(const uint8_t *digest) {
    std::stringstream ss;
    for (int i = 0; i < 32; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }
    return ss.str();
}
