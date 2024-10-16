#include <cstdint>
#include <map>
#include <string>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <hls_stream.h>
#include <ap_int.h>
#include <utility>
struct axis_data
{
	ap_uint<8> data;
    ap_uint<1> last;
};

using namespace std;
using TestVectorDict = std::map<std::string, std::string>;

TestVectorDict testVectors = {
    {"test_vector_1_key", "0000000000000000000000000000000000000000000000000000000000000000"},
    {"test_vector_1_nonce", "00000000000000000000000000000000"},
    {"test_vector_1_associated_data", "0000000000000000000000000000000000000000000000000000000000000000"},
    {"test_vector_1_plaintext", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
    {"test_vector_1_ciphertext", "9ac3326495a8d414fe407f47b54410502481cf79cab8c0a669323e07711e46170de5b2fbba0fae8de7c1fccaeefc362624fcfdc15f8bb3e64457e8b7e37557bb"},
    {"test_vector_1_tag", "8df934d1483710c9410f6a089c4ced9791901b7e2e661206202db2cc7a24a386"},

    {"test_vector_2_key", "0101010101010101010101010101010101010101010101010101010101010101"},
    {"test_vector_2_nonce", "01010101010101010101010101010101"},
    {"test_vector_2_associated_data", "0101010101010101010101010101010101010101010101010101010101010101"},
    {"test_vector_2_plaintext", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
    {"test_vector_2_ciphertext", "559ecb253bcfe26b483bf00e9c748345978ff921036a6c1fdcb712172836504fbc64d430a73fc67acd3c3b9c1976d80790f48357e7fe0c0682624569d3a658fb"},
    {"test_vector_2_tag", "c1fdf39762eca77da8b0f1dae5fff75a92fb0adfa7940a28c8cadbbbe8e4ca8d"},

    {"test_vector_3_key", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
    {"test_vector_3_nonce", "0123456789abcdef0123456789abcdef"},
    {"test_vector_3_associated_data", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
    {"test_vector_3_plaintext", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
    {"test_vector_3_ciphertext", "b5fc4e2a72b86d1a133c0f0202bdf790af14a24b2cdb676e427865e12fcc9d3021d18418fc75dc1912dd2cd79a3beeb2a98b235de2299b9dda93fd2b5ac8f436"},
    {"test_vector_3_tag", "a078e1351ef2420c8e3a93fd31f5b1135b15315a5f205534148efbcd63f79f00"},

    {"test_vector_4_key", "1111111111111111111111111111111122222222222222222222222222222222"},
    {"test_vector_4_nonce", "44444444444444444444444444444444"},
    {"test_vector_4_associated_data", ""},
    {"test_vector_4_plaintext", "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7"},
    {"test_vector_4_ciphertext", "e8c7adcc58302893b253c544f5d8e62d8fbd81160c2f4a95123962088d29f106422d3f26882fd7b1"},
    {"test_vector_4_tag", "f650eba86fb19dc14a3bbe8bbfad9ec5b5dd77a4c3f83d2c19ac0393dd47928f"},

    {"test_vector_5_key", "1111111111111111111111111111111122222222222222222222222222222222"},
    {"test_vector_5_nonce", "44444444444444444444444444444444"},
    {"test_vector_5_associated_data", ""},
    {"test_vector_5_plaintext", "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"},
    {"test_vector_5_ciphertext", "e8c7adcc58302893b253c544f5d8e62d8fbd81160c2f4a95123962088d29f106422d3f26882fd7b1fdee5680476e7e6e"},
    {"test_vector_5_tag", "49bb0ec78cab2c5f40a535925fa2d82752aba9606426537fc774f06fc0f6fc12"},

    {"test_vector_6_key", "1111111111111111111111111111111122222222222222222222222222222222"},
    {"test_vector_6_nonce", "44444444444444444444444444444444"},
    {"test_vector_6_associated_data", ""},
    {"test_vector_6_plaintext", "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8"},
    {"test_vector_6_ciphertext", "e8c7adcc58302893b253c544f5d8e62d8fbd81160c2f4a95123962088d29f106422d3f26882fd7b1fdee5680476e7e6e1fc473cdb2dded85c6"},
    {"test_vector_6_tag", "c674604803963a4b51685fda1f2aa043934736db2fbab6d188a09f5e0d1c0bf3"},

    {"test_vector_7_key", "1111111111111111111111111111111122222222222222222222222222222222"},
    {"test_vector_7_nonce", "44444444444444444444444444444444"},
    {"test_vector_7_associated_data", ""},
    {"test_vector_7_plaintext", "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"},
    {"test_vector_7_ciphertext", "e8c7adcc58302893b253c544f5d8e62d8fbd81160c2f4a95123962088d29f106422d3f26882fd7b1fdee5680476e7e6e1fc473cdb2dded85c692344f3ab85af0"},
    {"test_vector_7_tag", "850599a6624a3e936a77768c7717b926cc519081730df447127654d6980bcb02"}};

static const __uint128_t Z0 = ((__uint128_t)0xcdULL << 120) | ((__uint128_t)0x65ULL << 112) |
                              ((__uint128_t)0xefULL << 104) | ((__uint128_t)0x23ULL << 96) |
                              ((__uint128_t)0x91ULL << 88) | ((__uint128_t)0x44ULL << 80) |
                              ((__uint128_t)0x37ULL << 72) | ((__uint128_t)0x71ULL << 64) |
                              ((__uint128_t)0x22ULL << 56) | ((__uint128_t)0xaeULL << 48) |
                              ((__uint128_t)0x28ULL << 40) | ((__uint128_t)0xd7ULL << 32) |
                              ((__uint128_t)0x98ULL << 24) | ((__uint128_t)0x2fULL << 16) |
                              ((__uint128_t)0x8aULL << 8) | 0x42ULL;

static const __uint128_t Z1 = ((__uint128_t)0xbcULL << 120) | ((__uint128_t)0xdbULL << 112) |
                              ((__uint128_t)0x89ULL << 104) | ((__uint128_t)0x81ULL << 96) |
                              ((__uint128_t)0xa5ULL << 88) | ((__uint128_t)0xdbULL << 80) |
                              ((__uint128_t)0xb5ULL << 72) | ((__uint128_t)0xe9ULL << 64) |
                              ((__uint128_t)0x2fULL << 56) | ((__uint128_t)0x3bULL << 48) |
                              ((__uint128_t)0x4dULL << 40) | ((__uint128_t)0xecULL << 32) |
                              ((__uint128_t)0xcfULL << 24) | ((__uint128_t)0xfbULL << 16) |
                              ((__uint128_t)0xc0ULL << 8) | 0xb5ULL;
const uint8_t sboxhw[256] = {
    // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

#define getSBoxValue(num) (sboxhw[(num)])

pair<string, string> Rocca_S_sw(string K_string, string N_string, string AD_string, string M_string);

void Rocca_S_hw(hls::stream<axis_data> &input, hls::stream<axis_data> &output);
//
