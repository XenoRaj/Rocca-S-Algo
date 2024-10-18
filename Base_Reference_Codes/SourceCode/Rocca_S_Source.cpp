#include <iostream>
#include <string>
#include <iomanip>
#include <sstream>
#include "Rocca_S.h"

using namespace std;

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

static const __uint128_t Z0LE = ((__uint128_t)0x42ULL << 120) | ((__uint128_t)0x8aULL << 112) |
                                ((__uint128_t)0x2fULL << 104) | ((__uint128_t)0x98ULL << 96) |
                                ((__uint128_t)0xd7ULL << 88) | ((__uint128_t)0x28ULL << 80) |
                                ((__uint128_t)0xaeULL << 72) | ((__uint128_t)0x22ULL << 64) |
                                ((__uint128_t)0x71ULL << 56) | ((__uint128_t)0x37ULL << 48) |
                                ((__uint128_t)0x44ULL << 40) | ((__uint128_t)0x91ULL << 32) |
                                ((__uint128_t)0x23ULL << 24) | ((__uint128_t)0xefULL << 16) |
                                ((__uint128_t)0x65ULL << 8) | 0xcdULL;

static const __uint128_t Z1LE = ((__uint128_t)0xb5ULL << 120) | ((__uint128_t)0xc0ULL << 112) |
                                ((__uint128_t)0xfbULL << 104) | ((__uint128_t)0xcfULL << 96) |
                                ((__uint128_t)0xecULL << 88) | ((__uint128_t)0x4dULL << 80) |
                                ((__uint128_t)0x3bULL << 72) | ((__uint128_t)0x2fULL << 64) |
                                ((__uint128_t)0xe9ULL << 56) | ((__uint128_t)0xb5ULL << 48) |
                                ((__uint128_t)0xdbULL << 40) | ((__uint128_t)0xa5ULL << 32) |
                                ((__uint128_t)0x81ULL << 24) | ((__uint128_t)0x89ULL << 16) |
                                ((__uint128_t)0xdbULL << 8) | 0xbcULL;

__uint128_t K[2] = {0, 0};

__uint128_t lenAD;
__uint128_t lenM;
__uint128_t S[7]; // state array
__uint128_t N;    // 12 octets to 16 octets(since its always padded to 128 bits before use stored it as 128bit value)

__uint128_t AD[64]; // max length = 2^62 octets = 2^61 * 8 bits = 2^57 elements.
__uint128_t Size_AD;
__uint128_t M[256]; // max length = 2^125 octets = 2^125 * 8 bits = 2^121 elements.
__uint128_t Size_M;
__uint128_t C[256];
__uint128_t T[2];

string uint128_to_hex(__uint128_t value)
{
    ostringstream oss;

    // Split the 128-bit value into two 64-bit parts
    uint64_t high = static_cast<uint64_t>(value >> 64); // Higher 64 bits
    uint64_t low = static_cast<uint64_t>(value);        // Lower 64 bits

    // Print the higher part with leading zeros (even if it's zero)
    oss << hex << setw(16) << setfill('0') << high;

    // Print the lower part, also with leading zeros
    oss << hex << setw(16) << setfill('0') << low;

    return oss.str();
}

unsigned char hexCharToValue(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    throw std::invalid_argument("Invalid hex character");
}

int PAD(string inp, __uint128_t *Array)
{
    __uint128_t len = inp.length();
    int rem = (64 - len % 64) % 64; // using 64 instead of 256 as hex values are used

    for (int i = 0; i < rem; i++)
    {
        inp = inp + "0";
    }

    __uint128_t Array_size = (inp.length()) / 32;

    for (__uint128_t i = 0; i < Array_size; i = i + 1)
    {
        __uint128_t temp = 0;
        string substring = inp.substr(i * 32, 32);
        for (int j = 0; j < 32; j++)
        {
            unsigned char val = hexCharToValue(substring[j]);
            temp = (temp << 4) | val;
        }
        Array[i] = temp;
    }

    return Array_size;
}

__uint128_t PADN(string inp)
{
    __uint128_t len = inp.length();
    int rem = (32 - len % 32) % 32;

    for (int i = 0; i < rem; i++)
    {
        inp = inp + "0";
    }

    __uint128_t temp = 0;
    string substring = inp;
    for (int i = 0; i < 32; i++)
    {
        unsigned char val = hexCharToValue(substring[i]);

        temp = (temp << 4) | val;
    }

    return temp;
}

void subBytes(unsigned char *state)
{
    int i;
    for (i = 0; i < 16; i++)
        state[i] = getSBoxValue(state[i]);
}

void shiftRow(unsigned char *state, unsigned char nbr)
{
    int i, j;
    unsigned char tmp;
    for (i = 0; i < nbr; i++)
    {
        tmp = state[0];
        for (j = 0; j < 3; j++)
            state[j] = state[j + 1];
        state[3] = tmp;
    }
}

void shiftRows(unsigned char *state)
{
    int i, j;
    unsigned char row[4];
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            row[j] = state[(j * 4) + i];
        }

        shiftRow(row, i);

        for (j = 0; j < 4; j++)
        {
            state[(j * 4) + i] = row[j];
        }
    }
}

void addRoundKey(unsigned char *state, unsigned char *roundKey)
{
    int i;
    for (i = 0; i < 16; i++)
        state[i] = state[i] ^ roundKey[i];
}

unsigned char galois_multiplication(unsigned char a, unsigned char b)
{
    unsigned char p = 0;
    unsigned char counter;
    unsigned char hi_bit_set;
    for (counter = 0; counter < 8; counter++)
    {
        if ((b & 1) == 1)
            p ^= a;
        hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set == 0x80)
            a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

void mixColumn(unsigned char *column)
{
    unsigned char cpy[4];
    int i;
    for (i = 0; i < 4; i++)
    {
        cpy[i] = column[i];
    }
    column[0] = galois_multiplication(cpy[0], 2) ^
                galois_multiplication(cpy[3], 1) ^
                galois_multiplication(cpy[2], 1) ^
                galois_multiplication(cpy[1], 3);

    column[1] = galois_multiplication(cpy[1], 2) ^
                galois_multiplication(cpy[0], 1) ^
                galois_multiplication(cpy[3], 1) ^
                galois_multiplication(cpy[2], 3);

    column[2] = galois_multiplication(cpy[2], 2) ^
                galois_multiplication(cpy[1], 1) ^
                galois_multiplication(cpy[0], 1) ^
                galois_multiplication(cpy[3], 3);

    column[3] = galois_multiplication(cpy[3], 2) ^
                galois_multiplication(cpy[2], 1) ^
                galois_multiplication(cpy[1], 1) ^
                galois_multiplication(cpy[0], 3);
}

void mixColumns(unsigned char *state)
{
    int i, j;
    unsigned char column[4];

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            column[j] = state[j + i * 4];
        }

        mixColumn(column);

        for (j = 0; j < 4; j++)
        {
            state[j + i * 4] = column[j];
        }
    }
}
void uint128_to_charArray(__uint128_t value, uint8_t *array) // working
{
    for (int i = 15; i >= 0; i--)
    {
        array[i] = (uint8_t)(value & 0xFF);
        value >>= 8;
    }
}

__uint128_t charArray_to_uint128(uint8_t *array) // working
{
    __uint128_t result = 0;
    for (int i = 0; i < 16; i++)
    {
        result = (result << 8) | array[i];
    }

    return result;
}

void aes_round(unsigned char *state, unsigned char *roundKey)
{
    subBytes(state);

    shiftRows(state);

    mixColumns(state);

    addRoundKey(state, roundKey);
}

__uint128_t AES(__uint128_t state, __uint128_t key)
{
    uint8_t newState[16];
    uint8_t roundKey[16];

    uint128_to_charArray(state, newState);
    uint128_to_charArray(key, roundKey);

    aes_round(newState, roundKey);

    __uint128_t result = charArray_to_uint128(newState);

    return result;
}

void roundFunction(__uint128_t X_0, __uint128_t X_1)
{
    __uint128_t Snew[7];
    Snew[0] = S[6] ^ S[1];
    Snew[1] = AES(S[0], X_0);
    Snew[2] = AES(S[1], S[0]);
    Snew[3] = AES(S[2], S[6]);
    Snew[4] = AES(S[3], X_1);
    Snew[5] = AES(S[4], S[3]);
    Snew[6] = AES(S[5], S[4]);

    S[0] = Snew[0];
    S[1] = Snew[1];
    S[2] = Snew[2];
    S[3] = Snew[3];
    S[4] = Snew[4];
    S[5] = Snew[5];
    S[6] = Snew[6];
}

void initialize()
{
    S[0] = K[1],
    S[1] = N,
    S[2] = Z0;
    S[3] = K[0];
    S[4] = Z1;
    S[5] = N ^ K[1];
    S[6] = 0x000000000000000000000000;

    for (int i = 0; i < 16; i++)
    {
        roundFunction(Z0, Z1);
    }
    S[0] = S[0] ^ K[0];
    S[1] = S[1] ^ K[0];
    S[2] = S[2] ^ K[1];
    S[3] = S[3] ^ K[0];
    S[4] = S[4] ^ K[0];
    S[5] = S[5] ^ K[1];
    S[6] = S[6] ^ K[1];
}

void proccessAD(__uint128_t *AD)
{
    for (int i = 0; i < Size_AD; i = i + 2)
    {
        roundFunction(AD[i], AD[i + 1]);
    }
}

void Rocca_S_encrypt(__uint128_t *M)
{
    for (int i = 0; i < Size_M; i = i + 2)
    {
        C[i] = AES(S[3] ^ S[5], S[0]) ^ M[i];
        C[i + 1] = AES(S[4] ^ S[6], S[2]) ^ M[i + 1];
        roundFunction(M[i], M[i + 1]);
    }
}

__uint128_t LE128(__uint128_t num)
{
    __uint128_t out = 0;
    for (int i = 0; i < 16; i++)
    {
        out = out << 8;
        out = out | (num & 0xFF);
        num = num >> 8;
    }
    return out;
}

void finalize()
{
    for (int i = 0; i < 16; i++)
    {
        roundFunction(LE128(lenAD), LE128(lenM));
    }

    T[0] = (((S[0] ^ S[1]) ^ S[2]) ^ S[3]);
    T[1] = ((S[4] ^ S[5]) ^ S[6]);
}

int main()
{
    for (int i = 1; i <= 7; i++)
    {
        string s = "test_vector_" + to_string(i) + "_";

        string K_string = testVectors[s + "key"];
        string N_string = testVectors[s + "nonce"];
        string M_string = testVectors[s + "plaintext"];
        string AD_string = testVectors[s + "associated_data"];
        string C_string = testVectors[s + "ciphertext"];
        string T_string = testVectors[s + "tag"];

        lenAD = AD_string.length() * 4;
        lenM = M_string.length() * 4;

        PAD(K_string, K);

        N = PADN(N_string);

        Size_AD = PAD(AD_string, AD);
        Size_M = PAD(M_string, M);

        initialize();

        proccessAD(AD);

        Rocca_S_encrypt(M);

        finalize();

        string cipher_output = "";
        string tag_output = "";
        for (int i = 0; i < Size_M; i++)
        {
            cipher_output += uint128_to_hex(C[i]);
        }

        for (int i = 0; i < 2; i++)
        {
            tag_output += uint128_to_hex(T[i]);
        }

        if (cipher_output.substr(0, lenM / 4) != C_string)
        {
            cout << "ERROR: Cipher text doesn't match in test_vector " << i << endl;
            return 1;
        }
        if (tag_output != T_string)
        {
            cout << "ERROR: Tag doesn't match in test_vector " << i << endl;
            return 1;
        }
    }
    cout << "****************************************\n\n";
    cout << "All tests passed successfully\n\n";
    cout << "****************************************";
}