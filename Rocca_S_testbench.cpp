#include <iostream>
#include <string>

#include <cstring>

#include "Rocca_S.h"
using namespace std;

__uint128_t S[7]; // state array
__uint128_t N;    // 12 octets to 16 octets(since its always padded to 128 bits before use stored it as 128bit value)
__uint128_t Z0 = ((__uint128_t)0x428a2f98d728ae22ULL << 64) | 0x7137449123ef65cdULL;
__uint128_t Z1 = ((__uint128_t)0xb5c0fbcfec4d3b2fULL << 64) | 0xe9b5dba58189dbbcULL;
__uint128_t K[2] = {0, 0};

int Size_N;

__uint128_t AD[64]; // max length = 2^62 octets = 2^61 * 8 bits = 2^57 elements.
__uint128_t Size_AD;
__uint128_t M[256]; // max length = 2^125 octets = 2^125 * 8 bits = 2^121 elements.
__uint128_t Size_M;
__uint128_t C[256];
__uint128_t T[2];

typedef uint8_t state_t[4][4];

#include <iomanip>
#include <sstream>
#include <wmmintrin.h>

// Convert __uint128_t to __m128i
__m128i uint128_to_m128i(__uint128_t value)
{
    // Split the 128-bit value into two 64-bit parts
    uint64_t high = static_cast<uint64_t>(value >> 64);
    uint64_t low = static_cast<uint64_t>(value);

    // Combine them into an __m128i using the _mm_set_epi64x intrinsic
    return _mm_set_epi64x(high, low);
}

// Convert __m128i back to __uint128_t
__uint128_t m128i_to_uint128(__m128i value)
{
    // Use a temporary array to hold the 128-bit value
    uint64_t temp[2];
    _mm_storeu_si128((__m128i *)temp, value); // Store the __m128i into the array

    // Combine the two 64-bit parts into a 128-bit integer
    return ((__uint128_t)temp[1] << 64) | temp[0]; // temp[1] is the high part, temp[0] is the low part
}

std::string uint128_to_hex(__uint128_t value)
{
    std::ostringstream oss;

    // Split the 128-bit value into two 64-bit parts
    uint64_t high = static_cast<uint64_t>(value >> 64); // Higher 64 bits
    uint64_t low = static_cast<uint64_t>(value);        // Lower 64 bits

    // Print the higher part with leading zeros (even if it's zero)
    oss << std::hex << std::setw(16) << std::setfill('0') << high;

    // Print the lower part, also with leading zeros
    oss << std::hex << std::setw(16) << std::setfill('0') << low;

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

// to pad a hex string to size mod(256)=0
int PAD(string inp, __uint128_t *Array)
{
    __uint128_t len = inp.length();
    int rem = (64 - len % 64) % 64; // using 64 instead of 256 as hex values are used

    for (int i = 0; i < rem; i++)
    {
        inp = inp + "0";
    }

    __uint128_t Array_size = (inp.length()) / 32;

    for (__uint128_t i = 0; i < Array_size; i++)
    {
        __uint128_t temp = 0;
        string substring = inp.substr(i * 32, 32);
        for (int i = 0; i < 32; i++)
        {
            unsigned char val = hexCharToValue(substring[i]);
            temp << 4;
            temp = temp | val;
        }
        Array[i] = temp;
    }

    return Array_size;
}

__uint128_t PADN(string inp)
{
    __uint128_t len = inp.length();
    int rem = (32 - len % 32) % 32; // using 64 instead of 256 as hex values are used

    for (int i = 0; i < rem; i++)
    {
        inp = inp + "0";
    }

    __uint128_t temp = 0;
    string substring = inp;
    for (int i = 0; i < 32; i++)
    {
        unsigned char val = hexCharToValue(substring[i]);
        temp << 4;
        temp = temp | val;
    }

    return temp;
}

void SubBytes(state_t *state)
{
    uint8_t i, j;
    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 4; ++j)
        {
            (*state)[j][i] = sboxhw[(*state)[j][i]];
        }
    }
}

void ShiftRows(state_t *state)
{
    uint8_t temp;

    // Rotate first row 1 columns to left
    temp = (*state)[0][1];
    (*state)[0][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[3][1];
    (*state)[3][1] = temp;

    // Rotate second row 2 columns to left
    temp = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;

    temp = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    // Rotate third row 3 columns to left
    temp = (*state)[0][3];
    (*state)[0][3] = (*state)[3][3];
    (*state)[3][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[1][3];
    (*state)[1][3] = temp;
}

uint8_t xtime(uint8_t x)
{
    return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

void MixColumns(state_t *state)
{
    uint8_t i;
    uint8_t Tmp, Tm, t;
    for (i = 0; i < 4; ++i)
    {
        t = (*state)[i][0];
        Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
        Tm = (*state)[i][0] ^ (*state)[i][1];
        Tm = xtime(Tm);
        (*state)[i][0] ^= Tm ^ Tmp;
        Tm = (*state)[i][1] ^ (*state)[i][2];
        Tm = xtime(Tm);
        (*state)[i][1] ^= Tm ^ Tmp;
        Tm = (*state)[i][2] ^ (*state)[i][3];
        Tm = xtime(Tm);
        (*state)[i][2] ^= Tm ^ Tmp;
        Tm = (*state)[i][3] ^ t;
        Tm = xtime(Tm);
        (*state)[i][3] ^= Tm ^ Tmp;
    }
}

void A(state_t *state)
{
    SubBytes(state);

    ShiftRows(state);

    MixColumns(state);
}

__uint128_t AES(__uint128_t state, __uint128_t RoundKey)
{
    // Create a state_t object from the __uint128_t state
    state_t newState;
    uint64_t *stateParts = reinterpret_cast<uint64_t *>(&newState);
    stateParts[0] = static_cast<uint64_t>(state >> 64);
    stateParts[1] = static_cast<uint64_t>(state);

    // Apply the A function
    A(&newState);

    // XOR the state with the RoundKey
    uint64_t roundKeyParts[2];
    roundKeyParts[0] = static_cast<uint64_t>(RoundKey >> 64);
    roundKeyParts[1] = static_cast<uint64_t>(RoundKey);

    for (int i = 0; i < 4; ++i)
    {
        for (int j = 0; j < 4; ++j)
        {
            newState[j][i] ^= (j == 0 ? roundKeyParts[0] : roundKeyParts[1]) >> (8 * (i % 8));
        }
    }

    // Convert the state back to __uint128_t
    __uint128_t result = ((__uint128_t)newState[0][0] << 96) |
                         ((__uint128_t)newState[0][1] << 80) |
                         ((__uint128_t)newState[0][2] << 64) |
                         ((__uint128_t)newState[0][3] << 48) |
                         ((__uint128_t)newState[1][0] << 32) |
                         ((__uint128_t)newState[1][1] << 16) |
                         ((__uint128_t)newState[1][2]) |
                         ((__uint128_t)newState[1][3]);

    return result;
}

// __uint128_t AES(__uint128_t state, __uint128_t key)
// {
//     __m128i s = uint128_to_m128i(state);
//     __m128i k = uint128_to_m128i(key);
//     __m128i r = _mm_aesenc_si128(s, k);

//     __uint128_t result = m128i_to_uint128(r);
//     return result;
// }

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
    S[2] = Z0,
    S[3] = K[0],
    S[4] = Z1,
    S[5] = N ^ K[1],
    S[6] = 0;

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
    for (int i = 0; i < sizeof(AD); i = i + 2)
    {
        roundFunction(AD[i], AD[i + 1]);
    }
}

void Rocca_S_encrypt(__uint128_t *M)
{
    for (int i = 0; i < sizeof(M); i = i + 2)
    {
        C[i] = AES(S[3] ^ S[5], S[0]) ^ M[i];
        C[i] = AES(S[4] ^ S[6], S[2]) ^ M[i + 1];
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
        roundFunction(LE128(Size_AD), LE128(Size_M));
    }

    T[0] = (S[0] ^ S[1] ^ S[2] ^ S[3]);
    T[1] = (S[4] ^ S[5] ^ S[6]);
}

int main()
{

    string N_string = "0000000000000000000000000000000";
    string M_string = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    string AD_string = "000000000000000000000000000000000000000000000000000000000000000";
    Size_N = N_string.length();

    N = PADN(N_string);

    Size_AD = PAD(AD_string, AD);
    Size_M = PAD(M_string, M);

    for (int i = 0; i < Size_M; i++)
    {
        cout << i << endl;
        string temp = uint128_to_hex(M[i]);
        cout << temp;
    }
    cout << "\n";

    initialize();

    proccessAD(AD);

    Rocca_S_encrypt(M);

    finalize();
    cout << "\n\n";
    
    cout << uint128_to_hex(Size_M) << endl;

    cout << "Cipher text: ";
    for (int i = 0; i < Size_M; i++)
    {
        string temp = uint128_to_hex(C[i]);
        cout << temp;
    }
    cout << "\n";
    cout << "\n\n"
         << endl;
    for (int i = 0; i < 2; i++)
    {
        string temp = uint128_to_hex(T[i]);
        cout << temp;
    }
}