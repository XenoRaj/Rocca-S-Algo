#include <iostream>
#include <string>
#include <immintrin.h>
#include <cstring>

#include "Rocca_S.h"
using namespace std;
__uint128_t lenAD;
__uint128_t lenM;
__uint128_t S[7]; // state array
__uint128_t N;    // 12 octets to 16 octets(since its always padded to 128 bits before use stored it as 128bit value)
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
// int PAD(string inp, __uint128_t *Array)
// {
//     __uint128_t len = inp.length();
//     int rem = (64 - len % 64) % 64; // using 64 instead of 256 as hex values are used

//     for (int i = 0; i < rem; i++)
//     {
//         inp = inp + "0";
//     }

//     __uint128_t Array_size = (inp.length()) / 32;

//     for (__uint128_t i = 0; i < Array_size-1; i=i+2)
//     {
//         __uint128_t temp = 0;
//         string substring = inp.substr(i * 32, 32);
//         for (int j = 31; j >=1; j=j-2)
//         {
//             unsigned char val = hexCharToValue(substring[j-1]);
//             temp = (temp << 4) | val;
//             val = hexCharToValue(substring[j]);
//             temp = (temp << 4) | val;
//         }
//         Array[i+1] = temp;
//         substring = inp.substr(i * 32+32, 32);
//         temp = 0;
//         for (int j = 31; j >=1; j=j-2)
//         {
//             unsigned char val = hexCharToValue(substring[j-1]);
//             temp = (temp << 4) | val;
//             val = hexCharToValue(substring[j]);
//             temp = (temp << 4) | val;
//         }
//         Array[i] = temp;
//     }

//     return Array_size;
// }

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

// __uint128_t PADN(string inp)
// {
//     __uint128_t len = inp.length();
//     int rem = (32 - len % 32) % 32; // using 64 instead of 256 as hex values are used

//     for (int i = 0; i < rem; i++)
//     {
//         inp = inp + "0";
//     }

//     __uint128_t temp = 0;
//     string substring = inp;
//     for (int i = 31; i >=1; i=i-2)
//     {
//         unsigned char val = hexCharToValue(substring[i-1]);
//         temp = (temp << 4) | val;
//         val = hexCharToValue(substring[i]);
//         temp = (temp << 4) | val;
//     }

//     return temp;
// }

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
        temp = (temp << 4) | val;
    }

    return temp;
}

void subBytes(unsigned char *state)
{
    int i;
    /* substitute all the values from the state with the value in the SBox
     * using the state value as index for the SBox
     */
    for (i = 0; i < 16; i++)
        state[i] = getSBoxValue(state[i]);
}

void shiftRow(unsigned char *state, unsigned char nbr)
{
    int i, j;
    unsigned char tmp;
    /* each iteration shifts the row to the left by 1 */
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
    unsigned char column[4];
    /* iterate over the 4 rows and call shiftRow() with that row */
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            column[j] = state[(j * 4) + i];
        }
        shiftRow(column, i);
        for (j = 0; j < 4; j++)
        {
            state[(j * 4) + i] = column[j];
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

    /* iterate over the 4 columns */
    for (i = 0; i < 4; i++)
    {
        /* construct one column by iterating over the 4 rows */
        for (j = 0; j < 4; j++)
        {
            column[j] = state[j + i * 4];
        }

        /* apply the mixColumn on one column */
        mixColumn(column);

        /* put the values back into the state */
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

void uint128_to_charArray_mine(__uint128_t value, uint8_t *array)
{
    for (int i = 0; i < 16; i++)
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

__uint128_t charArray_to_uint128_mine(uint8_t *array) // working
{
    __uint128_t result = 0;
    for (int i = 15; i >= 0; i--)
    {
        result = (result << 8) | array[i];
    }

    return result;
}

void aes_round(unsigned char *state, unsigned char *roundKey)
{
    __uint128_t result = 0x0;
    // string ans = "";
    // result = charArray_to_uint128(state);
    // ans = uint128_to_hex(result);
    // cout << "before starting round: " << ans << "\n\n";

    subBytes(state);
    result = charArray_to_uint128(state);
    // ans = uint128_to_hex(result);
    // cout << "after sub bytes: " << ans << "\n\n";

    shiftRows(state);
    result = charArray_to_uint128(state);
    // ans = uint128_to_hex(result);
    // cout << "after shift rows: " << ans << "\n\n";

    mixColumns(state);
    result = charArray_to_uint128(state);
    // ans = uint128_to_hex(result);
    // cout << "after mix columns: " << ans << "\n\n";

    addRoundKey(state, roundKey);
    result = charArray_to_uint128(state);
    // ans = uint128_to_hex(result);
    // cout << "after add round key: " << ans << "\n\n";
}

__m128i char16_to_m128i(unsigned char input[16])
{
    // Load the 16 bytes (128 bits) from the input array into an __m128i value
    return _mm_loadu_si128((const __m128i *)input);
}

void m128i_to_char16(__m128i input, unsigned char output[16])
{
    // Store the 128-bit __m128i value into the output array
    _mm_storeu_si128((__m128i *)output, input);
}
#define load(m) _mm_loadu_si128((const __m128i *)(m))
#define store(m, a) _mm_storeu_si128((__m128i *)(m), a)

__uint128_t AESimp(__uint128_t state, __uint128_t key)
{
    uint8_t newState[16];
    uint8_t roundKey[16];

    uint128_to_charArray(state, newState);
    uint128_to_charArray(key, roundKey);

    // aes_round(newState, roundKey);
    __m128i ans = _mm_aesenc_si128(load(&newState), load(&roundKey));
    store(&newState, ans);
    __uint128_t result = charArray_to_uint128(newState);
    // string before = uint128_to_hex(state);
    // cout << "state: ";

    // cout << before << endl;
    return result;
}

__uint128_t AES(__uint128_t state, __uint128_t key)
{
    uint8_t newState[16];
    uint8_t roundKey[16];

    uint128_to_charArray(state, newState);
    uint128_to_charArray(key, roundKey);

    aes_round(newState, roundKey);
    // __m128i ans = _mm_aesenc_si128(load(&newState), load(&roundKey));
    // store(&newState,ans);
    __uint128_t result = charArray_to_uint128(newState);
    // string before = uint128_to_hex(state);
    // cout << "state: ";

    // cout << before << endl;
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

    cout << "before update round: \n";
    for (int i = 0; i < 7; i++)
    {
        cout << uint128_to_hex(S[i]) << endl;
    }
    cout << endl;
    S[0] = Snew[0];
    S[1] = Snew[1];
    S[2] = Snew[2];
    S[3] = Snew[3];
    S[4] = Snew[4];
    S[5] = Snew[5];
    S[6] = Snew[6];

    cout << "after update round: \n";
    for (int i = 0; i < 7; i++)
    {
        cout << uint128_to_hex(S[i]) << endl;
    }
    cout << endl;
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

    cout << "after first init: \n";
    for (int i = 0; i < 7; i++)
    {
        cout << uint128_to_hex(S[i]) << endl;
    }

    for (int i = 0; i < 16; i++)
    {
        roundFunction(Z0, Z1);
        cout << "after " << i << " round: \n";
        for (int i = 0; i < 7; i++)
        {
            cout << uint128_to_hex(S[i]) << endl;
        }
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
    cout << uint128_to_hex(LE128(lenAD)) << endl;
    cout << uint128_to_hex(LE128(lenM)) << endl;

    T[0] = (((S[0] ^ S[1]) ^ S[2]) ^ S[3]);
    T[1] = ((S[4] ^ S[5]) ^ S[6]);
}

int main()
{

    string N_string = "44444444444444444444444444444444";
    string M_string = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
    string AD_string = "";
    Size_N = N_string.length();

    string K_string = "1111111111111111111111111111111122222222222222222222222222222222";
    lenAD = AD_string.length() * 4;
    lenM = M_string.length() * 4;
    int lenMint = M_string.length() * 4;

    int x = PAD(K_string, K);
    cout << "key size: " << x << endl;

    N = PADN(N_string);

    Size_AD = PAD(AD_string, AD);
    Size_M = PAD(M_string, M);
    cout << "\n";
    for (int i = 0; i < Size_AD; i++)
    {
        cout << i << endl;
        string temp = uint128_to_hex(AD[i]);
        cout << temp;
    }
    cout << "\n";
    for (int i = 0; i < Size_M; i++)
    {
        cout << i << endl;
        string temp = uint128_to_hex(M[i]);
        cout << temp;
    }
    cout << "\n";

    initialize();
    cout << "after initialization: \n";
    for (int i = 0; i < 7; i++)
    {
        cout << uint128_to_hex(S[i]) << endl;
    }

    proccessAD(AD);
    cout << "after processAD: \n";
    for (int i = 0; i < 7; i++)
    {
        cout << uint128_to_hex(S[i]) << endl;
    }

    Rocca_S_encrypt(M);
    cout << "after encrypt: \n";
    for (int i = 0; i < 7; i++)
    {
        cout << uint128_to_hex(S[i]) << endl;
    }

    cout << "finalize: \n";
    finalize();
    cout << "\n\n";
    cout << "after tag: \n";
    for (int i = 0; i < 7; i++)
    {
        cout << uint128_to_hex(S[i]) << endl;
    }
    cout << "Cipher text: \n";
    for (int i = 0; i < Size_M; i++)
    {
        string temp = uint128_to_hex(C[i]);
        cout << temp << " ";
    }
    cout << "\n";
    cout << "\n\nTAG: "
         << endl;

    for (int i = 0; i < 2; i++)
    {
        string temp = uint128_to_hex(T[i]);
        cout << temp << " ";
    }
    cout << "\n\n";
    cout << uint128_to_hex(Size_AD) << endl;
    cout << uint128_to_hex(Size_M) << endl;

    const __uint128_t s = ((__uint128_t)0x193de3bea0f4e22bULL << 64) | 0x9ac68d2ae9f84808ULL;
    const __uint128_t s_le = ((__uint128_t)0x0848f8e92a8dc69aULL << 64) | 0x2be2f4a0bee33d19ULL;

    const __uint128_t k = ((__uint128_t)0xa0fafe1788542cb1ULL << 64) | 0x23a339392a6c7605ULL;
    const __uint128_t k_le = ((__uint128_t)0x05766c2a3939a323ULL << 64) | 0xb12c548817fef8a0ULL;

    __uint128_t l = AESimp(s, k);
    __uint128_t r = AES(s, k);

    string res = uint128_to_hex(l);
    cout << "\n\n";
    cout << "res: ";
    cout << res << endl;
    res = uint128_to_hex(r);
    cout << "\n\n";
    cout << "res(mine): ";
    cout << res << endl;
    cout << uint128_to_hex(lenM) << endl;
    cout << lenMint << endl;
    // string nounce = uint128_to_hex(N);
    // cout << "\n\n";
    // // cout << "nounce: ";
    // // cout << nounce;
    // __uint128_t s2 = __uint128_t(0x428a2f98d728ae22 << 64) | (0x7137449123ef65cd);
    // __uint128_t s6 = __uint128_t(0xd6a398ac8f2e584c << 64) | (0x8ad6b8c6e2eab8df);
    // __uint128_t res = AES(s2, s6);
    // cout << "\n\n"
    //  << uint128_to_hex(res) << endl;
}