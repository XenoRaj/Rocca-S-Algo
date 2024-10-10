#include <cstdint>
#include <hls_stream.h>
#include <ap_int.h>

struct axis_data
{
    uint8_t data;
    ap_uint<1> last;
};

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

__uint128_t charArray_to_uint128(uint8_t *array) // working
{
    __uint128_t result = 0;
    for (int i = 0; i < 16; i++)
    {
        result = (result << 8) | array[i];
    }

    return result;
}

void uint128_to_charArray(__uint128_t value, uint8_t *array) // working
{
    for (int i = 15; i >= 0; i--)
    {
        array[i] = (uint8_t)(value & 0xFF);
        value >>= 8;
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

void roundFunction(__uint128_t *S, __uint128_t X_0, __uint128_t X_1)
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

void initialize(__uint128_t *S, __uint128_t K[2], __uint128_t N)
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
        roundFunction(S, Z0, Z1);
    }
    S[0] = S[0] ^ K[0];
    S[1] = S[1] ^ K[0];
    S[2] = S[2] ^ K[1];
    S[3] = S[3] ^ K[0];
    S[4] = S[4] ^ K[0];
    S[5] = S[5] ^ K[1];
    S[6] = S[6] ^ K[1];
}

void proccessAD(__uint128_t *S, __uint128_t *AD, __uint128_t Size_AD)
{
    for (int i = 0; i < Size_AD; i = i + 2)
    {
        roundFunction(S, AD[i], AD[i + 1]);
    }
}

void Rocca_S_encrypt(__uint128_t *S, __uint128_t *M, __uint128_t *C, __uint128_t Size_M)
{
    for (int i = 0; i < Size_M; i = i + 2)
    {
        C[i] = AES(S[3] ^ S[5], S[0]) ^ M[i];
        C[i + 1] = AES(S[4] ^ S[6], S[2]) ^ M[i + 1];
        roundFunction(S, M[i], M[i + 1]);
    }
}

void finalize(__uint128_t *S, __uint128_t lenAD, __uint128_t lenM, __uint128_t *T)
{
    for (int i = 0; i < 16; i++)
    {
        roundFunction(S, LE128(lenAD), LE128(lenM));
    }

    T[0] = (((S[0] ^ S[1]) ^ S[2]) ^ S[3]);
    T[1] = ((S[4] ^ S[5]) ^ S[6]);
}

void Rocca_S_hw(hls::stream<axis_data> &input, hls::stream<axis_data> &output)
{
#pragma HLS INTERFACE axis register both port = output
#pragma HLS INTERFACE axis register both port = intput
#pragma HLS INTERFACE ap_ctrl_none port = return

    int N_len;
    __uint128_t M_len, AD_len;

    __uint128_t Size_AD; // array size
    __uint128_t Size_M;  // array size

    __uint128_t S[7]; // state array

    __uint128_t K[2];
    __uint128_t N;      // 12 octets to 16 octets(since its always padded to 128 bits before use stored it as 128bit value)
    __uint128_t AD[64]; // max length = 2^62 octets = 2^61 * 8 bits = 2^57 elements.
    __uint128_t M[256]; // max length = 2^125 octets = 2^125 * 8 bits = 2^121 elements.

    __uint128_t C[256];
    __uint128_t T[2];

    axis_data local_stream;

    local_stream = input.read();
    N_len = local_stream.data;

    uint8_t temp = 0;

    // get AD length
    for (int i = 0; i < 128 / 8; i++)
    {
        local_stream = input.read();
        temp = local_stream.data;
        AD_len = (AD_len << 8) | temp;
    }

    // get message length
    for (int i = 0; i < 128 / 8; i++)
    {
        local_stream = input.read();
        temp = local_stream.data;
        M_len = (M_len << 8) | temp;
    }

    // get key
    for (int i = 0; i < 256 / 8; i++)
    {
        if (i < 256 / 4)
        {
            local_stream = input.read();
            temp = local_stream.data;
            K[0] = (K[0] << 8) | temp;
        }
        else
        {
            local_stream = input.read();
            temp = local_stream.data;
            K[0] = (K[0] << 8) | temp;
        }
    }

    // get nonce
    for (int i = 0; i < 128 / 8; i++)
    {
        if (i < N_len / 8)
        {
            local_stream = input.read();
            temp = local_stream.data;
            N = (N << 8) | temp;
        }

        else
        {
            N = (N << 8);
        }
    }

    // get associated data
    Size_AD = AD_len + (256 - AD_len % 256) % 256;

    for (__uint128_t i = 0; i < Size_AD / 8; i++)
    {
        if (i < AD_len / 8)
        {
            local_stream = input.read();
            temp = local_stream.data;
            AD[i / 16] = (AD[i / 16] << 8) | temp;
        }
        else
        {
            AD[i / 16] = (AD << 8)
        }
    }
    Size_AD = Size_AD / 128;

    // get plaintext
    Size_M = M_len + (256 - M_len % 256) % 256;
    for (__uint128_t i = 0; i < Size_M / 8; i++)
    {
        if (i < M_len / 8)
        {
            local_stream = input.read();
            temp = local_stream.data;
            M[i / 16] = (M[i / 16] << 8) | temp;
        }
        else
        {
            M[i / 16] = (M[i / 16] << 8);
        }
    }
    Size_M = Size_M / 128;

    initialize(&S, K, N);

    proccessAD(&S, &AD, Size_AD);

    Rocca_S_encrypt(&S, &M, &C, Size_M);

    finalize(&S, lenAD, lenM, &T);

    for (int i = 0; i < M_len / 8; i++)
    {

        uint8_t val = (M[i / 16] >> (120 - (i % 16) * 8) & 0xFF);
        local_stream.data = val;
        if (i == M_len / 8 - 1)
        {
            local_stream.last = 1;
        }
        else
        {
            local_stream.last = 0;
        }
        output.write(local_stream);
    }

    for (int i = 0; i < 256 / 8; i++)
    {

        uint8_t val = (T[i / 16] >> (120 - (i % 16) * 8) & 0xFF);
        local_stream.data = val;
        if (i == 256 / 8 - 1)
        {
            local_stream.last = 1;
        }
        else
        {
            local_stream.last = 0;
        }
        output.write(local_stream);
    }
    return;
}