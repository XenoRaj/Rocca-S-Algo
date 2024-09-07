#include <iostream>
#include <string>
#include <cstdint>
#include <string.h>
using namespace std;

__uint128_t S[7]; // state array
__uint128_t N; // 12 octets to 16 octets(since its always padded to 128 bits before use stored it as 128bit value)
__uint128_t Z0 = 0x428a2f98d728ae227137449123ef65cd;
__uint128_t Z1 = 0xb5c0fbcfec4d3b2fe9b5dba58189dbbc;
__uint128_t K[2];

__uint128_t AD[64]; //max length = 2^62 octets = 2^61 * 8 bits
__uint128_t Size_AD;
__uint128_t M[256]; //max length = 2^125 octets = 2^125 * 8 bits
__uint128_t Size_M;
__uint128_t C[256]; 
__uint128_t T[2];

 

// to pad a hex string to size mod(256)=0
int PAD(const char *inp, uint8_t *byteArray)
{
    int len = strlen(inp);
    if (len % 2 != 0)
    {
        printf("Invalid hex string length!\n");
        return 0;
    }
    int rem = (64 - len % 64) % rem; // using 64 instead of 256 as hex values are used
    int i = 0;
    for (; i < len / 2; i++)
    {
        // Convert each pair of hex digits into a single byte
        sscanf(inp + 2 * i, "%2hhx", &byteArray[i]);
    }

    for (; i < rem / 2; i++)
    {
        sscanf("00", "%2hhx", &byteArray[i]);
    }
    return len + rem;
}

void hexStringToByteArray(const char *hexString, uint8_t *byteArray)
{
    size_t len = strlen(hexString);

    if (len % 2 != 0)
    {
        printf("Invalid hex string length!\n");
        return;
    }

    for (size_t i = 0; i < len; i++)
    {
        // Convert each pair of hex digits into a single byte
        sscanf(hexString + 2 * i, "%2hhx", &byteArray[i]);
    }
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
    S[1] = PADN(N),
    S[2] = Z0,
    S[3] = K[0],
    S[4] = Z1,
    S[5] = PADN(N) ^ K[1],
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
    for (int i = 0; i < sizeof(M); i=i+2)
    {
        C[i] = AES(S[3] ^ S[5], S[0]) ^ M[i];
        C[i] = AES(S[4] ^ S[6], S[2]) ^ M[i+1];
        roundFunction(M[i], M[i + 1]);
    }
}

__uint128_t LE128(__uint128_t num){
    __uint128_t out = 0;
    for (int i = 0; i < 16; i++){
        out = out << 8;
        out = out | (num & 0xFF);
        num = num >> 8;
    }
    return out;
}

void finalize(){
    for (int i = 0; i < 16; i++){
        roundFunction(LE128(Size_AD), LE128(Size_M));
    }

    T[0] = (S[0] ^ S[1] ^ S[2] ^ S[3]);
    T[1] = (S[4] ^ S[5] ^ S[6]);
}


int main()
{
    initialize();

    printf("%llx\n", (unsigned long long)S[6]);

    PAD(AD); // need to implement
    proccessAD(AD);

    PAD(M);
    Rocca_S_encrypt(M);

    finalize();

}