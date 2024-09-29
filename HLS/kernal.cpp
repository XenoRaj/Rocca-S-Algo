
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

void finalize()
{
    for (int i = 0; i < 16; i++)
    {
        roundFunction(LE128(lenAD), LE128(lenM));
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
        if(i < 256/4){
            local_stream = input.read();
            temp = local_stream.data;
            K[0] = (K[0] << 8) | temp;
        }
        else{
            local_stream = input.read();
            temp = local_stream.data;
            K[0] = (K[0] << 8) | temp;
        }
    }

    // get nonce
    for (int i = 0; i < 128 / 8; i++)
    {
        if(i < N_len/8 ){
            local_stream = input.read();
            temp = local_stream.data;
            N = (N << 8) | temp;
        }
        
        else{
            N = (N << 8);
        }
    }

    // get associated data
    Size_AD = AD_len + (256-AD_len%256)%256;

    for (__uint128_t i = 0; i < Size_AD / 8; i++)
    {
        if(i < AD_len/8){
            local_stream = input.read();
            temp = local_stream.data;
            AD[i/16] = (AD[i/16]<<8) | temp;
        }
        else{
            AD[i/16] = (AD<<8)
        }
    }
    Size_AD = Size_AD/128;

    // get plaintext
    Size_M = M_len + (256-M_len%256)%256;
    for (__uint128_t i = 0; i < Size_M / 8; i++)
    {
        if(i < M_len/8){
            local_stream = input.read();
            temp = local_stream.data;
            M[i/16] = (M[i/16]<<8) | temp;
        }
        else{
            M[i/16] = (M[i/16]<<8);   
        }
    }
    Size_M = Size_M/128;
 
    initialize();

    proccessAD(AD);

    Rocca_S_encrypt(M);

    finalize();


    for (int i = 0; i < M_len / 8;i++)
    {
        
        uint8_t val = (M[i/16]>>(120-(i%16)*8) & 0xFF);
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
        
        uint8_t val = (T[i/16]>>(120-(i%16)*8) & 0xFF);
        local_stream.data = val;
        if (i == 256/ 8 - 1)
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