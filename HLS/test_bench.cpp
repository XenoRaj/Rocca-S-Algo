#include "Rocca_S.h"

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

uint8_t hex_to_uint8(string str)
{
    uint8_t value = static_cast<uint8_t>(std::stoi(str, nullptr, 16));
    return value;
}

string uint8_to_hex(uint8_t value)
{
    stringstream ss;
    ss << hex << setw(2) << setfill('0') << static_cast<int>(value);

    string hexStr = ss.str();
    return hexStr;
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

        pair<string, string> output;

        output = Rocca_S_sw(K_string, N_string, AD_string, M_string);

        string sw_cipher_output = output.first;
        string sw_tag_output = output.second;

        hls::stream<axis_data> input;
        hls::stream<axis_data> output;
        axis_data local_stream;

        int N_len = N_string.length() * 4;
        __uint128_t M_len = M_string.length() * 4;
        __uint128_t AD_len = AD_string.length() * 4;

        local_stream.data = N_len;
        local_stream.last = 1;
        input.write(local_stream);

        uint8_t temp = 0;

        // set AD length
        for (int i = 0; i < 128 / 8; i++)
        {
            temp = (uint8_t)(AD_len >> (120 - i * 8) & 0xFF);
            local_stream.data = temp;
            if (i == 128 / 8 - 1)
            {
                local_stream.last = 1;
            }
            else
            {
                local_stream.last = 0;
            }
            input.write(local_stream);
        }

        // set message length
        for (int i = 0; i < 128 / 8; i++)
        {
            temp = (uint8_t)(M_len >> (120 - i * 8) & 0xFF);
            local_stream.data = temp;
            if (i == 128 / 8 - 1)
            {
                local_stream.last = 1;
            }
            else
            {
                local_stream.last = 0;
            }
            input.write(local_stream);
        }

        // set key
        for (int i = 0; i < 256 / 4; i += 2)
        {
            string k = K_string.substr(i * 2, 2);
            temp = hex_to_uint8(k);
            local_stream.data = temp;
            if (i == 256 / 4 - 2)
            {
                local_stream.last = 1;
            }
            else
            {
                local_stream.last = 0;
            }
            input.write(local_stream);
        }

        // set nonce
        for (int i = 0; i < N_len / 4; i += 2)
        {
            string n = N_string.substr(i * 2, 2);
            temp = hex_to_uint8(n);
            local_stream.data = temp;
            if (i == N_len / 4 - 2)
            {
                local_stream.last = 1;
            }
            else
            {
                local_stream.last = 0;
            }
            input.write(local_stream);
        }

        // set associated data
        for (__uint128_t i = 0; i < AD_len / 4; i += 2)
        {
            string ad = AD_string.substr(i * 2, 2);
            temp = hex_to_uint8(ad);
            local_stream.data = temp;
            if (i == AD_len / 4 - 2)
            {
                local_stream.last = 1;
            }
            else
            {
                local_stream.last = 0;
            }
            input.write(local_stream);
        }

        // get plaintext
        for (__uint128_t i = 0; i < M_len / 4; i += 2)
        {
            string ad = AD_string.substr(i * 2, 2);
            temp = hex_to_uint8(ad);
            local_stream.data = temp;
            if (i == AD_len / 4 - 2)
            {
                local_stream.last = 1;
            }
            else
            {
                local_stream.last = 0;
            }
            input.write(local_stream);
        }

        Rocca_S_hw(&input, &output);

        string hw_cipher_output = "";
        string hw_tag_output = "";

        for (__uint128_t i = 0; i < M_len / 8; i++)
        {
            local_stream = output.read();
            temp = local_stream.data;
            string hexval = uint8_to_hex(temp);
            hw_cipher_output += hexval;
        }

        for (int i = 0; i < 256 / 8; i++)
        {
            local_stream = input.read();
            temp = local_stream.data;
            string hexval = uint8_to_hex(temp);
            hw_tag_output += hexval;
        }

        if (sw_cipher_output != C_string)
        {
            cout << "ERROR: Software Cipher text doesn't match in test_vector " << i << endl;
            return 1;
        }
        if (hw_cipher_output != C_string)
        {
            cout << "ERROR: Hardware Cipher text doesn't match in test_vector " << i << endl;
            return 1;
        }
        if (sw_tag_output != T_string)
        {
            cout << "ERROR: Software Tag doesn't match in test_vector " << i << endl;
            return 1;
        }
        if (hw_tag_output != T_string)
        {
            cout << "ERROR: Hardware Tag doesn't match in test_vector " << i << endl;
            return 1;
        }
    }
    cout << "****************************************\n\n";
    cout << "All tests passed successfully\n\n";
    cout << "****************************************";
}