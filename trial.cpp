#include <emmintrin.h> // For SSE2 intrinsics
#include <stdio.h>
#include <cstdint>
int main()
{
    // Define an array of 16 bytes (128 bits)
    uint8_t data[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

    // Load the data into an __m128i variable
    __m128i value = _mm_loadu_si128((const __m128i *)data);

    // Use value in subsequent SIMD operations
    // For demonstration, we'll just print out the values
    uint8_t *loadedData = (uint8_t *)&value;
    for (int i = 0; i < 16; ++i)
    {
        printf("%02x ", loadedData[i]);
    }
    printf("\n");
    
    return 0;
}
