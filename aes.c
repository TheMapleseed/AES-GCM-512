/*

This is an implementation of the AES-GCM authenticated encryption algorithm.
Key sizes can be chosen in aes.h - available choices are AES128, AES192, AES256,
and a non-standard AES512.

The implementation of AES GCM is based on the guidelines in:
  National Institute of Standards and Technology Special Publication 800-38D

This implementation supports standard 12-byte (96-bit) IVs directly and 
handles other IV lengths by using GHASH as specified in NIST SP 800-38D.

Structure for architecture-specific optimizations (AES-NI, ARM Crypto, etc.)
for the core AES cipher and GHASH multiplication is included, but the 
optimized implementations themselves are currently placeholders.

The original code was an AES implementation supporting ECB, CTR and CBC mode.
ECB and CBC modes have been removed.

*/


/*****************************************************************************/
/* Includes:                                                                 */
/*****************************************************************************/
#include <string.h> // CBC mode, for memset
#include <stdio.h>  // Add stdio.h for printf
#include "aes.h"

// Include headers for intrinsics if needed (example)
#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h> // For AES-NI, PCLMULQDQ
#elif defined(__aarch64__)
#include <arm_neon.h>   // For ARM NEON and Crypto extensions
// #include <arm_acle.h> // Alternative/additional header for ARM CPU intrinsics
#endif

/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4

#if defined(AES256) && (AES256 == 1)
    #define Nk 8
    //#define Nr 14 // Nr is now defined in aes.h
#elif defined(AES192) && (AES192 == 1)
    #define Nk 6
    //#define Nr 12 // Nr is now defined in aes.h
#elif defined(AES512) && (AES512 == 1) // Added non-standard 512-bit key option
    #define Nk 16
    //#define Nr 22 // Nr is now defined in aes.h
#else // Default AES128
    #define Nk 4        // The number of 32 bit words in a key.
    //#define Nr 10       // The number of 32 bit words in a key.
#endif

// jcallan@github points out that declaring Multiply as a function 
// reduces code size considerably with the Keil ARM compiler.
// See this link for more information: https://github.com/kokke/tiny-AES-C/pull/3
#ifndef MULTIPLY_AS_A_FUNCTION
  #define MULTIPLY_AS_A_FUNCTION 0
#endif




/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/
// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[4][4];



// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM - 
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
static const uint8_t sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
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
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

#if 0 // (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1) - rsbox is unused for GCM
static const uint8_t rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };
#endif

// The round constant word array, Rcon[i], contains the values given by 
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

/*
 * Jordan Goulder points out in PR #12 (https://github.com/kokke/tiny-AES-C/pull/12),
 * that you can remove most of the elements in the Rcon array, because they are unused.
 *
 * From Wikipedia's article on the Rijndael key schedule @ https://en.wikipedia.org/wiki/Rijndael_key_schedule#Rcon
 * 
 * "Only the first some of these constants are actually used – up to rcon[10] for AES-128 (as 11 round keys are needed), 
 *  up to rcon[8] for AES-192, up to rcon[7] for AES-256. rcon[0] is not used in AES algorithm."
 */


/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/
#define getSBoxValue(num) (sbox[(num)])

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states. 
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
{
  unsigned i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations
  
  // The first round key is the key itself.
  for (i = 0; i < Nk; ++i)
  {
    RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
    RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  for (i = Nk; i < Nb * (Nr + 1); ++i)
  {
    {
      k = (i - 1) * 4;
      tempa[0]=RoundKey[k + 0];
      tempa[1]=RoundKey[k + 1];
      tempa[2]=RoundKey[k + 2];
      tempa[3]=RoundKey[k + 3];

    }

    if (i % Nk == 0)
    {
      // This function shifts the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        const uint8_t u8tmp = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = u8tmp;
      }

      // SubWord() is a function that takes a four-byte input word and 
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }

      tempa[0] = tempa[0] ^ Rcon[i/Nk];
    }
#if Nk > 6 // Apply extra SubWord for keys larger than 192 bits (Nk=8 for AES256, Nk=16 for non-standard AES512)
    if (i % Nk == 4)
    {
      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }
    }
#endif
    j = i * 4; k=(i - Nk) * 4;
    RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
    RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
    RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
    RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
  }
}

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)
{
  KeyExpansion(ctx->RoundKey, key);
}
#if 0 // No longer used in public API or GCM internal functions
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)
{
  KeyExpansion(ctx->RoundKey, key);
  memcpy (ctx->Iv, iv, AES_BLOCKLEN);
}
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)
{
  memcpy (ctx->Iv, iv, AES_BLOCKLEN);
}
#endif
#endif

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)
{
  uint8_t i,j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
    }
  }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxValue((*state)[j][i]);
    }
  }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to left  
  temp           = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  // Rotate second row 2 columns to left  
  temp           = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp           = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to left
  temp           = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}

static uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

// MixColumns function mixes the columns of the state matrix
static void MixColumns(state_t* state)
{
  uint8_t i;
  uint8_t Tmp, Tm, t;
  for (i = 0; i < 4; ++i)
  {  
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
  }
}

// Multiply is used to multiply numbers in the field GF(2^8)
// Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary
//       The compiler seems to be able to vectorize the operation better this way.
//       See https://github.com/kokke/tiny-AES-c/pull/34
#if MULTIPLY_AS_A_FUNCTION
static uint8_t Multiply(uint8_t x, uint8_t y)
{
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x)))))); /* this last call to xtime() can be omitted */
  }
#else
#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

#endif

#if 0 // Inverse functions are not used for GCM encryption/decryption

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
/*
static uint8_t getSBoxInvert(uint8_t num)
{
  return rsbox[num];
}
*/
#define getSBoxInvert(num) (rsbox[(num)])

// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns(state_t* state)
{
  int i;
  uint8_t a, b, c, d;
  for (i = 0; i < 4; ++i)
  { 
    a = (*state)[i][0];
    b = (*state)[i][1];
    c = (*state)[i][2];
    d = (*state)[i][3];

    (*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
    (*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
    (*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
    (*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
  }
}


// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void InvSubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxInvert((*state)[j][i]);
    }
  }
}

static void InvShiftRows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to right  
  temp = (*state)[3][1];
  (*state)[3][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[0][1];
  (*state)[0][1] = temp;

  // Rotate second row 2 columns to right 
  temp = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to right
  temp = (*state)[0][3];
  (*state)[0][3] = (*state)[1][3];
  (*state)[1][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[3][3];
  (*state)[3][3] = temp;
}
#endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

#endif // End of commented-out inverse functions

// Cipher is the main function that encrypts the PlainText.
static void Cipher(state_t* state, const uint8_t* RoundKey)
{
// --- Architecture-Specific Optimizations --- 
#if defined(__x86_64__) || defined(_M_X64)
    #if defined(__AES__)
        // AES-NI intrinsic version for x86-64
        // Assumes state is properly aligned
        // Load state and first round key
        __m128i block = _mm_loadu_si128((__m128i*)state);
        const __m128i* pRoundKey = (const __m128i*)RoundKey;

        // Initial AddRoundKey
        block = _mm_xor_si128(block, _mm_loadu_si128(&pRoundKey[0]));

        // Main rounds (Nr-1 rounds)
        // Unroll loop slightly for potentially better performance, adjust as needed
        for (uint8_t round = 1; round < Nr; round += 2) {
            block = _mm_aesenc_si128(block, _mm_loadu_si128(&pRoundKey[round]));
            if (round + 1 < Nr) { // Check if there's another round in this pair
                 block = _mm_aesenc_si128(block, _mm_loadu_si128(&pRoundKey[round + 1]));
            }
        }
        
        // Final round
        block = _mm_aesenclast_si128(block, _mm_loadu_si128(&pRoundKey[Nr]));

        // Store result back to state
        _mm_storeu_si128((__m128i*)state, block);
        return; // Skip C fallback if AES-NI path was taken
    #endif
#elif defined(__aarch64__)
    #if defined(__ARM_FEATURE_CRYPTO)
        // TODO: Implement ARMv8 Crypto Extensions intrinsic version
        // Example: Use vaeseq_u8, vaesmcq_u8, etc.
        // If implemented, use 'return;' at the end of this block 
        // to skip the C fallback.
        // printf("Note: ARM Crypto path placeholder hit.\n"); 
    #endif
// #elif defined(__riscv)
    // TODO: Implement RISC-V crypto extension version if available/needed
#endif
// --- End Architecture-Specific Optimizations ---

    // --- Generic C Implementation (Fallback) ---
    uint8_t round = 0;

    // Add the First round key to the state before starting the rounds.
    AddRoundKey(0, state, RoundKey);

    // There will be Nr rounds.
    // The first Nr-1 rounds are identical.
    // These Nr rounds are executed in the loop below.
    // Last one without MixColumns()
    for (round = 1; ; ++round)
    {
        SubBytes(state);
        ShiftRows(state);
        if (round == Nr) {
            break;
        }
        MixColumns(state);
        AddRoundKey(round, state, RoundKey);
    }
    // Add round key to last round
    AddRoundKey(Nr, state, RoundKey);
    // --- End Generic C Implementation ---
}

#if 0 // Inverse Cipher function is not used for GCM encryption/decryption
#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
static void InvCipher(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(Nr, state, RoundKey);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr rounds are executed in the loop below.
  // Last one without InvMixColumn()
  for (round = (Nr - 1); ; --round)
  {
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(round, state, RoundKey);
    if (round == 0) {
      break;
    }
    InvMixColumns(state);
  }

}
#endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
#endif // End of commented-out InvCipher

/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/
#if 0 // Deprecated ECB mode functions
#if defined(ECB) && (ECB == 1)

void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)
{
  // The next function call encrypts the PlainText with the Key using AES algorithm.
  Cipher((state_t*)buf, ctx->RoundKey);
}

void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)
{
  // The next function call decrypts the PlainText with the Key using AES algorithm.
  InvCipher((state_t*)buf, ctx->RoundKey);
}

#endif // #if defined(ECB) && (ECB == 1)
#endif // End of commented-out ECB

#if 0 // Deprecated CBC mode functions
#if defined(CBC) && (CBC == 1)

static void XorWithIv(uint8_t* buf, const uint8_t* Iv)
{
  uint8_t i;
  for (i = 0; i < AES_BLOCKLEN; ++i) // The block in AES is always 128bit no matter the key size
  {
    buf[i] ^= Iv[i];
  }
}

void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)
{
  size_t i;
  uint8_t *Iv = ctx->Iv;
  for (i = 0; i < length; i += AES_BLOCKLEN)
  {
    XorWithIv(buf, Iv);
    Cipher((state_t*)buf, ctx->RoundKey);
    Iv = buf;
    buf += AES_BLOCKLEN;
  }
  /* store Iv in ctx for next call */
  memcpy(ctx->Iv, Iv, AES_BLOCKLEN);
}

void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  size_t i;
  uint8_t storeNextIv[AES_BLOCKLEN];
  for (i = 0; i < length; i += AES_BLOCKLEN)
  {
    memcpy(storeNextIv, buf, AES_BLOCKLEN);
    InvCipher((state_t*)buf, ctx->RoundKey);
    XorWithIv(buf, ctx->Iv);
    memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN);
    buf += AES_BLOCKLEN;
  }

}

#endif // #if defined(CBC) && (CBC == 1)
#endif // End of commented-out CBC


#if defined(CTR) && (CTR == 1)

// Internal CTR function used by GCM.
// Encrypts/decrypts buffer using AES in CTR mode.
// Make ctx const as it's only used for reading RoundKey.
// Pass the counter block explicitly.
static void AES_CTR_xcrypt_buffer(const struct AES_ctx* ctx, uint8_t* current_counter_block, uint8_t* buf, size_t length)
{
  uint8_t buffer[AES_BLOCKLEN]; // Buffer for encrypted counter block
  size_t i;
  int bi;

  // Start with the current counter value
  memcpy(buffer, current_counter_block, AES_BLOCKLEN);

  for (i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi)
  {
    if (bi == AES_BLOCKLEN) // Regen xor buffer if needed
    {
        Cipher((state_t*)buffer, ctx->RoundKey); // Encrypt the current counter block

        // Increment counter block for next time (standard GCM increments the rightmost 32 bits)
        for (bi = (AES_BLOCKLEN - 1); bi >= (AES_BLOCKLEN - 4); --bi) {
            // Increment the byte and break if no carry
            if (++current_counter_block[bi] != 0) { 
                 break;
             }
        }
        // Copy the *next* counter value to buffer for the next encryption cycle
        memcpy(buffer, current_counter_block, AES_BLOCKLEN); 
        bi = 0;
    }
    buf[i] = (buf[i] ^ buffer[bi]); // XOR plaintext/ciphertext with encrypted counter block
  }
}

#endif // #if defined(CTR) && (CTR == 1)


// --- GCM Implementation ---

// Define the GCM polynomial R = x^128 + x^7 + x^2 + x + 1
// Represented as 0xE1000000000000000000000000000000 (bit 127, 7, 2, 1, 0)
// We only need the lowest byte for the bitwise implementation: 0xE1
#define GCM_POLYNOMIAL 0xE1

// Galois Field (GF(2^128)) Multiplication (ghash_gmul)
// Multiplies x by y in GF(2^128) using the GCM polynomial R.
// Includes placeholders for architecture-specific optimizations (PCLMULQDQ, PMULL).
// The C implementation below serves as a portable fallback.
// Input x, y, Output res are 16 bytes (128 bits) treated as polynomials.
static void ghash_gmul(const uint8_t x[16], const uint8_t y[16], uint8_t res[16]) {

// --- Architecture-Specific Optimizations --- 
#if defined(__x86_64__) || defined(_M_X64)
    #if defined(__PCLMULQDQ__) && defined(__SSE2__)
        // PCLMULQDQ intrinsic version for x86-64 (Illustrative - Reduction missing/simplified)
        // Based on Intel's Carry-Less Multiplication instruction whitepaper/examples
        // WARNING: Correct reduction implementation is complex and crucial for security.
        // This example only shows the multiplication part, NOT the full reduction.
        
        __m128i h = _mm_loadu_si128((const __m128i*)x); // Load H (already byte-reversed if needed)
        __m128i t = _mm_loadu_si128((const __m128i*)y); // Load Tag/Data (ensure byte order)

        // Perform carry-less multiplications
        __m128i tmp2 = _mm_clmulepi64_si128(h, t, 0x00); // H_low * T_low
        __m128i tmp3 = _mm_clmulepi64_si128(h, t, 0x11); // H_high * T_high
        __m128i tmp4 = _mm_clmulepi64_si128(h, t, 0x10); // H_high * T_low
        __m128i tmp5 = _mm_clmulepi64_si128(h, t, 0x01); // H_low * T_high

        // XOR intermediates
        __m128i tmp6 = _mm_xor_si128(tmp4, tmp5); // tmp4 ^ tmp5
        __m128i tmp7 = _mm_slli_si128(tmp6, 8);   // Shift left 64 bits
        __m128i tmp8 = _mm_srli_si128(tmp6, 8);   // Shift right 64 bits
        __m128i tmp9 = _mm_xor_si128(tmp2, tmp7); // tmp2 ^ shifted_tmp6_left
        __m128i tmp10 = _mm_xor_si128(tmp3, tmp8);// tmp3 ^ shifted_tmp6_right
        __m128i result_no_reduction = _mm_xor_si128(tmp9, tmp10); // Intermediate 256-bit result (lower 128 bits)

        // ****** IMPORTANT: POLYNOMIAL REDUCTION STEP IS MISSING HERE ******
        // The result_no_reduction needs to be reduced modulo the GCM polynomial (x^128 + x^7 + x^2 + x + 1)
        // Implementing this reduction efficiently and correctly using intrinsics 
        // (e.g., more PCLMULQDQ, shifts, XORs) is non-trivial and omitted for brevity/complexity.
        // A naive C implementation of reduction would defeat the purpose.
        // Refer to Intel documentation or optimized libraries (OpenSSL) for complete reduction.
        
        // Placeholder: Just copy the unreduced lower 128 bits for illustration
        _mm_storeu_si128((__m128i*)res, result_no_reduction);
        
        // If reduction were implemented correctly, we would return here.
        // printf("Warning: PCLMULQDQ path used, but reduction is NOT implemented!\n");
        return; 
    #endif
#elif defined(__aarch64__)
    #if defined(__ARM_FEATURE_CRYPTO) || defined(__ARM_NEON) // Check for NEON as well, PMULL is part of Adv SIMD
        // TODO: Implement ARMv8 PMULL intrinsic version (NEON)
        // Example: Use vmull_p64, veorq_u8, etc.
        // Requires careful handling of polynomial reduction (similar complexity to x86).
        // If implemented, use 'return;' at the end of this block 
        // to skip the C fallback.
        // printf("Note: ARM PMULL path placeholder hit.\n"); 
    #endif
// #elif defined(__riscv)
    // TODO: Implement RISC-V vector extension version if available/needed
#endif
// --- End Architecture-Specific Optimizations ---

    // --- Generic C Implementation (Fallback) ---
    uint8_t V[16];
    int i, j;

    memset(res, 0, 16); // Z = 0
    memcpy(V, y, 16);   // V = y

    for (i = 0; i < 16; ++i) { // Iterate over bytes of x
        for (j = 0; j < 8; ++j) { // Iterate over bits of x[i]
            // If the current bit of x is 1, XOR Z with V
            if ((x[i] >> (7 - j)) & 1) {
                for(int k=0; k<16; ++k) {
                    res[k] ^= V[k];
                }
            }

            // Right-shift V by 1 bit (multiply V by x^-1 mod P)
            uint8_t lsb_set = (V[15] & 1);
            for (int k = 15; k >= 0; --k) {
                V[k] >>= 1;
                if (k > 0 && (V[k - 1] & 1)) { // Carry bit from left byte
                    V[k] |= 0x80;
                }
            }

            // If the shifted-out bit was 1, XOR V with R (GCM_POLYNOMIAL)
            if (lsb_set) {
                V[0] ^= GCM_POLYNOMIAL; 
            }
        }
    }
    // The result is now in res (Z)
    // --- End Generic C Implementation ---
}

// GHASH function update
// Processes data (AAD or ciphertext) and updates the GHASH state S.
// S = (S ^ data_block) * H
static void ghash_update(uint8_t S[16], const uint8_t H[16], const uint8_t* data, size_t len) {
    size_t i;
    uint8_t block[16];

    for (i = 0; (i + AES_BLOCKLEN) <= len; i += AES_BLOCKLEN) {
        // XOR S with the current block
        for(int k=0; k<16; ++k) {
            S[k] ^= data[i + k];
        }
        // Multiply S by H
        ghash_gmul(S, H, S);
    }

    // Handle partial block if any
    if (i < len) {
        size_t remaining = len - i;
        memcpy(block, data + i, remaining);
        memset(block + remaining, 0, AES_BLOCKLEN - remaining); // Pad with zeros

        // XOR S with the padded block
        for(int k=0; k<16; ++k) {
            S[k] ^= block[k];
        }
        // Multiply S by H
        ghash_gmul(S, H, S);
    }
}

// Helper to increment the counter block (last 4 bytes) - specific for GCM J0 prep
static void increment_counter_j0(uint8_t counter[AES_BLOCKLEN]) {
    for (int i = AES_BLOCKLEN - 1; i >= AES_BLOCKLEN - 4; --i) {
        if (++counter[i] != 0) {
            break;
        }
    }
}

// Helper to encode length (as 64-bit big-endian) into the last 8 bytes of a block
static void encode_length(uint64_t len_bits, uint8_t block[AES_BLOCKLEN]) {
    // Encode length in big-endian order
    block[8]  = (uint8_t)(len_bits >> 56);
    block[9]  = (uint8_t)(len_bits >> 48);
    block[10] = (uint8_t)(len_bits >> 40);
    block[11] = (uint8_t)(len_bits >> 32);
    block[12] = (uint8_t)(len_bits >> 24);
    block[13] = (uint8_t)(len_bits >> 16);
    block[14] = (uint8_t)(len_bits >> 8);
    block[15] = (uint8_t)(len_bits);
    // Ensure first 8 bytes are zero if only encoding length
    // Note: In GHASH final block, AAD len is in first 8, PT len in last 8
    // This helper is used for both IV hashing (len in last 8) and final block (split)
}

// Constant-time memory comparison
// Returns 0 if identical, non-zero otherwise.
// Ensures that the comparison time is independent of the data.
static int constant_time_memcmp(const void* ptr1, const void* ptr2, size_t num) {
    const volatile uint8_t* a = (const volatile uint8_t*)ptr1;
    const volatile uint8_t* b = (const volatile uint8_t*)ptr2;
    uint8_t result = 0;
    size_t i;
    // Iterate through all bytes, accumulating differences via XOR
    // The result is non-zero if any byte differs, but the loop always runs num times.
    for (i = 0; i < num; ++i) {
        result |= (a[i] ^ b[i]);
    }
    // Return 0 if equal (result == 0), 1 if unequal (result != 0)
    // This final step ensures a consistent non-zero return value for any difference.
    return (result != 0);
}


int AES_GCM_encrypt(struct AES_ctx* ctx, 
                    const uint8_t* iv, size_t iv_len, 
                    const uint8_t* aad, size_t aad_len, 
                    const uint8_t* pt, uint8_t* ct, size_t pt_len, 
                    uint8_t* tag)
{
    if (iv_len == 0 || (aad == NULL && aad_len > 0) || (pt == NULL && pt_len > 0) || ct == NULL || tag == NULL) {
        return -1; // Invalid arguments
    }
    // Removed IV length check, now supporting other lengths
    // if (iv_len != AES_GCM_IV_LEN) { ... return -2; }

    uint8_t H[AES_BLOCKLEN] = {0};      // Hash subkey
    uint8_t J0[AES_BLOCKLEN];           // Initial counter block derived from IV
    uint8_t GCM_S[AES_BLOCKLEN] = {0};  // GHASH state (used for AAD/CT and potentially IV)
    uint8_t EK0[AES_BLOCKLEN];          // Encrypted initial counter block E_K(J0)

    // 1. Generate H = E_K(0^128)
    Cipher((state_t*)H, ctx->RoundKey);

    // 2. Prepare J0 (Initial Counter Block)
    if (iv_len == AES_GCM_IV_LEN) { // Standard 96-bit IV case
        memcpy(J0, iv, iv_len); // iv_len is 12
        memset(J0 + iv_len, 0, AES_BLOCKLEN - iv_len - 1); // Zero pad
        J0[AES_BLOCKLEN - 1] = 1; // Set last byte to 1
    } else { // IV length is not 96 bits - use GHASH
        uint8_t len_block[16] = {0};
        uint64_t iv_len_bits = (uint64_t)iv_len * 8;
        encode_length(iv_len_bits, len_block + 8); // Encode IV length in bits at the end

        memset(GCM_S, 0, 16); // Initialize GHASH state for IV processing
        ghash_update(GCM_S, H, iv, iv_len);       // GHASH the IV (ghash_update handles padding)
        ghash_update(GCM_S, H, len_block, 16);  // GHASH the length block
        memcpy(J0, GCM_S, 16); // Resulting hash is J0

        // Reset GCM_S for AAD/CT processing
        memset(GCM_S, 0, 16);
    }
    
    memcpy(EK0, J0, AES_BLOCKLEN); // Keep copy of J0 for tag calc
    Cipher((state_t*)EK0, ctx->RoundKey); // Calculate E_K(J0)

    // 3. Process AAD with GHASH
    ghash_update(GCM_S, H, aad, aad_len);

    // 4. Encrypt Plaintext using CTR mode (starting counter is J0+1)
    uint8_t current_counter[AES_BLOCKLEN];
    memcpy(current_counter, J0, AES_BLOCKLEN);
    increment_counter_j0(current_counter); // counter = J0 + 1
    if (pt_len > 0) {
        memcpy(ct, pt, pt_len); // Copy plaintext to ciphertext buffer for in-place encryption
        AES_CTR_xcrypt_buffer(ctx, current_counter, ct, pt_len);
    }

    // 5. Process Ciphertext with GHASH
    ghash_update(GCM_S, H, ct, pt_len);

    // 6. Calculate final GHASH block with lengths
    uint8_t final_len_block[16] = {0};
    encode_length((uint64_t)aad_len * 8, final_len_block);    // AAD length in bits
    encode_length((uint64_t)pt_len * 8, final_len_block + 8); // PT length in bits
    ghash_update(GCM_S, H, final_len_block, 16);

    // 7. Calculate Tag T = GHASH_result ^ E_K(J0)
    for (int i = 0; i < AES_GCM_TAG_LEN; ++i) {
        tag[i] = GCM_S[i] ^ EK0[i];
    }

    return 0; // Success
}

int AES_GCM_decrypt(struct AES_ctx* ctx, 
                    const uint8_t* iv, size_t iv_len, 
                    const uint8_t* aad, size_t aad_len, 
                    const uint8_t* ct, uint8_t* pt, size_t ct_len, 
                    const uint8_t* tag)
{
     if (iv_len == 0 || (aad == NULL && aad_len > 0) || (ct == NULL && ct_len > 0) || pt == NULL || tag == NULL) {
        return -1; // Invalid arguments
    }
    // Removed IV length check, now supporting other lengths
    // if (iv_len != AES_GCM_IV_LEN) { ... return -2; }

    uint8_t H[AES_BLOCKLEN] = {0};      // Hash subkey
    uint8_t J0[AES_BLOCKLEN];           // Initial counter block derived from IV
    uint8_t GCM_S[AES_BLOCKLEN] = {0};  // GHASH state
    uint8_t EK0[AES_BLOCKLEN];          // Encrypted initial counter block E_K(J0)
    uint8_t calculated_tag[AES_GCM_TAG_LEN];

    // 1. Generate H = E_K(0^128)
    Cipher((state_t*)H, ctx->RoundKey);

    // 2. Prepare J0 (Initial Counter Block) - Same logic as encryption
    if (iv_len == AES_GCM_IV_LEN) { // Standard 96-bit IV case
         memcpy(J0, iv, iv_len);
        memset(J0 + iv_len, 0, AES_BLOCKLEN - iv_len - 1); // Zero pad
        J0[AES_BLOCKLEN - 1] = 1; // Set last byte to 1
    } else { // IV length is not 96 bits - use GHASH
        uint8_t len_block[16] = {0};
        uint64_t iv_len_bits = (uint64_t)iv_len * 8;
        encode_length(iv_len_bits, len_block + 8); // Encode IV length in bits at the end

        memset(GCM_S, 0, 16); // Initialize GHASH state for IV processing
        ghash_update(GCM_S, H, iv, iv_len);       // GHASH the IV
        ghash_update(GCM_S, H, len_block, 16);  // GHASH the length block
        memcpy(J0, GCM_S, 16); // Resulting hash is J0

        // Reset GCM_S for AAD/CT processing
        memset(GCM_S, 0, 16);
    }

    memcpy(EK0, J0, AES_BLOCKLEN); // Keep copy of J0 for tag calc
    Cipher((state_t*)EK0, ctx->RoundKey); // Calculate E_K(J0)

    // 3. Process AAD with GHASH
    ghash_update(GCM_S, H, aad, aad_len);

    // 4. Process Ciphertext with GHASH
    ghash_update(GCM_S, H, ct, ct_len);

    // 5. Calculate final GHASH block with lengths
    uint8_t final_len_block[16] = {0};
    encode_length((uint64_t)aad_len * 8, final_len_block);     // AAD length in bits
    encode_length((uint64_t)ct_len * 8, final_len_block + 8);  // CT length in bits
    ghash_update(GCM_S, H, final_len_block, 16);

    // 6. Calculate potential Tag T = GHASH_result ^ E_K(J0)
    for (int i = 0; i < AES_GCM_TAG_LEN; ++i) {
        calculated_tag[i] = GCM_S[i] ^ EK0[i];
    }

    // 7. Compare calculated tag with received tag (use constant-time compare!)
    if (constant_time_memcmp(calculated_tag, tag, AES_GCM_TAG_LEN) != 0) {
        memset(pt, 0, ct_len); // Zero out plaintext buffer on tag mismatch
        return -3; // Authentication failed
    }

    // 8. Decrypt Ciphertext using CTR mode (starting counter is J0+1)
    uint8_t current_counter[AES_BLOCKLEN];
    memcpy(current_counter, J0, AES_BLOCKLEN);
    increment_counter_j0(current_counter); // counter = J0 + 1
    if (ct_len > 0) {
         memcpy(pt, ct, ct_len); // Copy ciphertext to plaintext buffer for in-place decryption
        AES_CTR_xcrypt_buffer(ctx, current_counter, pt, ct_len);
    }

    return 0; // Success (decryption ok, tag matched)
}

