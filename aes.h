#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>
#include <stddef.h>

// #define the macros below to 1/0 to enable/disable the mode of operation.
//
// CTR enables encryption in counter-mode.
// All other modes (ECB, CBC) were removed to create a dedicated GCM library.

// The #ifndef-guard allows it to be configured before #include'ing or at compile time.
#ifndef CTR
  #define CTR 1 // Keep CTR as it's needed internally for GCM
#endif

// #ifndef ECB // Removed ECB
//   #define ECB 1
// #endif

// #ifndef CBC // Removed CBC
//   #define CBC 1
// #endif


#define AES128 1 // Enabled standard 128-bit
#define AES192 1 // Enabled standard 192-bit
#define AES256 1 // Enabled standard 256-bit
#define AES512 1 // Enabled non-standard 512-bit key extension

#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only

// Determine key length and round count based on defined macros
#if defined(AES512) && (AES512 == 1)
    #define AES_KEYLEN 64   // Key length in bytes (512 bits)
    #define Nr 22           // Number of rounds (Chosen based on AES pattern Nk + 6, security implications unknown)
    #define AES_keyExpSize 368 // AES_BLOCKLEN * (Nr + 1) = 16 * 23 = 368
#elif defined(AES256) && (AES256 == 1)
    #define AES_KEYLEN 32
    #define Nr 14 // Number of rounds
    #define AES_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
    #define AES_KEYLEN 24
    #define Nr 12 // Number of rounds
    #define AES_keyExpSize 208
#else // Default to AES128 if none of the specific versions (512, 256, 192) are defined AND enabled
    #ifndef AES128 // Only define AES128 if it wasn't already defined externally
      #define AES128 1 
    #endif
    #define AES_KEYLEN 16   // Key length in bytes
    #define Nr 10           // Number of rounds
    #define AES_keyExpSize 176
#endif

struct AES_ctx
{
  uint8_t RoundKey[AES_keyExpSize];
//#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1)) // Keep Iv for GCM internal state/nonce handling
  uint8_t Iv[AES_BLOCKLEN]; 
//#endif
  // Add fields specific to GCM state if needed later (e.g., precomputed H)
  // uint8_t H[AES_BLOCKLEN]; 
};

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
//#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1)) // Remove IV-specific init/set functions from public API
// void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
// void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);
//#endif

//#if defined(ECB) && (ECB == 1) // Remove ECB public functions
// void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);
// void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);
// #endif // #if defined(ECB) && (ECB == !)


//#if defined(CBC) && (CBC == 1) // Remove CBC public functions
// void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
// void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
// #endif // #if defined(CBC) && (CBC == 1)


//#if defined(CTR) && (CTR == 1) // Remove public CTR function
// void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
// #endif // #if defined(CTR) && (CTR == 1)

// --- GCM API Declarations (Placeholders) ---

// GCM constants
#define AES_GCM_TAG_LEN 16 // GCM standard tag length is 16 bytes (128 bits)
#define AES_GCM_IV_LEN  12 // Recommended IV/nonce length is 12 bytes (96 bits)

/**
 * @brief Performs AES-GCM authenticated encryption.
 *
 * @param ctx       Initialized AES context (key already set).
 * @param iv        Initialization Vector (nonce). MUST be unique for the key.
 *                  Typically AES_GCM_IV_LEN (12) bytes.
 * @param iv_len    Length of the IV in bytes.
 * @param aad       Additional Authenticated Data (can be NULL if aad_len is 0).
 * @param aad_len   Length of AAD in bytes.
 * @param pt        Plaintext input.
 * @param ct        Ciphertext output buffer (must be at least pt_len bytes).
 * @param pt_len    Length of plaintext/ciphertext in bytes.
 * @param tag       Output buffer for the authentication tag (AES_GCM_TAG_LEN bytes).
 * @return int      0 on success, non-zero on error (e.g., invalid input).
 */
int AES_GCM_encrypt(struct AES_ctx* ctx, 
                    const uint8_t* iv, size_t iv_len, 
                    const uint8_t* aad, size_t aad_len, 
                    const uint8_t* pt, uint8_t* ct, size_t pt_len, 
                    uint8_t* tag);

/**
 * @brief Performs AES-GCM authenticated decryption and verification.
 *
 * @param ctx       Initialized AES context (key already set).
 * @param iv        Initialization Vector (nonce) used during encryption.
 * @param iv_len    Length of the IV in bytes.
 * @param aad       Additional Authenticated Data (must match encryption AAD).
 * @param aad_len   Length of AAD in bytes.
 * @param ct        Ciphertext input.
 * @param pt        Plaintext output buffer (must be at least ct_len bytes).
 * @param ct_len    Length of ciphertext/plaintext in bytes.
 * @param tag       Input buffer containing the authentication tag to verify.
 * @return int      0 on success (decryption successful, tag verified),
 *                  Non-zero on error (e.g., tag mismatch, invalid input).
 */
int AES_GCM_decrypt(struct AES_ctx* ctx, 
                    const uint8_t* iv, size_t iv_len, 
                    const uint8_t* aad, size_t aad_len, 
                    const uint8_t* ct, uint8_t* pt, size_t ct_len, 
                    const uint8_t* tag);


#endif // _AES_H_
