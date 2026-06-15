#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <chrono>
#include <ctime>
#include <random>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>
#include <cuda_runtime.h>

#include "config.h"
#include "sha256.cuh"
#include "sha512.cuh"
#include "ed25519.cuh"
#include "fingerprint_match.cuh"
#include "openssh_format.h"

// Ed25519 Precomputed Tables — defined once per TU (rdc links them per-device)
__device__ ge_precomp d_base_5bit[52][16];
__device__ ge_precomp d_base_7bit[37][64];
__device__ ge_precomp d_base_8bit[32][128];

// ============================================================
// Structures
// ============================================================
struct MatchResult {
    uint8_t seed[32];
    uint8_t private_key[64];
    uint8_t public_key[32];
    uint8_t fingerprint[32];
    int     found;
};

// __constant__ symbols (per-device, set via cudaSetDevice before cudaMemcpyToSymbol)
__constant__ uint32_t d_prefix_targets[8];
__constant__ uint32_t d_prefix_masks[8];
__constant__ int      d_prefix_full_words;
__constant__ uint32_t d_prefix_partial_mask;
__constant__ uint8_t  d_base_seed[32];
__constant__ uint32_t d_suffix_targets[8];
__constant__ uint32_t d_suffix_masks[8];
__constant__ int      d_suffix_start_word;
__constant__ int      d_suffix_word_count;
__constant__ int      d_match_mode;

// Pubkey vanity params — passed as device pointer
struct PubkeyParams {
    uint8_t prefix_target[32];
    uint8_t prefix_mask[32];
    int     prefix_len;
    uint8_t suffix_target[32];
    uint8_t suffix_mask[32];
    int     suffix_start;
    int     suffix_len;
};

// ============================================================
// Kernel
// ============================================================
__global__ void __launch_bounds__(THREADS_PER_BLOCK, MIN_BLOCKS_PER_SM) search_kernel(
    MatchResult* result,
    uint64_t base_counter,
    const PubkeyParams* pubkey_params
) {
    if (result->found) return;

    uint32_t thread_id = blockIdx.x * blockDim.x + threadIdx.x;
    uint8_t  seeds[BATCH_SIZE][32];
    uint8_t  pubkeys[BATCH_SIZE][32];
    uint32_t hash[8];

    for (int iter = 0; iter < ITERATIONS_PER_THREAD; iter += BATCH_SIZE) {
        #pragma unroll
        for (int b = 0; b < BATCH_SIZE; b++) {
            uint64_t idx = base_counter + ((uint64_t)thread_id * ITERATIONS_PER_THREAD) + iter + b;
            #pragma unroll
            for (int i = 0; i < 32; i++) seeds[b][i] = d_base_seed[i];
            *((uint64_t*)&seeds[b][0]) ^= idx;
        }

        ed25519_pubkey_batch<BATCH_SIZE>(seeds, pubkeys);

        #pragma unroll
        for (int b = 0; b < BATCH_SIZE; b++) {
            bool matched = false;

            if (d_match_mode == 3) {
                bool ok = true;
                for (int i = 0; i < pubkey_params->prefix_len && ok; i++)
                    ok = ((pubkeys[b][i] & pubkey_params->prefix_mask[i]) == pubkey_params->prefix_target[i]);
                matched = ok;
            } else if (d_match_mode == 4) {
                bool ok = true;
                for (int i = 0; i < pubkey_params->suffix_len && ok; i++)
                    ok = ((pubkeys[b][pubkey_params->suffix_start + i] & pubkey_params->suffix_mask[i]) == pubkey_params->suffix_target[i]);
                matched = ok;
            } else if (d_match_mode == 5) {
                bool ok = true;
                for (int i = 0; i < pubkey_params->prefix_len && ok; i++)
                    ok = ((pubkeys[b][i] & pubkey_params->prefix_mask[i]) == pubkey_params->prefix_target[i]);
                if (ok)
                    for (int i = 0; i < pubkey_params->suffix_len && ok; i++)
                        ok = ((pubkeys[b][pubkey_params->suffix_start + i] & pubkey_params->suffix_mask[i]) == pubkey_params->suffix_target[i]);
                matched = ok;
            } else {
                sha256_ssh_fingerprint(pubkeys[b], hash);
                if (d_match_mode == 0) {
                    matched = match_prefix_32bit(hash, d_prefix_targets, d_prefix_masks,
                                                 d_prefix_full_words, d_prefix_partial_mask);
                } else if (d_match_mode == 1) {
                    matched = match_suffix_32bit(hash, d_suffix_targets, d_suffix_masks,
                                                 d_suffix_start_word, d_suffix_word_count);
                } else {
                    matched = match_prefix_32bit(hash, d_prefix_targets, d_prefix_masks,
                                                 d_prefix_full_words, d_prefix_partial_mask);
                    if (matched)
                        matched = match_suffix_32bit(hash, d_suffix_targets, d_suffix_masks,
                                                     d_suffix_start_word, d_suffix_word_count);
                }
            }

            if (matched) {
                if (atomicExch(&result->found, 1) == 0) {
                    memcpy(result->seed,        seeds[b],   32);
                    memcpy(result->public_key,  pubkeys[b], 32);
                    sha256_ssh_fingerprint(pubkeys[b], hash);
                    hash32_to_bytes(hash, result->fingerprint);
                    memcpy(result->private_key,      seeds[b],   32);
                    memcpy(result->private_key + 32, pubkeys[b], 32);
                }
                return;
            }
        }
    }
}

// ============================================================
// Host helpers
// ============================================================
static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static bool is_valid_hex(const char* s) {
    if (!s || !*s) return false;
    while (*s) { if (hex_digit(*s) < 0) return false; s++; }
    return true;
}
static bool is_valid_base64(const char* s) {
    if (!s) return true;
    while (*s) {
        char c = *s++;
        if (!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='+'||c=='/')) return false;
    }
    return true;
}

// Must be called after cudaSetDevice(gpu_id)
void setup_fp_prefix(const char* prefix) {
    uint32_t targets[8]={0}, masks[8]={0};
    int full_words, partial_bits;
    decode_prefix_pattern_32bit(prefix, targets, masks, &full_words, &partial_bits);
    uint32_t partial_mask = (partial_bits > 0) ? masks[full_words] : 0;
    cudaMemcpyToSymbol(d_prefix_targets,      targets,       32);
    cudaMemcpyToSymbol(d_prefix_masks,        masks,         32);
    cudaMemcpyToSymbol(d_prefix_full_words,   &full_words,   sizeof(int));
    cudaMemcpyToSymbol(d_prefix_partial_mask, &partial_mask, sizeof(uint32_t));
}

void setup_fp_suffix(const char* suffix) {
    uint32_t targets[8]={0}, masks[8]={0};
    int start_word, word_count;
    decode_suffix_pattern_32bit(suffix, targets, masks, &start_word, &word_count);
    cudaMemcpyToSymbol(d_suffix_targets,    targets,     32);
    cudaMemcpyToSymbol(d_suffix_masks,      masks,       32);
    cudaMemcpyToSymbol(d_suffix_start_word, &start_word, sizeof(int));
    cudaMemcpyToSymbol(d_suffix_word_count, &word_count, sizeof(int));
}

void fill_pk_prefix(PubkeyParams& p, const char* hex) {
    int hex_len = (int)strlen(hex);
    memset(p.prefix_target, 0, 32); memset(p.prefix_mask, 0, 32);
    int full_bytes = hex_len / 2, has_nibble = hex_len % 2;
    p.prefix_len = full_bytes + has_nibble;
    for (int i = 0; i < full_bytes; i++) {
        p.prefix_target[i] = (uint8_t)((hex_digit(hex[i*2])<<4)|hex_digit(hex[i*2+1]));
        p.prefix_mask[i]   = 0xFF;
    }
    if (has_nibble) {
        p.prefix_target[full_bytes] = (uint8_t)(hex_digit(hex[full_bytes*2])<<4);
        p.prefix_mask[full_bytes]   = 0xF0;
    }
}

void fill_pk_suffix(PubkeyParams& p, const char* hex) {
    int hex_len = (int)strlen(hex);
    memset(p.suffix_target, 0, 32); memset(p.suffix_mask, 0, 32);
    int full_bytes = hex_len/2, has_nibble = hex_len%2, total = full_bytes+has_nibble;
    p.suffix_start = 32 - total; p.suffix_len = total;
    if (p.suffix_start < 0) { fprintf(stderr,"Error: --pubkey-suffix too long\n"); exit(1); }
    int idx = 0;
    if (has_nibble) {
        p.suffix_target[idx]=(uint8_t)(hex_digit(hex[0])<<4); p.suffix_mask[idx]=0xF0; idx++;
        for (int i=0;i<full_bytes;i++) {
            p.suffix_target[idx]=(uint8_t)((hex_digit(hex[1+i*2])<<4)|hex_digit(hex[2+i*2]));
            p.suffix_mask[idx]=0xFF; idx++;
        }
    } else {
        for (int i=0;i<full_bytes;i++) {
            p.suffix_target[idx]=(uint8_t)((hex_digit(hex[i*2])<<4)|hex_digit(hex[i*2+1]));
            p.suffix_mask[idx]=0xFF; idx++;
        }
    }
}

const char b64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
void base64_encode(const uint8_t* data, int len, char* out) {
    int i=0,j=0;
    while (i<len) {
        uint32_t a=(uint32_t)(i<len?data[i++]:0), b=(uint32_t)(i<len?data[i++]:0), c=(uint32_t)(i<len?data[i++]:0);
        uint32_t t=(a<<16)|(b<<8)|c;
        out[j++]=b64_chars[(t>>18)&0x3F]; out[j++]=b64_chars[(t>>12)&0x3F];
        out[j++]=b64_chars[(t>>6)&0x3F];  out[j++]=b64_chars[t&0x3F];
    }
    out[(len*8+5)/6]='\0';
}

// ============================================================
// Host-side SHA512 (standard, no CUDA) — needed to convert
// raw seed → MeshCore private key format (clamped scalar)
// ============================================================
static const uint64_t SHA512_K[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

static inline uint64_t ror64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

// Standard SHA-512 of a 32-byte input → 64-byte output (host side)
void host_sha512_32(const uint8_t* in, uint8_t* out) {
    uint64_t S[8] = {
        0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL
    };
    uint64_t W[80];
    // Load 32 bytes big-endian into W[0..3]
    for (int i = 0; i < 4; i++) {
        W[i] = 0;
        for (int b = 0; b < 8; b++)
            W[i] = (W[i] << 8) | in[i*8 + b];
    }
    W[4] = 0x8000000000000000ULL; // padding bit
    for (int i = 5; i < 15; i++) W[i] = 0;
    W[15] = 256; // length in bits
    for (int i = 16; i < 80; i++) {
        uint64_t g0 = ror64(W[i-15],1)  ^ ror64(W[i-15],8)  ^ (W[i-15]>>7);
        uint64_t g1 = ror64(W[i-2], 19) ^ ror64(W[i-2], 61) ^ (W[i-2]>>6);
        W[i] = g1 + W[i-7] + g0 + W[i-16];
    }
    uint64_t a=S[0],b=S[1],c=S[2],d=S[3],e=S[4],f=S[5],g=S[6],h=S[7];
    for (int i = 0; i < 80; i++) {
        uint64_t s1  = ror64(e,14) ^ ror64(e,18) ^ ror64(e,41);
        uint64_t ch  = (e & f) ^ (~e & g);
        uint64_t t1  = h + s1 + ch + SHA512_K[i] + W[i];
        uint64_t s0  = ror64(a,28) ^ ror64(a,34) ^ ror64(a,39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t t2  = s0 + maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    S[0]+=a; S[1]+=b; S[2]+=c; S[3]+=d;
    S[4]+=e; S[5]+=f; S[6]+=g; S[7]+=h;
    for (int i = 0; i < 8; i++) {
        for (int b = 7; b >= 0; b--) {
            out[i*8 + b] = (uint8_t)(S[i] & 0xFF);
            S[i] >>= 8;
        }
    }
}

// Convert raw 32-byte seed → 64-byte MeshCore private key.
//
// MeshCore Format (RFC 8032 extended key):
//   priv[0:32]  = clamped_scalar  = SHA512(seed)[0:32] with clamping applied
//   priv[32:64] = nonce           = SHA512(seed)[32:64]
//
// This is what MeshCore firmware reads when it calls:
//   crypto_scalarmult_ed25519_base_noclamp(priv[0:32])
// to reconstruct the public key.
void seed_to_meshcore_privkey(const uint8_t* seed, uint8_t* meshcore_priv) {
    uint8_t digest[64];
    host_sha512_32(seed, digest);
    // Clamp per RFC 8032 §5.1.5
    digest[0]  &= 248; // clear bits 0,1,2
    digest[31] &= 127; // clear bit 255
    digest[31] |= 64;  // set   bit 254
    // Format: [clamped_scalar(32)] + [nonce(32)]
    memcpy(meshcore_priv,      digest,      32);
    memcpy(meshcore_priv + 32, digest + 32, 32);
}

void write_key_info(const MatchResult* r, const char* filename) {
    FILE* f=fopen(filename,"w");
    if (!f){fprintf(stderr,"Error: Cannot open %s\n",filename);return;}

    char fp_b64[45]; base64_encode(r->fingerprint,32,fp_b64);

    // Compute MeshCore private key from seed
    uint8_t meshcore_priv[64];
    seed_to_meshcore_privkey(r->seed, meshcore_priv);

    fprintf(f,"# Ed25519 Key (Generated by ed25519brute_cuda)\n");
    fprintf(f,"# Contains BOTH formats for maximum compatibility\n\n");

    // ── Raw seed (source of truth) ──────────────────────────────
    fprintf(f,"## Seed (32 bytes) — source of truth\n");
    for(int i=0;i<32;i++) fprintf(f,"%02x",r->seed[i]);
    fprintf(f,"\n\n");

    // ── Public key ──────────────────────────────────────────────
    fprintf(f,"## Public Key (32 bytes)\n");
    for(int i=0;i<32;i++) fprintf(f,"%02x",r->public_key[i]);
    fprintf(f,"\n\n");

    // ── MeshCore format ─────────────────────────────────────────
    fprintf(f,"## MeshCore Private Key (64 bytes = clamped_scalar + nonce)\n");
    fprintf(f,"## Use this with MeshCore firmware / meshcore_keygen.py\n");
    fprintf(f,"## Verify: crypto_scalarmult_ed25519_base_noclamp(priv[0:32]) == pubkey\n");
    for(int i=0;i<64;i++) fprintf(f,"%02x",meshcore_priv[i]);
    fprintf(f,"\n\n");

    // ── Breakdown of MeshCore key ───────────────────────────────
    fprintf(f,"## MeshCore Key Breakdown:\n");
    fprintf(f,"##   [0:32]  clamped_scalar = ");
    for(int i=0;i<32;i++) fprintf(f,"%02x",meshcore_priv[i]);
    fprintf(f,"\n");
    fprintf(f,"##   [32:64] nonce          = ");
    for(int i=32;i<64;i++) fprintf(f,"%02x",meshcore_priv[i]);
    fprintf(f,"\n\n");

    // ── OpenSSH / RFC8032 seed format ───────────────────────────
    fprintf(f,"## OpenSSH Private Key (64 bytes = seed + pubkey)\n");
    fprintf(f,"## Use this with standard OpenSSH / libsodium\n");
    for(int i=0;i<32;i++) fprintf(f,"%02x",r->seed[i]);
    for(int i=0;i<32;i++) fprintf(f,"%02x",r->public_key[i]);
    fprintf(f,"\n\n");

    // ── SSH fingerprint ─────────────────────────────────────────
    fprintf(f,"## SSH Fingerprint\nSHA256:%s\n",fp_b64);

    fclose(f);
    printf("Key information written to %s\n",filename);
}

bool file_exists(const char* fn) { FILE* f=fopen(fn,"r"); if(f){fclose(f);return true;} return false; }

// Generate unique filename with timestamp + serial number.
// "id_ed25519" -> "id_ed25519_20240315_143022_001" if base already exists.
// Returns base name unchanged if file does not exist yet.
void make_output_filename(const char* base, char* out, size_t out_size) {
    if (!file_exists(base)) {
        strncpy(out, base, out_size - 1);
        out[out_size - 1] = '\0';
        return;
    }
    time_t now_t = time(nullptr);
    struct tm* t = localtime(&now_t);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", t);
    for (int serial = 1; serial <= 9999; serial++) {
        snprintf(out, out_size, "%s_%s_%03d", base, ts, serial);
        if (!file_exists(out)) return;
    }
    snprintf(out, out_size, "%s_%s", base, ts); // fallback
}

void print_usage(const char* prog) {
    fprintf(stderr,"Usage: %s [options]\n\n",prog);
    fprintf(stderr,"Fingerprint search (SHA256 base64):\n");
    fprintf(stderr,"  --fingerprint-prefix <b64>   e.g. dead\n");
    fprintf(stderr,"  --fingerprint-suffix <b64>   e.g. TFs\n");
    fprintf(stderr,"\nVanity pubkey search (hex of raw 32-byte Ed25519 pubkey):\n");
    fprintf(stderr,"  --pubkey-prefix <hex>        e.g. deadbeef\n");
    fprintf(stderr,"  --pubkey-suffix <hex>        e.g. cafe\n");
    fprintf(stderr,"\n  --blocks <n>                CUDA blocks per GPU (default: %d, max: %d)\n",DEFAULT_BLOCKS,MAX_BLOCKS);
    fprintf(stderr,"  --gpu <id[,id,...]>          GPU IDs to use (default: 0)\n");
    fprintf(stderr,"                               Example: --gpu 0,1,2,3\n");
    fprintf(stderr,"\nNote: --fingerprint-* and --pubkey-* modes cannot be combined.\n");
}

// ============================================================
// Per-GPU stats (shared atomically for progress display)
// ============================================================
struct GpuStats {
    std::atomic<uint64_t> keys_checked{0};
    std::atomic<bool>     running{true};
};

// ============================================================
// Per-GPU worker thread
// ============================================================
struct GpuWorkerArgs {
    int          gpu_id;
    int          blocks;
    int          match_mode;
    // Fingerprint params (precomputed on host)
    uint32_t     fp_prefix_targets[8];
    uint32_t     fp_prefix_masks[8];
    int          fp_prefix_full_words;
    uint32_t     fp_prefix_partial_mask;
    uint32_t     fp_suffix_targets[8];
    uint32_t     fp_suffix_masks[8];
    int          fp_suffix_start_word;
    int          fp_suffix_word_count;
    // Pubkey params
    PubkeyParams pk_params;
    bool         pk_mode;
    // Random base seed (unique per GPU thread)
    uint8_t      base_seed[32];
    // Shared state
    std::atomic<bool>*    global_found;
    std::mutex*           result_mutex;
    MatchResult*          shared_result; // written by winner
    GpuStats*             stats;
};

void gpu_worker(GpuWorkerArgs* args) {
    int gpu_id = args->gpu_id;
    cudaSetDevice(gpu_id);

    // Upload precomputed Ed25519 tables to this GPU
    cudaMemcpyToSymbol(d_base_seed, args->base_seed, 32);
    cudaMemcpyToSymbol(d_base_5bit, base_5bit, sizeof(ge_precomp)*52*16);
    cudaMemcpyToSymbol(d_base_7bit, base_7bit, sizeof(ge_precomp)*37*64);
    cudaMemcpyToSymbol(d_base_8bit, base_8bit, sizeof(ge_precomp)*32*128);

    // Upload search params
    cudaMemcpyToSymbol(d_match_mode, &args->match_mode, sizeof(int));

    if (!args->pk_mode) {
        cudaMemcpyToSymbol(d_prefix_targets,      args->fp_prefix_targets, 32);
        cudaMemcpyToSymbol(d_prefix_masks,        args->fp_prefix_masks,   32);
        cudaMemcpyToSymbol(d_prefix_full_words,   &args->fp_prefix_full_words,   sizeof(int));
        cudaMemcpyToSymbol(d_prefix_partial_mask, &args->fp_prefix_partial_mask, sizeof(uint32_t));
        cudaMemcpyToSymbol(d_suffix_targets,    args->fp_suffix_targets,  32);
        cudaMemcpyToSymbol(d_suffix_masks,      args->fp_suffix_masks,    32);
        cudaMemcpyToSymbol(d_suffix_start_word, &args->fp_suffix_start_word, sizeof(int));
        cudaMemcpyToSymbol(d_suffix_word_count, &args->fp_suffix_word_count, sizeof(int));
    }

    // Upload pubkey params if needed
    PubkeyParams* d_pk = nullptr;
    if (args->pk_mode) {
        cudaMalloc(&d_pk, sizeof(PubkeyParams));
        cudaMemcpy(d_pk, &args->pk_params, sizeof(PubkeyParams), cudaMemcpyHostToDevice);
    }

    // Allocate double-buffered result structs
    cudaStream_t   streams[NUM_STREAMS];
    MatchResult*   d_results[NUM_STREAMS];
    MatchResult    h_results[NUM_STREAMS];
    for (int i = 0; i < NUM_STREAMS; i++) {
        cudaStreamCreate(&streams[i]);
        cudaMalloc(&d_results[i], sizeof(MatchResult));
        h_results[i].found = 0;
        cudaMemcpy(d_results[i], &h_results[i], sizeof(MatchResult), cudaMemcpyHostToDevice);
    }

    int blocks = args->blocks;
    const uint64_t keys_per_launch = (uint64_t)blocks * THREADS_PER_BLOCK * ITERATIONS_PER_THREAD;

    // Each GPU starts at a different counter offset to avoid duplicate work.
    // Use gpu_id * 2^48 as a large stride — effectively partitions the space.
    uint64_t batch_counter = (uint64_t)gpu_id << 48;

    // Launch first batch
    search_kernel<<<blocks, THREADS_PER_BLOCK, 0, streams[0]>>>(d_results[0], batch_counter, d_pk);
    batch_counter += keys_per_launch;

    while (!args->global_found->load(std::memory_order_relaxed)) {
        for (int s = 0; s < NUM_STREAMS; s++) {
            if (args->global_found->load(std::memory_order_relaxed)) break;

            int cur  = s;
            int next = (s + 1) % NUM_STREAMS;

            // Launch next batch
            search_kernel<<<blocks, THREADS_PER_BLOCK, 0, streams[next]>>>(d_results[next], batch_counter, d_pk);
            batch_counter += keys_per_launch;

            // Wait for current batch
            cudaStreamSynchronize(streams[cur]);

            cudaError_t err = cudaGetLastError();
            if (err != cudaSuccess) {
                fprintf(stderr, "[GPU %d] CUDA error: %s\n", gpu_id, cudaGetErrorString(err));
                args->global_found->store(true, std::memory_order_relaxed);
                break;
            }

            cudaMemcpy(&h_results[cur], d_results[cur], sizeof(MatchResult), cudaMemcpyDeviceToHost);
            args->stats->keys_checked.fetch_add(keys_per_launch, std::memory_order_relaxed);

            if (h_results[cur].found) {
                // We found it — store result and signal everyone
                {
                    std::lock_guard<std::mutex> lk(*args->result_mutex);
                    if (!args->global_found->load(std::memory_order_relaxed)) {
                        *args->shared_result = h_results[cur];
                    }
                }
                args->global_found->store(true, std::memory_order_relaxed);
                cudaStreamSynchronize(streams[next]);
                break;
            }

            // Reset for reuse
            h_results[cur].found = 0;
            cudaMemcpyAsync(d_results[cur], &h_results[cur], sizeof(MatchResult),
                            cudaMemcpyHostToDevice, streams[cur]);
        }
    }

    // Cleanup
    for (int i = 0; i < NUM_STREAMS; i++) {
        cudaStreamSynchronize(streams[i]);
        cudaFree(d_results[i]);
        cudaStreamDestroy(streams[i]);
    }
    if (d_pk) cudaFree(d_pk);
    args->stats->running.store(false, std::memory_order_relaxed);
}

// ============================================================
// Parse comma-separated GPU list: "0,1,2,3" → {0,1,2,3}
// ============================================================
std::vector<int> parse_gpu_list(const char* s) {
    std::vector<int> ids;
    if (!s) { ids.push_back(0); return ids; }
    char buf[256]; strncpy(buf, s, 255); buf[255]='\0';
    char* tok = strtok(buf, ",");
    while (tok) {
        ids.push_back(atoi(tok));
        tok = strtok(nullptr, ",");
    }
    return ids;
}

// ============================================================
// main
// ============================================================
int main(int argc, char* argv[]) {
    const char* fp_prefix = nullptr, *fp_suffix = nullptr;
    const char* pk_prefix = nullptr, *pk_suffix = nullptr;
    const char* gpu_arg   = nullptr;
    int blocks = DEFAULT_BLOCKS;

    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i],"--fingerprint-prefix")&&i+1<argc) fp_prefix=argv[++i];
        else if (!strcmp(argv[i],"--fingerprint-suffix")&&i+1<argc) fp_suffix=argv[++i];
        else if (!strcmp(argv[i],"--pubkey-prefix")     &&i+1<argc) pk_prefix=argv[++i];
        else if (!strcmp(argv[i],"--pubkey-suffix")     &&i+1<argc) pk_suffix=argv[++i];
        else if (!strcmp(argv[i],"--gpu")               &&i+1<argc) gpu_arg  =argv[++i];
        else if (!strcmp(argv[i],"--blocks")            &&i+1<argc) {
            blocks=atoi(argv[++i]);
            if (blocks<=0||blocks>MAX_BLOCKS){fprintf(stderr,"Error: blocks must be 1..%d\n",MAX_BLOCKS);return 1;}
        } else if (!strcmp(argv[i],"--help")||!strcmp(argv[i],"-h")) { print_usage(argv[0]);return 0; }
    }

    if (!fp_prefix&&!fp_suffix&&!pk_prefix&&!pk_suffix){print_usage(argv[0]);return 1;}

    bool fp_mode=(fp_prefix||fp_suffix), pk_mode=(pk_prefix||pk_suffix);
    if (fp_mode&&pk_mode){fprintf(stderr,"Error: Cannot mix --fingerprint-* and --pubkey-*\n");return 1;}

    // Validate
    if (fp_prefix&&!is_valid_base64(fp_prefix)){fprintf(stderr,"Error: --fingerprint-prefix: bad base64\n");return 1;}
    if (fp_suffix){
        if (!is_valid_base64(fp_suffix)){fprintf(stderr,"Error: --fingerprint-suffix: bad base64\n");return 1;}
        int sl=(int)strlen(fp_suffix);
        if (sl>0&&!strchr("AEIMQUYcgkosw048",fp_suffix[sl-1])){
            fprintf(stderr,"Error: fingerprint suffix last char must be one of \"AEIMQUYcgkosw048\"\n");return 1;}
    }
    if (pk_prefix){
        if (!is_valid_hex(pk_prefix)){fprintf(stderr,"Error: --pubkey-prefix: bad hex\n");return 1;}
        if (strlen(pk_prefix)>64){fprintf(stderr,"Error: --pubkey-prefix: too long\n");return 1;}
    }
    if (pk_suffix){
        if (!is_valid_hex(pk_suffix)){fprintf(stderr,"Error: --pubkey-suffix: bad hex\n");return 1;}
        if (strlen(pk_suffix)>64){fprintf(stderr,"Error: --pubkey-suffix: too long\n");return 1;}
    }

    // Parse GPU list and validate
    std::vector<int> gpu_ids = parse_gpu_list(gpu_arg);
    int total_gpus = 0;
    cudaGetDeviceCount(&total_gpus);
    for (int id : gpu_ids) {
        if (id < 0 || id >= total_gpus) {
            fprintf(stderr,"Error: GPU %d does not exist (available: 0..%d)\n", id, total_gpus-1);
            return 1;
        }
    }

    // Output files are named with timestamp+serial — no overwrite, no prompt.

    printf("Ed25519 SSH Key CUDA Brute Force\n");
    printf("=================================\n");

    // Prepare shared search parameters
    int match_mode;
    GpuWorkerArgs proto; // prototype args, copied per GPU
    memset(&proto, 0, sizeof(proto));
    proto.pk_mode = pk_mode;

    if (pk_mode) {
        if (pk_prefix){printf("Pubkey prefix (hex): %s\n",pk_prefix); fill_pk_prefix(proto.pk_params,pk_prefix);}
        if (pk_suffix){printf("Pubkey suffix (hex): %s\n",pk_suffix); fill_pk_suffix(proto.pk_params,pk_suffix);}
        printf("(Matching raw 32-byte Ed25519 public key)\n");
        match_mode=(pk_prefix&&pk_suffix)?5:(pk_prefix?3:4);
    } else {
        if (fp_prefix){
            printf("Fingerprint prefix: %s\n",fp_prefix);
            uint32_t targets[8]={0},masks[8]={0};
            int fw,pb;
            decode_prefix_pattern_32bit(fp_prefix,targets,masks,&fw,&pb);
            memcpy(proto.fp_prefix_targets,targets,32);
            memcpy(proto.fp_prefix_masks,  masks,  32);
            proto.fp_prefix_full_words   = fw;
            proto.fp_prefix_partial_mask = (pb>0)?masks[fw]:0;
        }
        if (fp_suffix){
            printf("Fingerprint suffix: %s\n",fp_suffix);
            uint32_t targets[8]={0},masks[8]={0};
            decode_suffix_pattern_32bit(fp_suffix,targets,masks,&proto.fp_suffix_start_word,&proto.fp_suffix_word_count);
            memcpy(proto.fp_suffix_targets,targets,32);
            memcpy(proto.fp_suffix_masks,  masks,  32);
        }
        match_mode=(fp_prefix&&fp_suffix)?2:(fp_prefix?0:1);
    }
    proto.match_mode = match_mode;
    proto.blocks     = blocks;

    // Print GPU info
    printf("GPUs: ");
    for (int i = 0; i < (int)gpu_ids.size(); i++) {
        cudaDeviceProp prop; cudaGetDeviceProperties(&prop, gpu_ids[i]);
        printf("[%d] %s (SM %d.%d)%s", gpu_ids[i], prop.name, prop.major, prop.minor,
               i+1<(int)gpu_ids.size()?" | ":"\n");
    }
    printf("Blocks per GPU: %d  |  Threads per block: %d\n", blocks, THREADS_PER_BLOCK);
    printf("Starting search...\n\n");

    // Shared state
    std::atomic<bool> global_found(false);
    std::mutex        result_mutex;
    MatchResult       shared_result; shared_result.found = 0;

    int num_gpus = (int)gpu_ids.size();
    std::vector<GpuStats>       stats(num_gpus);
    std::vector<GpuWorkerArgs>  worker_args(num_gpus);
    std::vector<std::thread>    threads;

    // Generate unique random seed per GPU
    std::random_device rd;
    std::uniform_int_distribution<unsigned short> dist(0,255);

    for (int g = 0; g < num_gpus; g++) {
        worker_args[g]          = proto;
        worker_args[g].gpu_id   = gpu_ids[g];
        worker_args[g].global_found  = &global_found;
        worker_args[g].result_mutex  = &result_mutex;
        worker_args[g].shared_result = &shared_result;
        worker_args[g].stats         = &stats[g];
        // Each GPU gets a unique random base seed → no duplicate work
        for (int i = 0; i < 32; i++) worker_args[g].base_seed[i] = (uint8_t)dist(rd);
    }

    auto start_time = std::chrono::high_resolution_clock::now();

    // Launch GPU threads
    for (int g = 0; g < num_gpus; g++)
        threads.emplace_back(gpu_worker, &worker_args[g]);

    // Progress reporting loop (main thread)
    while (!global_found.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        auto now = std::chrono::high_resolution_clock::now();
        double sec = std::chrono::duration<double>(now - start_time).count();

        uint64_t total_keys = 0;
        for (int g = 0; g < num_gpus; g++)
            total_keys += stats[g].keys_checked.load(std::memory_order_relaxed);

        double total_mkeys_s = (double)total_keys / sec / 1e6;

        printf("\r[%5.1fs] Total: %6llu M  |  Speed: %7.2f MKeys/s  |  GPUs: ",
               sec, (unsigned long long)(total_keys/1000000), total_mkeys_s);
        for (int g = 0; g < num_gpus; g++) {
            uint64_t gk = stats[g].keys_checked.load(std::memory_order_relaxed);
            printf("GPU%d: %.0fM", gpu_ids[g], (double)gk/1e6);
            if (g+1 < num_gpus) printf(" | ");
        }
        printf("  ");
        fflush(stdout);
    }

    // Wait for all threads
    for (auto& t : threads) t.join();

    printf("\n");

    if (shared_result.found) {
        auto now = std::chrono::high_resolution_clock::now();
        double sec = std::chrono::duration<double>(now - start_time).count();
        uint64_t total_keys = 0;
        for (int g = 0; g < num_gpus; g++)
            total_keys += stats[g].keys_checked.load();

        printf("\n============================================\n");
        printf("Match found in %.1fs after ~%llu M keys!\n", sec, (unsigned long long)(total_keys/1000000));
        printf("============================================\n\n");

        char fp_b64[45]; base64_encode(shared_result.fingerprint, 32, fp_b64);

        // Compute MeshCore private key for display
        uint8_t mc_priv[64];
        seed_to_meshcore_privkey(shared_result.seed, mc_priv);

        printf("Seed (32 bytes):\n  ");
        for (int i=0;i<32;i++) printf("%02x",shared_result.seed[i]);

        printf("\nPublic Key (32 bytes):\n  ");
        for (int i=0;i<32;i++) printf("%02x",shared_result.public_key[i]);

        printf("\nFingerprint:\n  SHA256:%s", fp_b64);

        printf("\n\n── MeshCore Format (clamped_scalar + nonce) ──\n");
        printf("MeshCore Private Key (64 bytes):\n  ");
        for (int i=0;i<64;i++) printf("%02x",mc_priv[i]);
        printf("\n  [0:32]  clamped_scalar: ");
        for (int i=0;i<32;i++) printf("%02x",mc_priv[i]);
        printf("\n  [32:64] nonce:          ");
        for (int i=32;i<64;i++) printf("%02x",mc_priv[i]);

        printf("\n\n── OpenSSH Format (seed + pubkey) ──\n");
        printf("OpenSSH Private Key (64 bytes):\n  ");
        for (int i=0;i<32;i++) printf("%02x",shared_result.seed[i]);
        for (int i=0;i<32;i++) printf("%02x",shared_result.public_key[i]);
        printf("\n\n");

        // Generate unique filenames with timestamp + serial number
        char fn_info[256], fn_priv[256], fn_pub[256];
        make_output_filename("found_key.txt", fn_info, sizeof(fn_info));
        make_output_filename("id_ed25519",    fn_priv, sizeof(fn_priv));
        // pub filename = priv + ".pub"
        snprintf(fn_pub, sizeof(fn_pub), "%s.pub", fn_priv);

        printf("\nSaving results:\n");
        printf("  Info:        %s\n", fn_info);
        printf("  Private key: %s\n", fn_priv);
        printf("  Public key:  %s\n", fn_pub);

        write_key_info(&shared_result, fn_info);

        if (write_openssh_keys(shared_result.seed, shared_result.public_key,
                               fn_priv, fn_pub)) {
            printf("OpenSSH private key written to: %s\n", fn_priv);
            printf("OpenSSH public key written to:  %s\n", fn_pub);
        } else {
            fprintf(stderr, "Error: Failed to write OpenSSH keys\n");
        }
        return 0;
    }

    return 1;
}
