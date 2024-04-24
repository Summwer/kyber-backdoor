
/* Deterministic kyber_randombytes by Daniel J. Bernstein */
/* taken from SUPERCOP (https://bench.cr.yp.to)     */

#include <stddef.h>
#include <stdint.h>
#include "kem.h"
// #include "rng.h"
#include "randombytes.h"
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "../../mceliece348864/crypto_kem.h"
#include "../../mceliece348864/nist/rng.h"
#include "polyvec.h"
#include <time.h>
#include "sodium.h"
#include "indcpa.h"
#include <inttypes.h>
#include <assert.h>
#include "symmetric.h"
#include "speed_print.h"
#include "cpucycles.h"

void fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L);

#define NTESTS 1000
// #define NTESTS 100
#define KAT_FILE_OPEN_ERROR -1
#define ETA2NUM 5
#define ETA 2
#define gen_a(A,B)  gen_matrix(A,B,0)

uint64_t test[NTESTS];

static uint32_t seed[32] = {
  3,1,4,1,5,9,2,6,5,3,5,8,9,7,9,3,2,3,8,4,6,2,6,4,3,3,8,3,2,7,9,5
};
static uint32_t in[12];
static uint32_t out[8];
static int outleft = 0;

static unsigned char *mc_pk = 0; //public key of mceliece348864
static unsigned char *mc_sk = 0; //secret key of mceliece348864
static unsigned char *mc_ct = 0; //ciphertext of mceliece348864: implant the cipher text into the last bit of ciphertext (t) of kybers.
static unsigned char *mc_ct1 = 0; //The recover ciphertext of mceliece348864 extracted from t in kyber: implant the cipher text into the last bit of ciphertext (t) of kybers.
static unsigned char *mc_ss = 0; //session key of mceliece348864: use the session key as the seed of Kyber.
static unsigned char *mc_ss1 = 0; //checked session key of mceliece348864: check the decrypted the session key (using mc_sk) from the last bit of ciphertext (t) of kybers.
static unsigned char entropy_input[48];
static unsigned char mc_seed[48];


uint8_t kyber_pk[CRYPTO_PUBLICKEYBYTES];
uint8_t kyber_sk[CRYPTO_SECRETKEYBYTES];
uint8_t kyber_sk1[CRYPTO_SECRETKEYBYTES];//Recover kyber_sk from our backdoor attack.
uint8_t kyber_ct[CRYPTO_CIPHERTEXTBYTES];
uint8_t kyber_ss[CRYPTO_BYTES];
uint8_t kyber_ss1[CRYPTO_BYTES]; //Recover kyber's session key though our backdoor attack.
// FILE  *fp_rsp;


typedef struct{
  int16_t num;
  double prob;
} distribution;

static distribution eta2dis[ETA2NUM] = {{-2,1/16.}, {-1,  1./4.}, {0,  3./8.}, {1, 1./4.}, {2, 1/16.}};
static distribution zerodis[ETA2NUM] = {{-2,1./8.}, {0,  3/4.}, {2, 1./8.}}; //The distribution of e that e(mod 2) = 0
static distribution onedis[ETA2NUM] = {{-1,  1./2.}, {1, 1./2.}}; //The distribution of e that e(mod 2) = 1

#define ROTATE(x,b) (((x) << (b)) | ((x) >> (32 - (b))))
#define MUSH(i,b) x = t[i] += (((x ^ seed[i]) + sum) ^ ROTATE(x,b));

static void surf(void)
{
  uint32_t t[12]; uint32_t x; uint32_t sum = 0;
  int r; int i; int loop;

  for (i = 0;i < 12;++i) t[i] = in[i] ^ seed[12 + i];
  for (i = 0;i < 8;++i) out[i] = seed[24 + i];
  x = t[11];
  for (loop = 0;loop < 2;++loop) {
    for (r = 0;r < 16;++r) {
      sum += 0x9e3779b9;
      MUSH(0,5) MUSH(1,7) MUSH(2,9) MUSH(3,13)
      MUSH(4,5) MUSH(5,7) MUSH(6,9) MUSH(7,13)
      MUSH(8,5) MUSH(9,7) MUSH(10,9) MUSH(11,13)
    }
    for (i = 0;i < 8;++i) out[i] ^= t[i + 4];
  }
}

void kyber_randombytes(uint8_t *x,size_t xlen)
{
  while (xlen > 0) {
    if (!outleft) {
      if (!++in[0]) if (!++in[1]) if (!++in[2]) ++in[3];
      surf(); //generate the seed.
      outleft = 8;
    }
    *x = out[--outleft];
    // printf("%02x", *x);
    ++x;
    --xlen;
  }
  // printf("\n");
}



static int16_t gen_random_in_prob_dist(distribution *dis){
  const uint32_t temp=randombytes_uniform(100);//rand()%100+1;
  
  // srand((unsigned)time(mc_seed[i]) );
  double sum_prob = 0.;
  for(int i = 0; i < ETA2NUM; i++){
    sum_prob +=  dis[i].prob;
    if(temp < sum_prob*100){
      return dis[i].num;
    }
  }
  printf("Wrong!!\n");
  assert(temp < sum_prob*100);
  return 0;
}


//implant mc_ss to seed d in Kyber
void implant_ss_to_seed(uint8_t *x, size_t xlen){
  for(size_t i = 0; i < xlen; i++){
    x[i] =(uint8_t) mc_ss[i];
  }
}

//implant mc_ct to the last bit of t in Kyber
//We shoud give a new e s.t (As+e \in(-q/2^n, q/2^n))(mod 2) = mc_ct
//input: pkpv: As(As+e =t (mod q))
//output: new pkpv: t = As+e(mod q), new e.
void implant_ct_to_t(polyvec *pkpv, polyvec *e){
  // polyvec_reduce(&pkpv);
  size_t k = 0; //denote the current index of kyber_ct
  for(int i=0;i<KYBER_K;i++){
    for(int j=0;j<KYBER_N/8;j++) {
      for(int z=0; z < 8; z++){
        int16_t diff = abs(( (((int16_t)mc_ct[k]>>(7-z))&1) - (pkpv->vec[i]).coeffs[8*j+z])%2);
        
        if(k < mc_crypto_kem_CIPHERTEXTBYTES){
          //select the e from a new distribution that depart 0 and 1.
          if(diff == 1)
            (e->vec[i]).coeffs[8*j+z] = gen_random_in_prob_dist(onedis);
          if(diff == 0)
            (e->vec[i]).coeffs[8*j+z] = gen_random_in_prob_dist(zerodis);
        }
        else{
          //select the e from the original distribution that depart 0 and 1.
          (e->vec[i]).coeffs[8*j+z] = gen_random_in_prob_dist(eta2dis);
        }
        // if((pkpv->vec[i]).coeffs[8*j+z]> KYBER_Q/2 - 3 || (pkpv->vec[i]).coeffs[8*j+z]< -KYBER_Q/2+3)
          // printf("pkpv[%d][%d] = %d, k =%ld, diff = %d, ei = %d \n", i, 8*j+z,(pkpv->vec[i]).coeffs[8*j+z], k, diff, (e->vec[i]).coeffs[8*j+z]);
        (pkpv->vec[i]).coeffs[8*j+z] += (e->vec[i]).coeffs[8*j+z];
        // if((((int16_t)mc_ct[k]>>(7-z))&1)!= abs(((pkpv->vec[i]).coeffs[8*j+z])%2))
        //   printf("last bit: %d = %d = (%d - (%d)) (mod 2), index = %d, diff = %d, ei = %d, k = %ld, bound = %d, \n", (((int16_t)mc_ct[k]>>(7-z))&1), abs(((pkpv->vec[i]).coeffs[8*j+z]-(e->vec[i]).coeffs[8*j+z])%2),  (pkpv->vec[i]).coeffs[8*j+z], (e->vec[i]).coeffs[8*j+z], i* KYBER_N + 8*j+z, diff, (e->vec[i]).coeffs[8*j+z], k, mc_crypto_kem_CIPHERTEXTBYTES);
      }
      k++;
    }
  }
}

//output: the right skpv
static int backdoor_keyrec(unsigned char *tmp_mc_ct1, uint8_t pk_seed[KYBER_SYMBYTES]){
  mc_crypto_kem_dec(mc_ss1, tmp_mc_ct1, mc_sk);
  polyvec skpv;
  
  uint8_t buf[2*KYBER_SYMBYTES];
  // const uint8_t *publicseed = buf;
  uint8_t nonce = 0;
  const uint8_t *publicseed = buf;
  const uint8_t *noiseseed = buf+KYBER_SYMBYTES;
  polyvec a[KYBER_K];

  // implant_ss_to_seed(buf, KYBER_SYMBYTES);
  for(int k = 0; k < KYBER_SYMBYTES; k++){
    buf[k] =(uint8_t) mc_ss1[k];
  }
  hash_g(buf, buf, KYBER_SYMBYTES);
  gen_a(a, publicseed);

  //Determine whether publicseed = pkseed
  // printf("publicseed: ");
  // for (int i = 0; i < KYBER_SYMBYTES; i++) {
  //   // sscanf(ss + 2*i, "%02hhx", &buf[i]);
  //   printf("%02x",publicseed[i]);
  // }
  // printf("\n");

  // printf("pk_seed: ");
  // for (int i = 0; i < KYBER_SYMBYTES; i++) {
  //   // sscanf(ss + 2*i, "%02hhx", &buf[i]);
  //   printf("%02x",pk_seed[i]);
  // }
  // printf("\n");
  // printf("=============================");
  
  if(memcmp(publicseed,pk_seed,KYBER_SYMBYTES)!=0){
    // printf("memcmp:%d\n",memcmp(publicseed,pk_seed,KYBER_SYMBYTES));
    return 0;
  }
  
  // printf("============0=================");

  //Regenerate sk
  for(int k=0;k<KYBER_K;k++)
    poly_getnoise_eta1(&skpv.vec[k], noiseseed, nonce++); //generate vector s


  polyvec_ntt(&skpv);

  // matrix-vector multiplication
  // for(int i=0;i<KYBER_K;i++) {
  //   polyvec_basemul_acc_montgomery(&pkpv1.vec[i], &a[i], &skpv);
  //   poly_tomont(&pkpv1.vec[i]);
  // }
  // polyvec_invntt(&pkpv1);

  // for(int i=0;i<KYBER_K;i++){
  //   for(int j=0;j<KYBER_N;j++) {
  //     int16_t ei = (pkpv.vec[i].coeffs[j] - pkpv1.vec[i].coeffs[j]) % KYBER_Q;
  //     if(ei < -KYBER_Q/2)
  //       ei += KYBER_Q;
  //     if(ei > KYBER_Q/2)
  //       ei -= KYBER_Q;
  //     if(abs(ei) > ETA)
  //       return 0;
  //   }
  // }
  // printf("============1=================");
  pack_sk(kyber_sk1, &skpv);
  for(int k=0;k<KYBER_INDCPA_PUBLICKEYBYTES;k++)
    kyber_sk1[k+KYBER_INDCPA_SECRETKEYBYTES] = kyber_pk[k];
  hash_h(kyber_sk1+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, kyber_pk, KYBER_PUBLICKEYBYTES);
  /* Value z for pseudo-random output on reject */
  kyber_randombytes(kyber_sk1+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES);
  // printf("=============================");
  return 1;
}

//After impacting the ss as the seed d of Kyber.
//We can decrypt the ss by the mc_sk after obtaining the kyber_pk(t) of kyber.
//And use ss to compute the kyber_sk in Kyber.
//Then, we can decap the session key of Kyber using the kyber_sk.
static int decap_kyber_ss_in_backdoor(){
  unsigned int num_of_bound_condition = 0; //The number of element reaches the bound condition.

  // enum_times[0] = 0; //Total enumeration times: 2^(num_of_bound_condition)
  // enum_times[1] = 0; //The number we search.
  
  
  uint8_t pk_seed[KYBER_SYMBYTES];
  // uint8_t nonce = 0;
  polyvec pkpv;
  // poly v, k, epp;

  unpack_pk(&pkpv, pk_seed, kyber_pk);


 
  polyvec_invntt(&pkpv);
  unsigned char *last_bit_of_t = last_bit_of_polyvec(&pkpv);

  int *indices_reach_bound = malloc(sizeof(int)*mc_crypto_kem_CIPHERTEXTBYTES); //consider the kyber_ct may in a bound condition, which will fail to solve the solution.

  // int num_of_bound_condition = 0; //The number of element reaches the bound condition.
  for(int i = 0; i < mc_crypto_kem_CIPHERTEXTBYTES; i++){
    mc_ct1[i] =  last_bit_of_t[i];
    indices_reach_bound[i] = -1;
    for(int j = 0; j < 8; j++){
      if((pkpv.vec[(i*8+j)/KYBER_N]).coeffs[(i*8+j)%KYBER_N]>= (KYBER_Q-3)/2  || (pkpv.vec[(i*8+j)/KYBER_N]).coeffs[(i*8+j)%KYBER_N] <= (-KYBER_Q+3)/2){
        // printf("%d\n",(pkpv.vec[(i*8+j)/KYBER_N]).coeffs[(i*8+j)%KYBER_N]);
        indices_reach_bound[num_of_bound_condition] = (i*8+j);
        num_of_bound_condition++;
      }
    }
  }


  if(num_of_bound_condition > 0){
    // enum_times[0] = (1<<num_of_bound_condition);
    for(int i = 0; i < (1<<num_of_bound_condition); i++){
      // enum_times[1]++;
      unsigned char *tmp_mc_ct1 = malloc(mc_crypto_kem_CIPHERTEXTBYTES);
      for(int j = 0; j < mc_crypto_kem_CIPHERTEXTBYTES; j++)
        tmp_mc_ct1[j]= mc_ct1[j];
      // strcpy(tmp_mc_ct1,mc_ct1);
      for(unsigned int j = 0; j < num_of_bound_condition; j++){
        int ct_index = indices_reach_bound[j];
        
        int change_bit = (i>>(num_of_bound_condition-j-1)) & 1;
        if(change_bit == 1)
          tmp_mc_ct1[ct_index/8] = (1<<(7-(ct_index%8))) ^ tmp_mc_ct1[ct_index/8]; // bin(kyber_ct)[index] ^ 1/0

      }
      if(backdoor_keyrec(tmp_mc_ct1, pk_seed)){
        mc_ct1 = tmp_mc_ct1;
        break;
      }
    }
  }
  else{
    backdoor_keyrec(mc_ct1, pk_seed);
  }
  crypto_kem_dec(kyber_ss1, kyber_ct, kyber_sk1); //decap using the recovered kyber_sk.

  return num_of_bound_condition;

}


int main(void)
{
  unsigned int i;


  //seed generation in mceliece348864
  for (i=0; i<48; i++)
    entropy_input[i] = i;
  mc_randombytes_init(entropy_input, NULL, 256);
  
  
  // fp_rsp = fdopen(0, "w");
  // if (!fp_rsp)
  //   return KAT_FILE_OPEN_ERROR;

  if(!mc_pk) mc_pk = malloc(mc_crypto_kem_PUBLICKEYBYTES);
  if (!mc_pk) abort();
  if(!mc_sk) mc_sk = malloc(mc_crypto_kem_SECRETKEYBYTES);
  if (!mc_sk) abort();
  if (!mc_ct) mc_ct = malloc(mc_crypto_kem_CIPHERTEXTBYTES);
  if (!mc_ct) abort();
  if (!mc_ct1) mc_ct1 = malloc(mc_crypto_kem_CIPHERTEXTBYTES);
  if (!mc_ct1) abort();
  if (!mc_ss) mc_ss = malloc(crypto_kem_BYTES);
  if (!mc_ss) abort();
  if (!mc_ss1) mc_ss1 = malloc(crypto_kem_BYTES);
  if (!mc_ss1) abort();

  // for(i=0;i<NTESTS;i++) {
    // fprintf(fp_rsp, "count = %d\n", i+1);
    // printf("count = %d/%d\n", i+1,NTESTS);
  
  mc_randombytes(mc_seed, 48);
  mc_randombytes_init(mc_seed, NULL, 256);
  

  mc_crypto_kem_keypair(mc_pk, mc_sk); //generate keypairs in mceliece348864
  for(i=0;i<NTESTS;i++) {
    test[i] = cpucycles();
    // //Encap in mceliece348864
    mc_crypto_kem_enc(mc_ct, mc_ss, mc_pk);
    crypto_kem_keypair(kyber_pk, kyber_sk);
  }

  print_results("kyber_backdoor_KeyGen*: ", test, NTESTS);


  // Key-pair generation in Kyber
  //Impant mc_ss into Kyber as the seed d
  //Impant ma_ct into Kyber as the last bit of t in Kyber.
  // crypto_kem_keypair(kyber_pk, kyber_sk);


  // Encapsulation
  // for(i=0;i<NTESTS;i++) {
  //   test[i] = cpucycles();
  //   crypto_kem_enc(kyber_ct, kyber_ss, kyber_pk);
  // }
  // print_results("kyber_backdoor_encaps: ", test, NTESTS);
    
  // Decapsulation
  for(i=0;i<NTESTS;i++) {
    test[i] = cpucycles();
    decap_kyber_ss_in_backdoor();
  }
  print_results("kyber_backdoor_KeyRec*: ", test, NTESTS);
  

    // fprintBstr(fp_rsp, "kyber_ss = ", kyber_ss, CRYPTO_BYTES);
    // fprintBstr(fp_rsp, "kyber_ss1 = ", kyber_ss1,CRYPTO_BYTES);
    // assert(memcmp(kyber_ss, kyber_ss1, CRYPTO_BYTES)==0);

    // fprintf(fp_rsp, "===============end===================\n\n");
    // // printf("===============end===================\n\n");

  return 0;
}




void
fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L)
{
    unsigned long long i;

    fprintf(fp, "%s", S);

    for ( i=0; i<L; i++ )
        fprintf(fp, "%02X", A[i]);

    if ( L == 0 )
        fprintf(fp, "00");

    fprintf(fp, "\n");
}
