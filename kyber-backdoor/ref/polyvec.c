
#include <stdint.h>
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "reduce.h"
#include <stdio.h>
#include <stdlib.h>

/*************************************************
* Name:        polyvec_compress
*
* Description: Compress and serialize vector of polynomials
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for KYBER_POLYVECCOMPRESSEDBYTES)
*              - const polyvec *a: pointer to input vector of polynomials
**************************************************/
void polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES], const polyvec *a)
{
  unsigned int i,j,k;

#if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352))
  uint16_t t[8];
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/8;j++) {
      for(k=0;k<8;k++) {
        t[k]  = a->vec[i].coeffs[8*j+k];
        t[k] += ((int16_t)t[k] >> 15) & KYBER_Q;
        t[k]  = ((((uint32_t)t[k] << 11) + KYBER_Q/2)/KYBER_Q) & 0x7ff;
      }

      r[ 0] = (t[0] >>  0);
      r[ 1] = (t[0] >>  8) | (t[1] << 3);
      r[ 2] = (t[1] >>  5) | (t[2] << 6);
      r[ 3] = (t[2] >>  2);
      r[ 4] = (t[2] >> 10) | (t[3] << 1);
      r[ 5] = (t[3] >>  7) | (t[4] << 4);
      r[ 6] = (t[4] >>  4) | (t[5] << 7);
      r[ 7] = (t[5] >>  1);
      r[ 8] = (t[5] >>  9) | (t[6] << 2);
      r[ 9] = (t[6] >>  6) | (t[7] << 5);
      r[10] = (t[7] >>  3);
      r += 11;
    }
  }
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320))
  uint16_t t[4];
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/4;j++) {
      for(k=0;k<4;k++) {
        t[k]  = a->vec[i].coeffs[4*j+k];
        t[k] += ((int16_t)t[k] >> 15) & KYBER_Q;
        t[k]  = ((((uint32_t)t[k] << 10) + KYBER_Q/2)/ KYBER_Q) & 0x3ff;
      }

      r[0] = (t[0] >> 0);
      r[1] = (t[0] >> 8) | (t[1] << 2);
      r[2] = (t[1] >> 6) | (t[2] << 4);
      r[3] = (t[2] >> 4) | (t[3] << 6);
      r[4] = (t[3] >> 2);
      r += 5;
    }
  }
#else
#error "KYBER_POLYVECCOMPRESSEDBYTES needs to be in {320*KYBER_K, 352*KYBER_K}"
#endif
}

/*************************************************
* Name:        polyvec_decompress
*
* Description: De-serialize and decompress vector of polynomials;
*              approximate inverse of polyvec_compress
*
* Arguments:   - polyvec *r:       pointer to output vector of polynomials
*              - const uint8_t *a: pointer to input byte array
*                                  (of length KYBER_POLYVECCOMPRESSEDBYTES)
**************************************************/
void polyvec_decompress(polyvec *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES])
{
  unsigned int i,j,k;

#if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352))
  uint16_t t[8];
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/8;j++) {
      t[0] = (a[0] >> 0) | ((uint16_t)a[ 1] << 8);
      t[1] = (a[1] >> 3) | ((uint16_t)a[ 2] << 5);
      t[2] = (a[2] >> 6) | ((uint16_t)a[ 3] << 2) | ((uint16_t)a[4] << 10);
      t[3] = (a[4] >> 1) | ((uint16_t)a[ 5] << 7);
      t[4] = (a[5] >> 4) | ((uint16_t)a[ 6] << 4);
      t[5] = (a[6] >> 7) | ((uint16_t)a[ 7] << 1) | ((uint16_t)a[8] << 9);
      t[6] = (a[8] >> 2) | ((uint16_t)a[ 9] << 6);
      t[7] = (a[9] >> 5) | ((uint16_t)a[10] << 3);
      a += 11;

      for(k=0;k<8;k++)
        r->vec[i].coeffs[8*j+k] = ((uint32_t)(t[k] & 0x7FF)*KYBER_Q + 1024) >> 11;
    }
  }
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320))
  uint16_t t[4];
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/4;j++) {
      t[0] = (a[0] >> 0) | ((uint16_t)a[1] << 8);
      t[1] = (a[1] >> 2) | ((uint16_t)a[2] << 6);
      t[2] = (a[2] >> 4) | ((uint16_t)a[3] << 4);
      t[3] = (a[3] >> 6) | ((uint16_t)a[4] << 2);
      a += 5;

      for(k=0;k<4;k++)
        r->vec[i].coeffs[4*j+k] = ((uint32_t)(t[k] & 0x3FF)*KYBER_Q + 512) >> 10;
    }
  }
#else
#error "KYBER_POLYVECCOMPRESSEDBYTES needs to be in {320*KYBER_K, 352*KYBER_K}"
#endif
}

/*************************************************
* Name:        polyvec_tobytes
*
* Description: Serialize vector of polynomials
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for KYBER_POLYVECBYTES)
*              - const polyvec *a: pointer to input vector of polynomials
**************************************************/
void polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], const polyvec *a)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    poly_tobytes(r+i*KYBER_POLYBYTES, &a->vec[i]);
}

/*************************************************
* Name:        polyvec_frombytes
*
* Description: De-serialize vector of polynomials;
*              inverse of polyvec_tobytes
*
* Arguments:   - uint8_t *r:       pointer to output byte array
*              - const polyvec *a: pointer to input vector of polynomials
*                                  (of length KYBER_POLYVECBYTES)
**************************************************/
void polyvec_frombytes(polyvec *r, const uint8_t a[KYBER_POLYVECBYTES])
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    poly_frombytes(&r->vec[i], a+i*KYBER_POLYBYTES);
}

/*************************************************
* Name:        polyvec_ntt
*
* Description: Apply forward NTT to all elements of a vector of polynomials
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/
void polyvec_ntt(polyvec *r)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    poly_ntt(&r->vec[i]);
}

/*************************************************
* Name:        polyvec_invntt_tomont
*
* Description: Apply inverse NTT to all elements of a vector of polynomials
*              and multiply by Montgomery factor 2^16
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/
void polyvec_invntt_tomont(polyvec *r)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    poly_invntt_tomont(&r->vec[i]);
}

/*************************************************
* Name:        polyvec_basemul_acc_montgomery
*
* Description: Multiply elements of a and b in NTT domain, accumulate into r,
*              and multiply by 2^-16.
*
* Arguments: - poly *r: pointer to output polynomial
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/
void polyvec_basemul_acc_montgomery(poly *r, const polyvec *a, const polyvec *b)
{
  unsigned int i;
  poly t;

  poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
  for(i=1;i<KYBER_K;i++) {
    poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i]);
    poly_add(r, r, &t);
  }

  poly_reduce(r);
}

/*************************************************
* Name:        polyvec_reduce
*
* Description: Applies Barrett reduction to each coefficient
*              of each element of a vector of polynomials;
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments:   - polyvec *r: pointer to input/output polynomial
**************************************************/
void polyvec_reduce(polyvec *r)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    poly_reduce(&r->vec[i]);
}

/*************************************************
* Name:        polyvec_add
*
* Description: Add vectors of polynomials
*
* Arguments: - polyvec *r: pointer to output vector of polynomials
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/
void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
}



/*************************************************
* Name:        polyvec_invntt
* Description: Apply inverse NTT to all elements of a vector of polynomials
*              and recover the original vector.
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/
void polyvec_invntt(polyvec *r)
{
  polyvec_invntt_tomont(r);

  for(int i=0;i<KYBER_K;i++){
    for(int j=0;j<KYBER_N;j++) {
      (r->vec[i]).coeffs[j] = (MONTINV * (r->vec[i]).coeffs[j]) % KYBER_Q;
      if((r->vec[i]).coeffs[j] < -KYBER_Q/2)
        (r->vec[i]).coeffs[j] += KYBER_Q;
      if((r->vec[i]).coeffs[j] > KYBER_Q/2)
        (r->vec[i]).coeffs[j] -= KYBER_Q;
    }
  }
}


/*************************************************
* Name:        print_polyvec
* Description: print the polyvec.
*
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/

void print_polyvec(polyvec *r){
  printf("[");
  for(int i=0;i<KYBER_K;i++){
    for(int j=0;j<KYBER_N;j++) {
      printf("%d", (r->vec[i]).coeffs[j]);
      if(!(i == KYBER_K-1 && j==KYBER_N-1))
        printf(", ");
    }
  }
  printf("]\n");
}



/*************************************************
* Name:        return last_bit_of_polyvec
* Description: return the last bit of each element in polyvec in base16.
*
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/

unsigned char * last_bit_of_polyvec(polyvec *r){
  // uint8_t *last_bits = new uint8_t[KYBER_K*KYBER_N/8];
  unsigned char *last_bits = malloc (sizeof (unsigned char) *KYBER_K*KYBER_N/8);
  for(int i=0;i<KYBER_K;i++){
    for(int j=0;j<KYBER_N/8;j++) {
      last_bits[i*KYBER_N/8+j] = 0;
      for(int k=0;k<8;k++) {
        last_bits[i*KYBER_N/8+j] += (abs((r->vec[i]).coeffs[8*j+k])%2 << (7-k));
      }
      // printf("%02x", last_bits[i*KYBER_N/8+j]);
    }
  }
  // printf("\n");
  return last_bits;
}




// /*************************************************
// * Name:        return possible_last_bit_of_polyvec
// * Description: return the last bit of each element in polyvec in base16.
// *              Consider last bit of polyvec might reach the bound condition. We should *              reconsider such condition, and return multiple possible ct.
// *
// *
// * Arguments:   - polyvec *r: pointer to in/output vector of polynomials
// **************************************************/

// unsigned char ** possible_last_bit_of_polyvec(polyvec *r){
//   // uint8_t *last_bits = new uint8_t[KYBER_K*KYBER_N/8];
//   unsigned char **last_bits = malloc (sizeof (unsigned char) *KYBER_K*KYBER_N/8);
//   for(int i=0;i<KYBER_K;i++){
//     for(int j=0;j<KYBER_N/8;j++) {
//       last_bits[i*KYBER_N/8+j] = 0;
//       for(int k=0;k<8;k++) {
//         last_bits[i*KYBER_N/8+j] += (abs((r->vec[i]).coeffs[8*j+k])%2 << (7-k));
//       }
//       printf("%02x", last_bits[i*KYBER_N/8+j]);
//     }
//   }
//   printf("\n");
//   return last_bits;
// }



/*************************************************
* Name:        probability distribution of the noise polyvec e.
* Description: print the probability distribution of the noise polyvec e.
*
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/

void polyvec_prob_dis_eta2(polyvec *r){
  int16_t nums[ETA2NUM] = {-2,-1,0,1,2};
  // int probs[ETA2NUM] = {1/16., 1/4., 3/8., 1/4., 1/16.};
  double probs[ETA2NUM] = {0., 0., 0., 0., 0.};
  for(int i=0;i<KYBER_K;i++){
    for(int j=0;j<KYBER_N;j++) {
      for(int k = 0; k < ETA2NUM; k++){
        if((r->vec[i]).coeffs[j]==nums[k]){
          probs[k]++;
          break;
        }
      }
    }
  }
  // printf("Distribution of e: {");
  for(int k = 0; k < ETA2NUM; k++){
     probs[k] /= (KYBER_K*KYBER_N);
    //  printf("%d: %.3f", nums[k], probs[k]);
    //  if(k<ETA2NUM-1)
      // printf(", ");
  }
  // printf("}\n");
}

