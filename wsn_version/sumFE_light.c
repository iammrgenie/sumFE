#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "mini-gmp.h"

#define NUM 5

//Representation of a Ciphertext
typedef struct {
    mpz_t firstcomp;   
    mpz_t secondcomp;
    //mpz_t CT;                           //product of the 2 components. Used for adding all ciphertexts
} Ciphertext;

//Representation of a User
typedef struct {
    char *ID;
    mpz_t secKey;
    mpz_t pubKey;
    unsigned long int plaintext;
} Users;

void random_number(mpz_t min_num, mpz_t max_num, mpz_t out) {
        mpz_t result, tmp1, tmp2;
        mpz_init(result);
        mpz_init(tmp1);

        srand(time(NULL));
        mpz_sub(tmp1, max_num, min_num);

        unsigned long int v = rand();
        mpz_init_set_ui(tmp2, v);

        mpz_mod(result, tmp2, tmp1);
        mpz_add(result, result, min_num);

        mpz_clear(result);
        mpz_clear(tmp1);
        mpz_clear(tmp2);
}

void genKeyPair(Users *U, int num, mpz_t p, mpz_t g) {    
    mpz_t cnt;
    mpz_init_set_str(cnt, "1", 0);

    for (int i = 0; i < num; i++) {
        //Initialise the parameters
        mpz_t sKey, pKey;
        mpz_init(sKey);
        mpz_init(pKey);

        //Generate a random secret key based on p
        random_number(cnt, p, sKey);

        //Calculate the public key based on the secret key
        mpz_powm(pKey, g, sKey, p);

        //Store values into the Struct
        mpz_init_set(U[i].secKey, sKey);
        mpz_init_set(U[i].pubKey, pKey);

        //Clear the temporal parameters from memory
        mpz_clear(sKey);
        mpz_clear(pKey);
    }
}

void HE_Encrypt(Ciphertext *C, Users *U, mpz_t g, mpz_t p, unsigned long int r, int num) {
    for (int i = 0; i < num; i ++) {
        mpz_t res1, res2, res3, tmp1, tmp2, tmp3;
        mpz_init(res1);
        mpz_init(res2);
        //mpz_init(res3);
        mpz_init(tmp1);
        mpz_init(tmp2);
        mpz_init(tmp3);

        // (gˆr) % p
        mpz_powm_ui(res1, g, r, p);
        // tmp1 = pk ^r
        mpz_pow_ui(tmp1, U[i].pubKey, r);
        // tmp2 = g ^ msg
        mpz_pow_ui(tmp2, g, U[i].plaintext);
        // tmp3 = tmp1 * tmp2
        mpz_mul(tmp3, tmp1, tmp2);
        // res2 = tmp3 % p
        mpz_mod(res2, tmp3, p);

        //calculate the product of the 2 components
        //mpz_mul(res3, res1, res2);

        //Copy results into struct
        mpz_init_set(C[i].firstcomp, res1);
        mpz_init_set(C[i].secondcomp, res2);
        //mpz_init_set(C[i].CT, res3);

        mpz_clear(res1);
        mpz_clear(res2);
        //mpz_clear(res3);
        mpz_clear(tmp1);
        mpz_clear(tmp2);
        mpz_clear(tmp3);
    }
}


int main() {
    mpz_t p,g,q;

    unsigned long int r = 5;

    mpz_init_set_str(p, "141103728801468755249503291901801300339454489134873273269161807133184957725631203791969744406992490029017308434294093310271973777802513443575042969796895750747614660497411432558300476234836462151925376765365205539666438199705555483194413832902302373511490858360959114097755447464088887287145428704637498873563", 0);
    mpz_init_set_str(g, "105861658449903670398842707812938888531601091401355008230876634024010937268870331311638117904636173888707058855182778532622385692236892785716421644114344195029162371175818169381366740838052666046929986716700970629216177653754852315554730008499152818656193522542478412787555437975470969140718764372166206582283", 0);
    mpz_init_set_str(q, "783294875021436409578654247252215361374348380322356315904524998417053527857380", 0);

    Users U[NUM];
    genKeyPair(U, NUM, p, g);

    return 1;
}