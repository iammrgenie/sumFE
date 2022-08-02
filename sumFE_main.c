#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <time.h>

#define NUM 200
#define PRECOMP 500000

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

//Users File1[NUM];

void genPreComputedValues(mpz_t g, mpz_t p, int size, mpz_t *values){
    for (unsigned long int i = 0; i < size; i++){
        mpz_init(values[i]);
        mpz_powm_ui(values[i], g, i, p);
    }
}

void genKeyPair(Users *U, int num, mpz_t p, mpz_t g) {    
    //Set Random parameters
    gmp_randstate_t st;
    unsigned long int sd = (unsigned long int) (clock());
    gmp_randinit_default(st);
    gmp_randseed_ui(st, sd);

    for (int i = 0; i < num; i++) {
        //Initialise the parameters
        mpz_t sKey, pKey;
        mpz_init(sKey);
        mpz_init(pKey);

        //Generate a random secret key based on p
        mpz_urandomm(sKey, st, p);

        //Calculate the public key based on the secret key
        mpz_powm_sec(pKey, g, sKey, p);

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

void addCipher(int cnt, Ciphertext *out_cipher, Ciphertext *C, mpz_t g, mpz_t p, unsigned long int r) {
    //mpz_powm_ui(finalCipher.firstcomp, g, r, p);
    mpz_t res1, res2;
    mpz_init(res1);
    mpz_init(res2);

    //first component of the ciphertext. Same as all ciphertexts
    mpz_powm_ui(res1, g, r, p);

    mpz_set(res2, C[0].secondcomp);

    for (int i = 1; i < cnt; i++){
        mpz_mul(res2, res2, C[i].secondcomp);
    }

    //copy results into the out_cipher
    mpz_init_set(out_cipher->firstcomp, res1);
    mpz_init_set(out_cipher->secondcomp, res2);

    mpz_clear(res1);
    mpz_clear(res2);

}

void addKeys(int cnt, Users *U, mpz_t msk){
    mpz_t res;
    mpz_init(res);

    mpz_set(res, U[0].secKey);

    for (int i = 1; i < cnt; i++){
        mpz_add(res, res, U[i].secKey);
    }

    mpz_init_set(msk, res);
    mpz_clear(res);
}

void FE_decrypt(Ciphertext *finalcipher, mpz_t msk, mpz_t p, mpz_t *values) {
    mpz_t res1, res2, res3, fg;

    mpz_init(res1);
    mpz_init(res2);
    mpz_init(res3);

    signed long int i = 1;
    mpz_init_set_si(fg, i);

    // (p - msk) - 1
    mpz_sub(res1, p, msk);
    mpz_sub(res1, res1, fg);

    // (cipher->firstcomp ^ p - privateKey - 1) % p
    mpz_powm(res2, finalcipher->firstcomp, res1, p);

    //((cipher->firstcomp ^ p - privateKey - 1) % p) * cipher->secondcomp
    mpz_mul(res3, res2, finalcipher->secondcomp);

    // ((cipher->firstcomp ^ p - privateKey - 1) % p) * cipher->secondcomp) % p
    mpz_mod(res3, res3, p);

    //Copy the contents out
    //mpz_init_set(out, res3);
    int output = 0;

    for(int i = 0; i < PRECOMP; i++)
    {
        int p = mpz_cmp(values[i],res3);
        if (p == 0) {
            output = i;
            break;
        }
    }

    if (output !=0 ) {
        printf("Total sum of %d encrypted values = %d\n", NUM, output);
    } else {
        printf("The value is beyond the scope of the Precomputed Values\n");
    }

    mpz_clear(res1);
    mpz_clear(res2);
    mpz_clear(res3);
}

int main() {
    mpz_t p,g,q;

    unsigned long int r = 5;

    mpz_init_set_str(p, "141103728801468755249503291901801300339454489134873273269161807133184957725631203791969744406992490029017308434294093310271973777802513443575042969796895750747614660497411432558300476234836462151925376765365205539666438199705555483194413832902302373511490858360959114097755447464088887287145428704637498873563", 0);
    mpz_init_set_str(g, "105861658449903670398842707812938888531601091401355008230876634024010937268870331311638117904636173888707058855182778532622385692236892785716421644114344195029162371175818169381366740838052666046929986716700970629216177653754852315554730008499152818656193522542478412787555437975470969140718764372166206582283", 0);
    mpz_init_set_str(q, "783294875021436409578654247252215361374348380322356315904524998417053527857380", 0);

    //unsigned long int plaintext = 11689;
        
    clock_t start = clock();
    mpz_t values[PRECOMP];
    genPreComputedValues(g, p, PRECOMP, values);
    clock_t end = clock();
    double cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("Precomputation for %d values took %f seconds to execute \n", PRECOMP, cpu_time_used);

    /*    
    gmp_printf("P = %Zd\n", p);
    gmp_printf("G = %Zd\n", g);
    gmp_printf("Q = %Zd\n", q);
    */

    Users U[NUM];
    genKeyPair(U, NUM, p, g);

    srand(time(NULL));   // Initialization, should only be called once.

    //Generate random values for test purposes
    for (int i = 0; i < NUM; i ++) {
        U[i].plaintext = rand() % 1500; 
        //printf("%ld\n", U[i].plaintext);
    }
    
    unsigned long int sum = U[0].plaintext;
     for (int i = 1; i < NUM; i ++) {
        sum = sum + U[i].plaintext; 
    }
    printf("Total sum of %d plaintext values is = %ld\n", NUM, sum);

    mpz_t msk;
    addKeys(NUM, U, msk);
    //gmp_printf("MSK: %Zd\n", msk);

    Ciphertext cipher[NUM];
    HE_Encrypt(cipher, U, g, p, r, NUM);

    Ciphertext t_cipher;
    addCipher(NUM, &t_cipher, cipher, g, p, r);

    //gmp_printf("C1.1: %Zd\n", t_cipher.firstcomp);
    //gmp_printf("C1.2: %Zd\n", t_cipher.secondcomp);

    FE_decrypt(&t_cipher, msk, p, values);

    return 1;

}

