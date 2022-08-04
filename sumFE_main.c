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

void FE_decrypt(Ciphertext *finalcipher, mpz_t msk, mpz_t p, mpz_t *values, mpz_t k) {
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
    //mpz_mul(res3, res2, finalcipher->secondcomp);
    mpz_mul(res3, res2, k);                             //Test with Light version

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
    mpz_t p,g,q,c,k;

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
    //printf("Total sum of %d plaintext values is = %ld\n", NUM, sum);

    mpz_t msk;
    addKeys(NUM, U, msk);
    //gmp_printf("MSK: %Zd\n", msk);

    Ciphertext cipher[NUM];
    HE_Encrypt(cipher, U, g, p, r, NUM);

    Ciphertext t_cipher;
    addCipher(NUM, &t_cipher, cipher, g, p, r);

    //gmp_printf("C1.1: %Zd\n", t_cipher.firstcomp);
    //gmp_printf("C1.2: %Zd\n", t_cipher.secondcomp);

    //Test out values from the Light version
    mpz_init_set_str(c, "379528334058105121016034627665760025705129029319027921610005106020260711583476868454627687009430235907583039616987061308812579210578458186535349828049658670869435673894786680436261636919906565210530894798722431320062542276063575020431118576969422223839439113144576617755153978418354762239712988265793918947873296842274682978144546788834536644579609037958595857198384736738051851946060730182090944302911260816515785953634647009967784300914301241793153379285736621527634829191359310886467344760846193681482170193132363373225515238070189774373099780748796471977395378806237467886853183740311588104546424885878483835780396406068244926225680919990998438371606844059271121715337261038229028483733533436017492697211532587736668079361534712962087586175483755424302709104262087976197465041471551791416207611867015560833825464683097753090173656339114946517527760550193696013967010943847203972346651469623719464722661290278367171482652721583426404110518102472393495112600635847818894727400640720173188874375767038528633571325859933708730109575166387066576649187853806636871273400255171507012142905877849262422714413438698254420010574239142856470112037002726567622285297032175440075267096346034006984620011710301337272387685228200174542224437594597025022899270818093460941224588059297571722827369144428213740881427253417317728663653729054180609220149593932272985323589621665955321649920543902654944632192526019593175724464143344589672275058635602602931724760252675606260990008738323738201966071582889838155519415922021431905486039515906828721443026160", 0);
    mpz_init_set_str(k, "2822074576029375104990065838036026006789089782697465465383236142663699154512624075839394888139849800580346168685881866205439475556050268871500859395937915014952293209948228651166009524696729243038507535307304110793328763994111109663888276658046047470229817167219182281955108949281777745742908574092749977471270", 0);

    //FE_decrypt(&t_cipher, msk, p, values);
    FE_decrypt(&t_cipher, k, p, values, c);         //Check out the encrypted values from the Light version

    return 1;

}

