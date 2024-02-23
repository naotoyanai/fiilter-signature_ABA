#include <bits/stdc++.h>
#include <time.h>
#include <unistd.h>
#include <chrono>
#include <random>
#include <ratio>
#include "./ModifiedCuckooFilter/src/cuckoofilter.h"
#include "vacuum.h"
#include "hashutil.h"

#include <sodium.h> /* g++ opition: -lsodium */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/time.h>
#include <sys/resource.h>

#define MESSAGE (const unsigned char *) "test"
#define MESSAGE_LEN 5

int n = 1000000; /* number of inserted keys --> the size of Dv */
int q = 10000000; /* number of queries */ 
int slots = 8; /* slots per backets */
int max_kick = 400; /* max kick steps */

using namespace std;

/* generate n 64-bit random numbers */
void random_gen(int n, vector<uint64_t>& store, mt19937& rd) {
    store.resize(n);
    for (int i = 0; i < n; i++)
        store[i] = (uint64_t(rd()) << 32) + rd();
}


void test_vf_no_padding() { /* Vacuum from scratch */

    /*
        We implemented VF_no_padding from scratch.
        It supports fingerprint length from 4 to 16 bits, but we recommend to use fingerprint longer than 8 bits.
        This version aims at flexibility, so it is slower than VF_with_padding.
    */
    struct rusage setup_start, setup_end, keygen_start, keygen_end, 
        sign_start, sign_end, vrfy_start, vrfy_end;
/*
    cout << "Testing vacuum filter(no padding)..." << endl;


    cout << "Keys number = " << n << endl;
    cout << "Queries number = " << q << endl;
*/
    mt19937 rd(12821);
    vector<uint64_t> insKey;
    vector<uint64_t> alienKey;

    VacuumFilter<uint16_t, 16> vf;

    /* Setup: Generation of Crypto keys */
/*
    getrusage(RUSAGE_SELF, &setup_start);
*/
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);
    unsigned char signed_message[crypto_sign_BYTES + MESSAGE_LEN];
    unsigned long long signed_message_len;
/*
    getrusage(RUSAGE_SELF, &setup_end);
    printf("%s\n", MESSAGE);
*/


    /* KeyGen */
/*
    getrusage(RUSAGE_SELF, &keygen_start);
*/
    random_gen(n, insKey, rd); /* unique value for uint64_t as vk_id */
    
/*
    getrusage(RUSAGE_SELF, &keygen_end);
*/
    /* Sign */ 
/*
    getrusage(RUSAGE_SELF, &sign_start);    
*/
    crypto_sign(signed_message, &signed_message_len, MESSAGE, MESSAGE_LEN, sk);
/*    printf("%s\n", signed_message); */

    
    vf.init(n, slots, max_kick); /* vf.init(max_item_numbers, slots per bucket, max_kick_steps) 
        --> Gen of Vacuum */

    for (int i = 0; i < n; i++)
        if (vf.insert(insKey[i]) == false)
            cout << "Insertion fails when inserting " << i << "th key: " << insKey[i] << endl;

    int T = static_cast<int>(vf.get_load_factor()) * 100;

    /* cast from AMQ to message as m||T 
    MESSAGE << T;
    */
/*
    getrusage(RUSAGE_SELF, &sign_end);
    cout << "Load factor = " << vf.get_load_factor() << endl;
*/

    /* Verify */
    getrusage(RUSAGE_SELF, &vrfy_start);
    unsigned char unsigned_message[MESSAGE_LEN];
    unsigned long long unsigned_message_len;

    if (crypto_sign_open(unsigned_message, &unsigned_message_len, signed_message, 
        signed_message_len, pk) != 0) { /* checking signature verification */
        printf("incorrect signature!\n");
        /* incorrect signature! */
    }

    for (int i = 0; i < n; i++) 
        if (vf.lookup(insKey[i]) == false) { /* checking insKey[i] by Lookup */
        /*
            cout << "False negative happens at " << i << "th key: " << insKey[i] << endl;
            printf("incrrect AMQ!\n");
            break;
        */
        }

    getrusage(RUSAGE_SELF, &vrfy_end);

/*
    printf("Setup (user-time) \n");
    printf("Setup (sys-time) \n");

    printf("KeyGen (user-time) \n");
    printf("KeyGen (sys-time) \n");

    printf("Sign (user-time) \n");
    printf("Sign (sys-time) \n");
    printf("Verify (user-time) \n");
    printf("Verify (sys-time) \n");
*/

/*
    printf("%lf\n",
        (setup_end.ru_utime.tv_sec  - setup_start.ru_utime.tv_sec) +
        (setup_end.ru_utime.tv_usec - setup_start.ru_utime.tv_usec)*1.0E-6
        );
    printf("%lf\n",
        (setup_end.ru_stime.tv_sec  - setup_start.ru_stime.tv_sec) +
        (setup_end.ru_stime.tv_usec - setup_start.ru_stime.tv_usec)*1.0E-6);

    printf("%lf\n",
        (keygen_end.ru_utime.tv_sec  - keygen_start.ru_utime.tv_sec) +
        (keygen_end.ru_utime.tv_usec - keygen_start.ru_utime.tv_usec)*1.0E-6);
    printf("%lf\n",
        (keygen_end.ru_stime.tv_sec  - keygen_start.ru_stime.tv_sec) +
        (keygen_end.ru_stime.tv_usec - keygen_start.ru_stime.tv_usec)*1.0E-6);

    printf("%lf\n",
        (sign_end.ru_utime.tv_sec  - sign_start.ru_utime.tv_sec) +
        (sign_end.ru_utime.tv_usec - sign_start.ru_utime.tv_usec)*1.0E-6);
    printf("%lf\n",
        (sign_end.ru_stime.tv_sec  - sign_start.ru_stime.tv_sec) +
        (sign_end.ru_stime.tv_usec - sign_start.ru_stime.tv_usec)*1.0E-6);
*/
    printf("%lf\n",
        (vrfy_end.ru_utime.tv_sec  - vrfy_start.ru_utime.tv_sec) +
        (vrfy_end.ru_utime.tv_usec - vrfy_start.ru_utime.tv_usec)*1.0E-6);
/*
    printf("%lf\n",
        (vrfy_end.ru_stime.tv_sec  - vrfy_start.ru_stime.tv_sec) +
        (vrfy_end.ru_stime.tv_usec - vrfy_start.ru_stime.tv_usec)*1.0E-6);
*/

/*
    int false_positive_cnt = 0;

    for (int i = 0; i < q; i++)
        if (vf.lookup(alienKey[i]) == true)
            false_positive_cnt++;

    cout << "False positive rate = " << double(false_positive_cnt) / q << endl;
    cout << "Bits per key = " << vf.get_bits_per_item() << endl;
*/
    cout << endl;
}


int main() {

    cout << "Keys number = " << n << endl;
    printf("Verify (user-time) \n");


    for (int k = 0; k < 5; k ++) {
        test_vf_no_padding();
    }
    /* 
    test_vf_with_padding();
    test_batch(); 
    */


/*
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    unsigned char signed_message[crypto_sign_BYTES + MESSAGE_LEN];
    unsigned long long signed_message_len;

    crypto_sign(signed_message, &signed_message_len,
            MESSAGE, MESSAGE_LEN, sk);

    printf("%s\n", signed_message);
    printf("%s\n", MESSAGE);
*/

    return 0;
}
