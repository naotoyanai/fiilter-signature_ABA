#pragma once
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
#include <iostream>

#include <sys/time.h>
#include <sys/resource.h>


#define MESSAGE (const unsigned char *) "test"
#define MESSAGE_LEN 32
int n = 100; /* number of users */
int j =100; /* test index in verification */

using namespace std;

/* generate n 64-bit random numbers */
void random_gen(int n, vector<uint64_t>& store, mt19937& rd) {
    store.resize(n);
    for (int i = 0; i < n; i++)
        store[i] = (uint64_t(rd()) << 32) + rd();
}


void test_vf_no_padding() { /* Vacuum from scratch */

    struct rusage setup_start, setup_end, keygen_start, keygen_end, 
        sign_start, sign_end, vrfy_start, vrfy_end;
    /*
        We implemented VF_no_padding from scratch.
        It supports fingerprint length from 4 to 16 bits, but we recommend to use fingerprint longer than 8 bits.
        This version aims at flexibility, so it is slower than VF_with_padding.
    */


    /* int n = 100; */ /* number of inserted keys --> the size of Dv */


    mt19937 rd(12821);
    vector<uint64_t> insKey;

    /*
    random_gen(n, insKey, rd);
    random_gen(q, alienKey, rd);
    */

    VacuumFilter<uint16_t, 16> vf;

    /* Setup: Generation of Crypto keys */

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    unsigned char signed_message[crypto_sign_BYTES + MESSAGE_LEN];
    unsigned long long signed_message_len;




    /* KeyGen */
    /*
    random_gen(n, insKey, rd); 
    random_gen(q, alienKey, rd);
    */


    /* Sign */ 

    random_gen(n, insKey, rd); /* Define Dv */
 
    unsigned char hash[crypto_generichash_BYTES];
    /*
    unsigned char value[sizeof(insKey)];
    */
    /* 
    std::cout << "debug before sizeof\n" << endl;
    */
    /* hash-and-sign paradigm for Signing on m||Dv */

    /* 
    for (int i=0; i <n; i++ ){
        std::memcpy(value,&insKey[i],sizeof(insKey[i]));
    }
    */ 
    
    /*     std::cout << "debug before hash\n" << endl; */
    /* original hash function 
    crypto_generichash(hash, sizeof hash, MESSAGE, MESSAGE_LEN, NULL, 0);
    */
    crypto_generichash(hash, sizeof hash, MESSAGE, MESSAGE_LEN, NULL, 0);
    /* delete[] value;    */

    crypto_sign(signed_message, &signed_message_len, MESSAGE, MESSAGE_LEN, sk);


    /* printDump(const unsigned char *buff, int length, unsigned char *copy) */

    /* original sign function
    crypto_sign(signed_message, &signed_message_len, MESSAGE, MESSAGE_LEN, sk);
    std::cout << "cout: " << hash << endl;
    printf("hash output::: %s::%s\n", print_hex(hash, sizeof hash), MESSAGE);

    */


    int T = static_cast<int>(vf.get_load_factor()) * 100;




    /* Verify */


    getrusage(RUSAGE_SELF, &vrfy_start);
    unsigned char unsigned_message[MESSAGE_LEN];
    unsigned long long unsigned_message_len;

    for (int i = 0; i < n; i++)
        if (insKey[i] == insKey[j])
            cout << endl;


    /* cout << "debug before crypto_sign_open\n" << endl; */
    if (crypto_sign_open(unsigned_message, &unsigned_message_len, signed_message, 
        signed_message_len, pk) != 0) { /* checking signature verification */
        printf("incorrect signature!\n");
        /* incorrect signature! */
    }


    /* cout << "debug before lookup\n" << endl; */

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

    cout << endl;
}


int main() {
    cout << "Testing trivial construction..." << endl;

    cout << "Keys number = " << n << endl;
    printf("Verify (user-time) \n");

    for (int k =0; k < 5; k++) {
        test_vf_no_padding();
    }


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
