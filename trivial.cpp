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

#define MESSAGE (const unsigned char *) "test"
#define MESSAGE_LEN 32



using namespace std;

/* generate n 64-bit random numbers */
void random_gen(int n, vector<uint64_t>& store, mt19937& rd) {
    store.resize(n);
    for (int i = 0; i < n; i++)
        store[i] = (uint64_t(rd()) << 32) + rd();
}

/* generate n 64-bit random numbers */
void random_gen_1(int n, uint64_t** store, mt19937& rd) {
    *store = new uint64_t[n + 128];
    for (int i = 0; i < n; i++)
        (*store)[i] = (uint64_t(rd()) << 32) + rd();
}

/* copy a set of identifiers to a single array, Dv */
static void printDump(const unsigned char *buff, int length, unsigned char *copy)
{
    int i;

    for (i = 0; i < length; i++) {
        copy[i] = buff[i];
        /* printf("%02x", (buff[i] & 0x000000ff)); for debug */
    }
}

void test_vf_no_padding() { /* Vacuum from scratch */

    /*
        We implemented VF_no_padding from scratch.
        It supports fingerprint length from 4 to 16 bits, but we recommend to use fingerprint longer than 8 bits.
        This version aims at flexibility, so it is slower than VF_with_padding.
    */

    cout << "Testing vacuum filter(no padding)..." << endl;

    int n = 100; /* number of inserted keys --> the size of Dv */
    int q = 10000000; /* number of queries */ 

    cout << "Keys number = " << n << endl;
    cout << "Queries number = " << q << endl;

    mt19937 rd(12821);
    vector<uint64_t> insKey;
    vector<uint64_t> alienKey;
    
    random_gen(q, alienKey, rd);

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

    printf("%s\n", MESSAGE);


    /* KeyGen */
    /*
    random_gen(n, insKey, rd); 
    random_gen(q, alienKey, rd);
    */

    random_gen(n, insKey, rd); /* Define Dv */

    /* Sign */ 



    unsigned char hash[crypto_generichash_BYTES];
    /*
    unsigned char value[sizeof(insKey)];
    */

    std::cout << "debug before sizeof\n" << endl;

    /* hash-and-sign paradigm for Signing on m||Dv */

    /* 
    for (int i=0; i <n; i++ ){
        std::memcpy(value,&insKey[i],sizeof(insKey[i]));
    }
    */ 
    std::cout << "debug after sizeof\n" << endl;
    
    std::cout << "debug before hash\n" << endl;
    /* original hash function 
    crypto_generichash(hash, sizeof hash, MESSAGE, MESSAGE_LEN, NULL, 0);
    */
    crypto_generichash(hash, sizeof hash, MESSAGE, MESSAGE_LEN, NULL, 0);
    std::cout << "debug after hash\n" << endl;
    /* delete[] value;    */

    std::cout << "debug before sign\n" << endl;
    crypto_sign(signed_message, &signed_message_len, MESSAGE, MESSAGE_LEN, sk);
    std::cout << "debug after sign\n" << endl;

    /* printDump(const unsigned char *buff, int length, unsigned char *copy) */

    /* original sign function
    crypto_sign(signed_message, &signed_message_len, MESSAGE, MESSAGE_LEN, sk);
    std::cout << "cout: " << hash << endl;
    printf("hash output::: %s::%s\n", print_hex(hash, sizeof hash), MESSAGE);

    */


    vf.init(n, 4, 400); 

    for (int i = 0; i < n; i++)
        if (vf.insert(insKey[i]) == false)
            cout << "Insertion fails when inserting " << i << "th key: " << insKey[i] << endl;

    int T = static_cast<int>(vf.get_load_factor()) * 100;
    printf("T: %d\n", T); /* for debug */

    /* cast from AMQ to message as m||T 
    MESSAGE << T;
    */
    cout << "Load factor = " << vf.get_load_factor() << endl;


    /* Verify */

    unsigned char unsigned_message[MESSAGE_LEN];
    unsigned long long unsigned_message_len;

    cout << "debug before crypto_sign_open\n" << endl;
    if (crypto_sign_open(unsigned_message, &unsigned_message_len, signed_message, 
        signed_message_len, pk) != 0) { /* checking signature verification */
        printf("incorrect signature!\n");
        /* incorrect signature! */
    }


    cout << "debug before lookup\n" << endl;

    for (int i = 0; i < n; i++) 
        if (vf.lookup(insKey[i]) == false) { /* checking insKey[i] by Lookup */
            cout << "False negative happens at " << i << "th key: " << insKey[i] << endl;
            printf("incrrect AMQ!\n");
            break;
        }
    
    int false_positive_cnt = 0;

    for (int i = 0; i < q; i++)
        if (vf.lookup(alienKey[i]) == true)
            false_positive_cnt++;

    cout << "False positive rate = " << double(false_positive_cnt) / q << endl;
    cout << "Bits per key = " << vf.get_bits_per_item() << endl;

    for (int i = 0; i < n; i++)
        if (vf.del(insKey[i]) == false)
            cout << "Deletion fails when inserting " << i << "th key: " << insKey[i] << endl;

    cout << endl;
}


int main() {
    test_vf_no_padding();


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
