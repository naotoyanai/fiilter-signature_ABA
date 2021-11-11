#include "cuckoofilter.h"

#include <assert.h>
#include <math.h>
#include <stdio.h>

#include <openssl/sha.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/hmac.h>
#include <openssl/opensslconf.h>

#include <iostream>
#include <vector>


using cuckoofilter::CuckooFilter;

int N=10; /* Num. of devices */
int User = 5; /* Num. of users in List */
int sec_lev = 32;

const char *command = {"Command Message"}; /* command for Auth*/
const char *command_ver = {"Command Message"}; /* command for Vrfy */


/* definition of device info. */
struct device_info {
    unsigned char id[32];        /*  device name */
    unsigned char name[32];
    char keyy[EVP_MAX_MD_SIZE]; /* key y_id */
    char keyr[EVP_MAX_MD_SIZE]; /* key r_id */
    char keyk[EVP_MAX_MD_SIZE]; /* key K_id */
};


int main(int argc, char **argv) {
  size_t total_items = 1000000;

  /* Create a cuckoo filter where each item is of type size_t and 
  // use 12 bits for each item:
  //    CuckooFilter<size_t, 12> filter(total_items);
  // To enable semi-sorting, define the storage of cuckoo filter to be
  // PackedTable, accepting keys of size_t type and making 13 bits
  // for each key:
  //   CuckooFilter<size_t, 13, cuckoofilter::PackedTable> filter(total_items); */
  CuckooFilter<size_t, 12> filter(total_items);

  /* Insert items to this cuckoo filter */
  size_t num_inserted = 0;
  for (size_t i = 0; i < total_items; i++, num_inserted++) {
    if (filter.Add(i) != cuckoofilter::Ok) {
      break;
    }
  }




  /* Check if previously inserted items are in the filter, expected
  // true for all items */
  for (size_t i = 0; i < num_inserted; i++) {
    assert(filter.Contain(i) == cuckoofilter::Ok);
  }

  /* Check non-existing items, a few false positives expected */
  size_t total_queries = 0;
  size_t false_queries = 0;
  for (size_t i = total_items; i < 2 * total_items; i++) {
    if (filter.Contain(i) == cuckoofilter::Ok) {
      false_queries++;
    }
    total_queries++;
  }

  /* Output the measured false positive rate */
  std::cout << "false positive rate is "
            << 100.0 * false_queries / total_queries << "%\n";

  printf("test\n ");

  return 0;
}
