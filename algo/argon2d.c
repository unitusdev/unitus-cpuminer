#include "miner.h"
#include "compat.h"

#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdlib.h>

#include "algo/argon2/argon2.h"

int scanhash_argon2d(int thr_id, uint32_t *pdata, const uint32_t *ptarget, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(64) vhash[8];
	uint32_t _ALIGN(64) endiandata[20];

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];

	uint32_t n = first_nonce;
    
    uint32_t t_cost = 1; // 1 iteration
    uint32_t m_cost = 4096; // use 4MB
    uint32_t parallelism = 1; // 1 thread, 2 lanes

	for (int i=0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	}

	do {
		be32enc(&endiandata[19], n);
        argon2d_hash_raw(t_cost, m_cost, parallelism, (char*) endiandata, 80, (char*) endiandata, 80, (char*) vhash, 32);
		if (vhash[7] < Htarg && fulltest(vhash, ptarget)) {
			*hashes_done = n - first_nonce + 1;
			pdata[19] = n;
			return true;
		}
		n++;

	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;

	return 0;
}
