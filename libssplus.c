/*
 * Copyright 2016 Mikeqin <Fengling.Qin@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "sha2.h"

#include "libssplus.h"

#define INSTRUCTIONS_RAM_START	0x42000000
#define INSTRUCTIONS_RAM_SIZE	(1 << 16)
#define POINTS_RAM_START	0xfffc0000
#define POINTS_RAM_SIZE	(256 << 10)

/* hasher instructions */
#define INST_DONE	0x00040000
#define INST_DATA_IRAM	0x0
#define INST_DATA_LASTHASH_PAD	0x14000000
#define INST_DATA_LASTHASH_IRAM	0x10000000
#define INST_DATA_PAD512	0x26000000
#define INST_MID_INIT	0x0
#define INST_MID_LASTHASH	0x100000

#define NEXT_ADDR(x)	(((x) & 0x1ff) << 8)

#define UNPACK32(x, str)			\
{						\
	*((str) + 3) = (uint8_t) ((x)      );	\
	*((str) + 2) = (uint8_t) ((x) >>  8);	\
	*((str) + 1) = (uint8_t) ((x) >> 16);	\
	*((str) + 0) = (uint8_t) ((x) >> 24);	\
}

#define SORTER_DEBUG

struct ssp_hasher_instruction {
	uint32_t opcode;
	uint8_t data[64];
};

struct ssp_point {
	uint32_t nonce2;
	uint32_t tail;
};

struct ssp_info {
	pthread_t hasher_thr;
	pthread_mutex_t hasher_lock;
	volatile uint32_t *iram_addr;
	volatile uint64_t *pram_addr;
	bool stratum_update;
	bool run;
};

struct ssp_pair_element {
	uint32_t nonce2[2];
	struct ssp_pair_element *next;
};

struct ssp_hashtable {
	struct ssp_point *cells;
	uint32_t size;
	uint32_t max_size;  /* must be powers of 2 */
	uint32_t limit;  /* probing limit */
	uint32_t c1;
	uint32_t c2;
};

static struct ssp_info sspinfo;
static struct ssp_hashtable *ssp_ht = NULL;
static struct ssp_pair_element *ssp_pair_head = NULL;
static struct ssp_pair_element *ssp_pair_tail = NULL;

#ifdef SORTER_DEBUG
static uint32_t pair_count = 0;
static uint32_t consumed = 0;
static uint32_t discarded = 0;
static uint32_t calls = 0;
static struct timeval ssp_ti, ssp_tf;
static double insert_time = .0;

static uint32_t maxnonce = 0;
static uint32_t ver = 0;
#endif

static void ssp_sorter_insert(const struct ssp_point *point)
{
	uint32_t i;
	uint32_t key;

#ifdef SORTER_DEBUG
	if (calls == 0xffffffff)
		applog(LOG_NOTICE, "calls overflow");
	calls++;
#endif

	for (i = 0; i < ssp_ht->limit; i++) {
		key = (point->tail + ssp_ht->c1 * i + ssp_ht->c2 * i * i) %
			(ssp_ht->max_size);
		if (ssp_ht->cells[key].nonce2 == 0 && ssp_ht->cells[key].tail == 0) {
			/* insert */
			ssp_ht->cells[key].tail = point->tail;
			ssp_ht->cells[key].nonce2 = point->nonce2;
			ssp_ht->size++;
			goto out;
		}
		if (ssp_ht->cells[key].tail == point->tail) {
			/* get a collision */
			ssp_pair_tail->nonce2[0] = point->nonce2;
			ssp_pair_tail->nonce2[1] = ssp_ht->cells[key].nonce2;
			ssp_pair_tail->next = (struct ssp_pair_element *)cgmalloc(sizeof(struct ssp_pair_element));
			ssp_pair_tail = ssp_pair_tail->next;
#ifdef SORTER_DEBUG
			pair_count++;
#endif

			/* update nonce2 of the point */
			ssp_ht->cells[key].nonce2 = 0;
			ssp_ht->cells[key].tail = 0;
			/* or just delete it? */
			/* or leave it be? */
			goto out;
		}
	}

	/* discard */
#ifdef SORTER_DEBUG
	discarded++;
#endif
out:
	return;
}

void ssp_sorter_init(uint32_t max_size, uint32_t limit, uint32_t c1, uint32_t c2)
{
#ifdef SORTER_DEBUG
	cgtime(&ssp_ti);
#endif

	ssp_ht = (struct ssp_hashtable *)cgmalloc(sizeof(struct ssp_hashtable));

	ssp_ht->max_size = max_size;
	ssp_ht->limit = limit;
	ssp_ht->c1 = c1;
	ssp_ht->c2 = c2;
	ssp_ht->size = 0;
	ssp_ht->cells = (struct ssp_point *)cgmalloc(sizeof(struct ssp_point) * max_size);
	memset(ssp_ht->cells, 0, sizeof(struct ssp_point) * max_size);

	ssp_pair_head = (struct ssp_pair_element *)cgmalloc(sizeof(struct ssp_pair_element));
	ssp_pair_tail = ssp_pair_head;
}

void ssp_sorter_flush(void)
{
#ifdef SORTER_DEBUG
	double delta_t;

	cgtime(&ssp_tf);
	delta_t = tdiff(&ssp_tf, &ssp_ti);

	applog(LOG_NOTICE, "Stratum %d: %f s", ver, delta_t);
	applog(LOG_NOTICE, "Stratum %d: get %d pairs. %f pair/s", ver, pair_count, pair_count / delta_t);
	applog(LOG_NOTICE, "Stratum %d: consume %d pairs. %f pair/s", ver, consumed, consumed / delta_t);
	applog(LOG_NOTICE, "Stratum %d: discard %d points. %f point/s", ver, discarded, discarded / delta_t);
	applog(LOG_NOTICE, "Stratum %d: reading discards %d points. %f point/s. %.2f%%", ver, maxnonce - calls, (maxnonce - calls) / delta_t, (maxnonce - calls) * 1.0 / maxnonce * 100);
	applog(LOG_NOTICE, "Stratum %d: record %d points. %f%% of hashtable. %f point/s", ver, ssp_ht->size, ssp_ht->size * 100.0 / ssp_ht->max_size, ssp_ht->size / delta_t);
	applog(LOG_NOTICE, "Stratum %d: %d calls of sorter_insert. %f call/s", ver, calls, calls / delta_t);
	applog(LOG_NOTICE, "Stratum %d: avg call time - %f us", ver, delta_t * 1000000 / calls);
	applog(LOG_NOTICE, "Stratum %d: k^2 / 2N / pair - %f", ver, 0.5 * calls * calls / 4294967296 / pair_count);
	applog(LOG_NOTICE, "========================================================");

	cgtime(&ssp_ti);
	pair_count = 0;
	consumed = 0;
	discarded = 0;
	calls = 0;
	insert_time = 0;
	ver++;
#endif

	ssp_ht->size = 0;
	memset(ssp_ht->cells, 0, sizeof(struct ssp_point) * ssp_ht->max_size);

	/* MM only use one stratum, we need drop all pairs */
	while (ssp_pair_head != ssp_pair_tail) {
		struct ssp_pair_element *tmp;

		tmp = ssp_pair_head;
		ssp_pair_head = tmp->next;
		free(tmp);
	}
}

int ssp_sorter_get_pair(ssp_pair pair)
{
	struct ssp_pair_element *tmp;

	if (ssp_pair_head == ssp_pair_tail)
		return 0;

	mutex_lock(&(sspinfo.hasher_lock));

	tmp = ssp_pair_head;
	pair[0] = tmp->nonce2[0];
	pair[1] = tmp->nonce2[1];

	ssp_pair_head = tmp->next;
	free(tmp);
#ifdef SORTER_DEBUG
	consumed++;
#endif
	mutex_unlock(&(sspinfo.hasher_lock));
	return 1;
}

static void *ssp_hasher_thread(void *userdata)
{
	uint32_t last_nonce2 = 0, point_index = 0, nonce2;
	bool valid_nonce2 = false;
	struct ssp_info *p_ssp_info = (struct ssp_info *)userdata;

	while (1) {
		mutex_lock(&(sspinfo.hasher_lock));

		if (!p_ssp_info->run)
			valid_nonce2 = false;

		if (p_ssp_info->stratum_update) {
			p_ssp_info->stratum_update = false;
			point_index = 0;
			last_nonce2 = 0;
			valid_nonce2 = false;
			ssp_sorter_flush();
			applog(LOG_NOTICE, "libssplus: stratum update");
		}

		/* Note: hasher is fast enough, so the new job will start with a lower nonce2 */
		nonce2 = (sspinfo.pram_addr[point_index] & 0xffffffff);
		if (last_nonce2 > nonce2) {
			applog(LOG_DEBUG, "libssplus: last nonce2 %08x, valid nonce2 %08x", last_nonce2, nonce2);
			valid_nonce2 = true;
		}

		applog(LOG_DEBUG, "(%08x -> %08llx)",
				nonce2,
				sspinfo.pram_addr[point_index] >> 32);

		point_index = (point_index + 1) % (POINTS_RAM_SIZE / sizeof(struct ssp_point));
		if (valid_nonce2) {
#ifdef SORTER_DEBUG
			if (nonce2 > maxnonce)
				maxnonce = nonce2;
#endif
			ssp_sorter_insert((struct ssp_point *)&sspinfo.pram_addr[point_index]);
		}
		last_nonce2 = nonce2;

		mutex_unlock(&(sspinfo.hasher_lock));
	}
	return NULL;
}

static inline void ssp_haser_fill_iram(struct ssp_hasher_instruction *p_inst, uint32_t inst_index)
{
	uint8_t i;
	volatile uint32_t *p_iram_addr;
	uint32_t tmp;

	p_iram_addr = sspinfo.iram_addr + inst_index * 32;
	p_iram_addr[0] = p_inst->opcode;
	simplelog(LOG_DEBUG, "iram[%d*32+0] = 0x%08x;", inst_index, p_inst->opcode);

	for (i = 0; i < 16; i++) {
		tmp = ((p_inst->data[i * 4 + 0] << 24) |
			(p_inst->data[i * 4 + 1] << 16) |
			(p_inst->data[i * 4 + 2] << 8) |
			(p_inst->data[i * 4 + 3]));
		p_iram_addr[i + 1] = tmp;
		simplelog(LOG_DEBUG, "iram[%d*32+%d] = 0x%08x;", inst_index, i + 1, tmp);
	}
	p_iram_addr[i + 1] = 0x1; /* flush */
	simplelog(LOG_DEBUG, "iram[%d*32+%d] = 1;", inst_index, i + 1);
}

static inline void ssp_hasher_stop(void)
{
	sspinfo.iram_addr[31] = 1;
	sspinfo.run = false;
}

static inline void ssp_hasher_start(void)
{
	sspinfo.iram_addr[31] = 0;
	sspinfo.run = true;
}

int ssp_hasher_init(void)
{
	int memfd;

	memfd = open("/dev/mem", O_RDWR | O_SYNC);
	if (memfd < 0) {
		applog(LOG_ERR, "libssplus: failed open /dev/mem");
		return 1;
	}

	sspinfo.iram_addr = (volatile uint32_t *)mmap(NULL, INSTRUCTIONS_RAM_SIZE,
						PROT_READ | PROT_WRITE,
						MAP_SHARED, memfd,
						INSTRUCTIONS_RAM_START);
	if (sspinfo.iram_addr == MAP_FAILED) {
		close(memfd);
		applog(LOG_ERR, "libssplus: mmap instructions ram failed");
		return 1;
	}

	sspinfo.pram_addr = (volatile uint64_t *)mmap(NULL, POINTS_RAM_SIZE,
						PROT_READ | PROT_WRITE,
						MAP_SHARED, memfd,
						POINTS_RAM_START);
	if (sspinfo.pram_addr == MAP_FAILED) {
		close(memfd);
		applog(LOG_ERR, "libssplus: mmap points ram failed");
		return 1;
	}
	close(memfd);

	if (pthread_create(&(sspinfo.hasher_thr), NULL, ssp_hasher_thread, &sspinfo)) {
		applog(LOG_ERR, "libssplus: create thread failed");
		return 1;
	}

	sspinfo.stratum_update = false;
	ssp_hasher_stop();
	mutex_init(&sspinfo.hasher_lock);

	return 0;
}

static inline void sha256_prehash(const unsigned char *message, unsigned int len, unsigned char *digest)
{
	int i;
	sha256_ctx ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, message, len);

	for (i = 0; i < 8; i++)
		UNPACK32(ctx.h[i], &digest[i << 2]);
}

void ssp_hasher_update_stratum(struct pool *pool, bool clean)
{
	struct ssp_hasher_instruction inst;
	uint32_t coinbase_len_posthash, coinbase_len_prehash;
	uint32_t i, len_rem, block_nb;
	int merkle_index;
	uint32_t inst_index = 0, nonce2_init = 0;
	uint64_t coinbase_len_bits = pool->coinbase_len * 8;

	mutex_lock(&(sspinfo.hasher_lock));

	ssp_hasher_stop();
	/* instruction init */
	inst.opcode = 0;
	memset(inst.data, 0, SHA256_BLOCK_SIZE);
	inst.data[28] = (nonce2_init >> 24) & 0xff;
	inst.data[29] = (nonce2_init >> 16) & 0xff;
	inst.data[30] = (nonce2_init >> 8) & 0xff;
	inst.data[31] = (nonce2_init) & 0xff;

	coinbase_len_prehash = pool->nonce2_offset - (pool->nonce2_offset % SHA256_BLOCK_SIZE);
	sha256_prehash(pool->coinbase, coinbase_len_prehash, inst.data + 32);
	ssp_haser_fill_iram(&inst, inst_index);
	inst_index++;

	/* coinbase */
	coinbase_len_posthash = pool->coinbase_len - coinbase_len_prehash;
	block_nb = coinbase_len_posthash / SHA256_BLOCK_SIZE;
	len_rem = (coinbase_len_posthash % SHA256_BLOCK_SIZE);
	for (i = 0; i < block_nb; i++) {
		inst.opcode = INST_DATA_IRAM | NEXT_ADDR(inst_index + 1);
		if (!i) {
			inst.opcode |= (63 - (pool->nonce2_offset % SHA256_BLOCK_SIZE));
			inst.opcode |= INST_MID_INIT;
		} else
			inst.opcode |= INST_MID_LASTHASH;
		memcpy(inst.data, pool->coinbase + coinbase_len_prehash + i * SHA256_BLOCK_SIZE, SHA256_BLOCK_SIZE);
		ssp_haser_fill_iram(&inst, inst_index);
		inst_index++;
	}

	memset(inst.data, 0, SHA256_BLOCK_SIZE);
	inst.opcode = INST_DATA_IRAM | NEXT_ADDR(inst_index + 1);
	if (!block_nb) {
		inst.opcode |= (63 - (pool->nonce2_offset % SHA256_BLOCK_SIZE));
		inst.opcode |= INST_MID_INIT;
	} else
		inst.opcode |= INST_MID_LASTHASH;
	memcpy(inst.data, pool->coinbase + coinbase_len_prehash + (block_nb * SHA256_BLOCK_SIZE), len_rem);
	inst.data[len_rem] = 0x80;

	if (len_rem <= (SHA256_BLOCK_SIZE - 9)) {
		for (i = 0; i < 8; i++)
			inst.data[63 - i] = (coinbase_len_bits >> (i * 8)) & 0xff;
		ssp_haser_fill_iram(&inst, inst_index);
		inst_index++;
	} else {
		ssp_haser_fill_iram(&inst, inst_index);
		inst_index++;

		memset(inst.data, 0, SHA256_BLOCK_SIZE);
		inst.opcode = INST_DATA_IRAM | NEXT_ADDR(inst_index + 1);
		inst.opcode |= INST_MID_LASTHASH;
		for (i = 0; i < 8; i++)
			inst.data[63 - i] = (coinbase_len_bits >> (i * 8)) & 0xff;
		ssp_haser_fill_iram(&inst, inst_index);
		inst_index++;
	}

	/* double hash coinbase */
	inst.opcode = INST_DATA_LASTHASH_PAD | INST_MID_INIT | NEXT_ADDR(inst_index + 1);
	memset(inst.data, 0, SHA256_BLOCK_SIZE);
	ssp_haser_fill_iram(&inst, inst_index);
	inst_index++;

	/* merkle branches */
	for (merkle_index = 0; merkle_index < pool->merkles; merkle_index++) {
		inst.opcode = INST_DATA_LASTHASH_IRAM | INST_MID_INIT | NEXT_ADDR(inst_index + 1);
		memcpy(inst.data + 32, pool->swork.merkle_bin[merkle_index], 32);
		ssp_haser_fill_iram(&inst, inst_index);
		inst_index++;

		inst.opcode = INST_DATA_PAD512 | INST_MID_LASTHASH | NEXT_ADDR(inst_index + 1);
		memset(inst.data, 0, SHA256_BLOCK_SIZE);
		ssp_haser_fill_iram(&inst, inst_index);
		inst_index++;

		inst.opcode = INST_DATA_LASTHASH_PAD | INST_MID_INIT | NEXT_ADDR(inst_index + 1);
		memset(inst.data, 0, SHA256_BLOCK_SIZE);
		ssp_haser_fill_iram(&inst, inst_index);
		inst_index++;
	}

	/* done */
	inst.opcode = INST_DONE;
	ssp_haser_fill_iram(&inst, inst_index);

	sspinfo.stratum_update = true;
	ssp_hasher_start();
	mutex_unlock(&(sspinfo.hasher_lock));
}

#define TESTCASE3
void ssp_hasher_test(void)
{
	struct pool test_pool;
	struct timeval t_start, t_find_pair;
	ssp_pair pair;
	int i;
	double pair_diff;

#ifdef TESTCASE1
	/* nonce2 4 bytes without block_nb */
	unsigned char coinbase[] = {
		0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0x64,0x03,0x85,0xc3,0x06,0x37,0xe4,0xb8,0x83,0xe5,0xbd,0xa9,0xe7,0xa5,0x9e,0xe4,0xbb,0x99,0xe9,0xb1,0xbc,0x17,0x60,
		0xcb,0x03,0x29,0xf4,0xa7,0x98,0x99,0xde,0x10,0x87,0xd1,0x01,0xc6,0x1e,0x7a,0x1f,0x0f,0x25,0xc0,0xec,0xc4,0x74,0x65,0x8c,0x69,0x7c,0x78,0x79,0xa4,0x7a,0x02,0x00,
		0x00,0x00,0xf0,0x9f,0x90,0x9f,0x14,0x4d,0x69,0x6e,0x65,0x64,0x20,0x62,0x79,0x20,0x71,0x69,0x6e,0x66,0x65,0x6e,0x67,0x6c,0x69,0x6e,0x67,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x5d,0xcc,0xe0,0x4b,0x00,0x00,0x00,0x00,0x19,0x76,0xa9,0x14,0xc8,
		0x25,0xa1,0xec,0xf2,0xa6,0x83,0x0c,0x44,0x01,0x62,0x0c,0x3a,0x16,0xf1,0x99,0x50,0x57,0xc2,0xab,0x88,0xac,0xa0,0x60,0x82,0x2f
	};

	unsigned char merkle_branches[][32] = {
		{0x0d,0x44,0xd1,0xab,0xc4,0x1e,0x2f,0xed,0x72,0xa7,0x46,0xc9,0x68,0x31,0xbd,0x98,0x60,0xe5,0x32,0x6c,0x96,0xf0,0xe8,0x97,0x72,0xf4,0x59,0x0e,0x0c,0x36,0xd9,0x7c},
		{0x10,0x24,0x76,0x6d,0xde,0x67,0xdf,0x66,0x54,0xa8,0xac,0x19,0x8d,0x9d,0xf2,0x45,0xea,0x74,0x60,0x2d,0x0d,0xb7,0xa6,0x34,0x5e,0x2d,0x51,0xe2,0x8a,0x8e,0xb1,0xf6},
		{0x2c,0x03,0x81,0x54,0xf9,0xfc,0xa7,0x7d,0xc8,0x09,0xcf,0xb4,0xc2,0x12,0x11,0xbe,0xbb,0x57,0x8d,0x4f,0x80,0x1f,0x78,0xce,0x5c,0x58,0x10,0xdb,0x03,0xb8,0x33,0xaa},
		{0x61,0xce,0xe4,0xd0,0xb9,0x85,0xf7,0xea,0xb2,0x57,0x39,0x16,0x24,0xb1,0x3d,0xf0,0xd0,0x09,0x65,0x75,0xb2,0xf5,0x95,0x63,0x4b,0x38,0xd8,0xcf,0x8a,0x36,0xe5,0xe9},
		{0x09,0xb4,0x42,0x7c,0xf6,0x18,0xa4,0xe4,0x18,0xd3,0xd1,0xa1,0xe0,0x47,0x7b,0x39,0x6f,0x7c,0x1d,0x70,0x00,0xed,0x07,0xc2,0xd6,0xc1,0x03,0x5b,0x93,0xe8,0x46,0xc6},
		{0x71,0xb0,0x09,0x2f,0x74,0xe9,0x3a,0x86,0x85,0xc6,0x8a,0x27,0xcd,0x2b,0x80,0x13,0xf9,0x4b,0x20,0xcd,0xdb,0x8f,0xfd,0xb2,0x28,0x2e,0x17,0x4f,0xc7,0xd8,0x83,0xd5},
		{0x27,0xc2,0x80,0x96,0xd7,0x8f,0x41,0xfb,0x18,0x2c,0x7c,0xe8,0xce,0x59,0x5a,0x81,0x3f,0x08,0xdb,0xbb,0x02,0xd2,0x43,0x99,0x18,0x04,0x0b,0x61,0x60,0x2f,0x5f,0xba},
		{0xe7,0xf8,0x8a,0x99,0xf3,0x50,0x3c,0xf7,0x81,0x3b,0x9e,0x7e,0xf9,0x6c,0x98,0x85,0x4a,0x67,0x07,0x08,0x61,0x8f,0xe3,0x8c,0x3d,0x78,0xc8,0xd0,0x0e,0x14,0x86,0xf9},
		{0x48,0x56,0x1c,0x47,0x35,0x49,0x4b,0xdb,0x5a,0x19,0xd5,0x27,0xe5,0x7e,0x52,0x59,0x2e,0xe8,0xab,0xae,0xa1,0xc9,0x3e,0x0b,0x09,0x06,0x70,0x81,0xb8,0x38,0xa9,0x22},
		{0x95,0x9c,0x26,0x49,0xa2,0xcc,0xd6,0x96,0x47,0x11,0x49,0xb8,0x31,0x44,0x17,0x01,0xeb,0x32,0xac,0x95,0x07,0xf6,0xd0,0x5c,0x7c,0x0e,0xf9,0x2a,0xd3,0xc2,0xfc,0x27},
	};

	test_pool.n2size = 4;
	test_pool.nonce2_offset = 142;
#endif
#ifdef TESTCASE2
	/* nonce2 4 bytes with block_nb */
	unsigned char coinbase[] = {
		0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0x45,0x03,0x0e,0x47,0x06,0xfa,0xbe,0x6d,0x6d,0x36,0xef,0x89,0xc9,0x76,0xd4,0xb8,0x75,0x52,0xf3,0x52,0x89,0x4a,0x26,
		0xd3,0x07,0x98,0x4b,0x28,0x1d,0x6e,0x3d,0x3a,0xa2,0xa8,0xc8,0x21,0x67,0x33,0x50,0x79,0x95,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xde,0xad,0xbe,0xef,0xca,0xfe,
		0xbe,0x00,0x00,0x00,0x00,0x10,0xe3,0x03,0x2f,0x73,0x6c,0x75,0x73,0x68,0x2f,0x00,0x00,0x00,0x00,0x01,0xeb,0xb9,0xed,0x97,0x00,0x00,0x00,0x00,0x19,0x76,0xa9,0x14,
		0x7c,0x15,0x4e,0xd1,0xdc,0x59,0x60,0x9e,0x3d,0x26,0xab,0xb2,0xdf,0x2e,0xa3,0xd5,0x87,0xcd,0x8c,0x41,0x88,0xac,0x00,0x00,0x00,0x00
	};

	unsigned char merkle_branches[][32] = {
		{0xf2,0xe1,0xd3,0x58,0x4d,0x02,0x24,0xfb,0x0b,0x7b,0x43,0xc8,0x87,0x41,0x3b,0xb6,0xab,0x3e,0xaf,0x5a,0x79,0x92,0x90,0xc2,0x56,0x9f,0x20,0xb5,0xfe,0x6b,0x0b,0x36},
		{0x36,0xb3,0xff,0xba,0x99,0xb8,0x9f,0xe4,0x0f,0xf3,0x21,0x64,0xf0,0xa1,0x19,0x86,0x0f,0x09,0x13,0x4c,0xe2,0x54,0x1e,0xff,0x38,0xc6,0xab,0x55,0xcc,0x58,0xd2,0xe4},
		{0x13,0xb1,0x66,0xdc,0x92,0x6f,0x3f,0x37,0xdb,0x30,0xec,0x4d,0x7b,0x37,0x38,0xac,0xf5,0x38,0xb6,0x4d,0x1f,0x11,0x6c,0xd2,0xee,0x84,0x5b,0xd2,0x15,0x62,0x99,0x78},
		{0x72,0x24,0xd0,0x31,0x90,0x4a,0x30,0xe0,0x7f,0x8d,0x41,0x48,0xa7,0x26,0x21,0xed,0xd3,0x47,0x0a,0xb7,0x38,0x52,0x0e,0xaf,0x65,0xab,0x3b,0xcd,0xf0,0x1c,0xeb,0x67},
		{0x81,0x85,0xe7,0x18,0x92,0xe5,0xf6,0xc5,0x05,0xba,0xe0,0xdb,0x45,0x45,0xfe,0x86,0x68,0x9a,0x11,0xb8,0x04,0x32,0x14,0x5c,0x72,0x1f,0xf9,0x6c,0xe5,0x26,0x86,0x0a},
		{0xea,0xff,0xbf,0x99,0x8f,0xfc,0x3c,0xa8,0x35,0x14,0x60,0x79,0xa3,0xdc,0x6c,0x97,0x3a,0xe7,0xb0,0xb9,0x64,0x69,0xc7,0x16,0x7b,0x17,0x12,0x46,0x87,0xdd,0x10,0x3f},
		{0x99,0x5a,0x04,0xf1,0x56,0xdf,0x6b,0x09,0x46,0xd2,0x65,0x23,0x6d,0x59,0xdf,0xeb,0xaa,0x60,0xda,0xd0,0x09,0xc3,0x22,0x56,0x14,0xf8,0xbd,0xd1,0x1c,0x74,0x7e,0x71},
		{0xf8,0x3f,0xe9,0x84,0x7c,0x0b,0x35,0x5e,0xfa,0x59,0x06,0x11,0xd2,0x82,0xd2,0x33,0x0b,0x28,0xd2,0x3d,0x18,0x4a,0x45,0x6d,0x05,0xff,0x5f,0x7b,0xaf,0x6a,0xda,0x81},
		{0x13,0xd7,0x5e,0xf4,0xda,0x4b,0x1a,0x2a,0xc9,0x42,0x19,0x7d,0x18,0x5e,0x93,0x4a,0xec,0x72,0x09,0xbc,0x95,0x2a,0xa2,0xdd,0xc6,0x77,0x4f,0xdb,0x1e,0x65,0x2c,0xd7},
		{0x85,0x6b,0x96,0xe8,0x56,0x3e,0xaa,0x9e,0x59,0x3a,0xa7,0xe0,0x29,0xc2,0xd4,0x01,0xc5,0x66,0xf7,0x8d,0x8e,0xf8,0x22,0xda,0xfe,0x79,0x5f,0x10,0x8a,0x59,0x8a,0x28},
		{0xce,0x79,0x63,0xa5,0x43,0xe1,0x00,0x18,0xf2,0x3e,0x3d,0xfd,0x52,0x01,0x17,0x55,0xe5,0xc8,0x47,0x37,0xa0,0xd0,0x86,0x51,0xb8,0x8c,0x89,0x56,0x71,0xf3,0x96,0x49},
		{0x88,0x73,0x89,0x13,0xa3,0xc7,0x3a,0xee,0x99,0x6c,0xc9,0xf5,0x76,0x0a,0xec,0x41,0xf6,0x97,0x99,0xd4,0x9b,0x09,0x36,0x4c,0x12,0xb3,0x6a,0x37,0x9c,0x18,0x42,0xef},
	};

	test_pool.n2size = 4;
	test_pool.nonce2_offset = 97;
#endif
#ifdef TESTCASE3
	/* nonce2 8 bytes */
	unsigned char coinbase[] = {
		0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0x31,0x03,0x18,0xc4,0x06,0x00,0x04,0xa6,0xfc,0x50,0x58,0x04,0x20,0xb8,0xb4,0x15,0x0c,0x62,0xa4,0x85,0x58,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x0a,0x63,0x6b,0x70,0x6f,0x6f,0x6c,0x0d,0x2f,0x4b,0x61,0x6e,0x6f,0x20,0x2f,0x42,0x45,0x42,0x4f,0x50,0x2f,0xff,0xff,0xff,0xff,0x02,
		0xe4,0xf2,0x64,0x4d,0x00,0x00,0x00,0x00,0x19,0x76,0xa9,0x14,0x1e,0xff,0xba,0x01,0xe0,0xc6,0x5d,0x69,0x44,0xe5,0x99,0x2e,0x7b,0xa5,0x3d,0x29,0xfc,0x02,0x05,0xca,
		0x88,0xac,0x9b,0xef,0xb3,0x00,0x00,0x00,0x00,0x00,0x19,0x76,0xa9,0x14,0x5d,0xdd,0xa1,0xc1,0x1c,0xe7,0xdf,0x66,0x81,0xcb,0x06,0x4c,0xf9,0xaa,0xb5,0xd6,0xdf,0x44,
		0xbb,0x1b,0x88,0xac,0x00,0x00,0x00,0x00
	};

	unsigned char merkle_branches[][32] = {
		{0xdf,0x40,0xcf,0x4d,0x90,0x64,0xb3,0x9e,0xce,0x1a,0x32,0x42,0xb0,0x33,0x97,0xea,0x1b,0x43,0x23,0x13,0x8a,0x0a,0x51,0x52,0x7a,0x20,0x74,0xf2,0x71,0xc3,0x88,0x52},
		{0xed,0xb0,0x7a,0x6c,0x50,0x99,0x0f,0xe8,0x9e,0xe7,0x84,0xd7,0x82,0xa0,0xe6,0xd8,0xdd,0x99,0xd6,0x15,0x35,0x63,0xa9,0x3d,0xd3,0x6c,0xb9,0xdb,0x5a,0x1e,0x34,0x5f},
		{0x64,0x98,0xb5,0x26,0x04,0x8f,0x08,0x15,0xd9,0x39,0x0d,0x0f,0x32,0x08,0x57,0x49,0x83,0xcd,0x72,0x52,0x84,0xe3,0x74,0xe0,0xe5,0xda,0x5a,0xcc,0x8e,0xdb,0xe4,0x4c},
		{0x3c,0x78,0x9f,0x8c,0xf7,0x39,0x93,0x52,0x55,0xf4,0x34,0x42,0x9a,0x77,0xe3,0xcf,0x22,0xf6,0x1c,0x4a,0x38,0x2e,0x32,0xfd,0xb5,0xd0,0x3d,0x36,0x9b,0x31,0x79,0x5a},
		{0xc2,0xce,0xd4,0x9b,0x26,0xdf,0x6d,0x83,0x25,0xf8,0x33,0x94,0x60,0xf8,0x8f,0x69,0xbd,0x98,0x07,0x18,0x94,0xa4,0x5a,0x14,0x2a,0x54,0x6e,0x6d,0x88,0xb4,0xc7,0xd2},
		{0x4f,0x62,0x78,0x05,0xdc,0x7e,0x4d,0xc8,0x52,0x6a,0xc8,0xb2,0x86,0xf6,0x52,0x0d,0x17,0x57,0x74,0x59,0x04,0xc3,0x9d,0x38,0xa6,0xf8,0xc3,0x6b,0x74,0xfd,0x5d,0x10},
		{0xe1,0xd3,0xfb,0x46,0x1c,0xb4,0xbe,0xd1,0x55,0xcf,0x9e,0x21,0x2b,0x65,0xe1,0x0f,0xd1,0x65,0x1a,0x2e,0x25,0x78,0x74,0x0f,0x6c,0xb1,0x11,0xa2,0x26,0x34,0xba,0x9e},
		{0x63,0xd0,0x2e,0x76,0xd7,0x54,0xf7,0x67,0xef,0x9a,0x3c,0xa3,0xae,0xa0,0x5e,0xb2,0xc3,0x94,0x75,0x99,0x73,0xf0,0x40,0xa1,0x80,0x9e,0x02,0xf3,0x0e,0xed,0xcd,0x0d},
		{0x7f,0x51,0x79,0xc7,0x36,0x27,0xe7,0x35,0xf4,0x41,0x52,0x04,0x0a,0xd8,0x61,0xe6,0x95,0x97,0xb6,0x89,0x81,0x09,0x17,0x4e,0x09,0x2d,0x28,0xc0,0x37,0x74,0x73,0x52},
		{0x9c,0x37,0x53,0xe0,0x39,0x6f,0x49,0xe4,0x46,0xb9,0xf8,0x82,0x0a,0xaf,0xd0,0x7b,0x38,0xf7,0xea,0x6f,0xf8,0xc3,0x60,0x05,0x96,0x99,0x9b,0x1c,0xbb,0x51,0xd7,0x49},
		{0x20,0xf8,0x90,0x21,0xa8,0x4c,0xb4,0x93,0x0d,0xf8,0x1d,0xfc,0x66,0x81,0xab,0x0e,0x01,0x97,0x95,0x42,0x03,0x36,0x41,0x0f,0xfc,0x2b,0xe2,0x9a,0x31,0x34,0x8e,0x5f},
	};

	test_pool.n2size = 8;
	test_pool.nonce2_offset = 62;
#endif
	test_pool.coinbase_len = sizeof(coinbase);
	test_pool.coinbase = cgcalloc(sizeof(coinbase), 1);
	test_pool.merkles = sizeof(merkle_branches) / 32;

	test_pool.swork.merkle_bin = cgmalloc(sizeof(char *) * test_pool.merkles + 1);
	for (i = 0; i < test_pool.merkles; i++) {
		test_pool.swork.merkle_bin[i] = cgmalloc(32);
		memcpy(test_pool.swork.merkle_bin[i], merkle_branches[i], 32);
	}
	memcpy(test_pool.coinbase, coinbase, sizeof(coinbase));

	ssp_sorter_init(HT_SIZE, HT_PRB_LMT, HT_PRB_C1, HT_PRB_C2);
	ssp_hasher_init();

	for (i = 0; i < 2; i++) {
		ssp_hasher_update_stratum(&test_pool, true);
		cgsleep_ms(1);
	}

	cgtime(&t_start);
	while (1) {
		if (ssp_sorter_get_pair(pair)) {
			cgtime(&t_find_pair);
			pair_diff = tdiff(&t_find_pair, &t_start);
			applog(LOG_NOTICE, "%0.8fs\tGot a pair %08x-%08x", pair_diff, pair[0], pair[1]);
			gen_merkle_root(&test_pool, pair[0]);
			gen_merkle_root(&test_pool, pair[1]);
			memcpy(&t_start, &t_find_pair, sizeof(t_find_pair));
		}
	}

	free(test_pool.coinbase);
	for (i = 0; i < test_pool.merkles; i++)
		free(test_pool.swork.merkle_bin[i]);

	quit(1, "ssp_hasher_test finished\n");
}
