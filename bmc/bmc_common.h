/*
 *  Software Name : bmc-cache
 *  SPDX-FileCopyrightText: Copyright (c) 2021 Orange
 *  SPDX-License-Identifier: LGPL-2.1-only
 *
 *  This software is distributed under the
 *  GNU Lesser General Public License v2.1 only.
 *
 *  Author: Yoann GHIGOFF <yoann.ghigoff@orange.com> et al.
 */

#ifndef _BMC_COMMON_H
#define _BMC_COMMON_H

#define BMC_MAX_KEY_LENGTH 250
#define BMC_MAX_VAL_LENGTH 1000
#define BMC_MAX_ADDITIONAL_PAYLOAD_BYTES 53
#define BMC_MAX_CACHE_DATA_SIZE BMC_MAX_KEY_LENGTH+BMC_MAX_VAL_LENGTH+BMC_MAX_ADDITIONAL_PAYLOAD_BYTES
#define BMC_MAX_KEY_IN_MULTIGET 30
#define BMC_CACHE_ENTRY_COUNT 3250000
#define BMC_MAX_PACKET_LENGTH 1500
#define BMC_MAX_KEY_IN_PACKET BMC_MAX_KEY_IN_MULTIGET

#define FNV_OFFSET_BASIS_32		2166136261
#define FNV_PRIME_32			16777619

enum {
	BMC_PROG_XDP_HASH_KEYS = 0,
	BMC_PROG_XDP_PREPARE_PACKET,
	BMC_PROG_XDP_WRITE_REPLY,
	BMC_PROG_XDP_INVALIDATE_CACHE,

	BMC_PROG_XDP_MAX
};

enum {
	BMC_PROG_TC_UPDATE_CACHE = 0,

	BMC_PROG_TC_MAX
};


struct bmc_cache_entry {
	struct bpf_spin_lock lock;
	unsigned int len;
	char valid;
	int hash;
	char data[BMC_MAX_CACHE_DATA_SIZE];
};

struct bmc_stats {
	unsigned int get_recv_count;			// Number of GET command received
	unsigned int set_recv_count;			// Number of SET command received
	unsigned int get_resp_count;			// Number of GET command reply analyzed
	unsigned int hit_misprediction;			// Number of keys that were expected to hit but did not (either because of a hash colision or a race with an invalidation/update)
	unsigned int hit_count;				// Number of HIT in kernel cache
	unsigned int miss_count;			// Number of MISS in kernel cache
	unsigned int update_count;			// Number of kernel cache updates
	unsigned int invalidation_count;		// Number of kernel cache entry invalidated
};

/* LLVM's BPF target selects the endianness of the CPU
 * it compiles on, or the user specifies (bpfel/bpfeb),
 * respectively. The used __BYTE_ORDER__ is defined by
 * the compiler, we cannot rely on __BYTE_ORDER from
 * libc headers, since it doesn't reflect the actual
 * requested byte order.
 *
 * Note, LLVM's BPF target has different __builtin_bswapX()
 * semantics. It does map to BPF_ALU | BPF_END | BPF_TO_BE
 * in bpfel and bpfeb case, which means below, that we map
 * to cpu_to_be16(). We could use it unconditionally in BPF
 * case, but better not rely on it, so that this header here
 * can be used from application and BPF program side, which
 * use different targets.
 */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define __bpf_ntohs(x)			__builtin_bswap16(x)
# define __bpf_htons(x)			__builtin_bswap16(x)
# define __bpf_ntohl(x)			__builtin_bswap32(x)
# define __bpf_htonl(x)			__builtin_bswap32(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# define __bpf_ntohs(x)			(x)
# define __bpf_htons(x)			(x)
# define __bpf_ntohl(x)			(x)
# define __bpf_htonl(x)			(x)
#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif

#define bpf_htons(x) __bpf_htons(x)
#define bpf_ntohs(x) __bpf_ntohs(x)

#endif
