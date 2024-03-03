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

#include "vmlinux.h"

#include "bmc_common.h"
#include <bpf_helpers.h>

#define htons bpf_htons

#define __ksym __attribute__((section(".ksyms")))
#include "bpf_kfuncs.h"

#define ETH_ALEN 6
#define TC_ACT_OK 0

#define ADJUST_HEAD_LEN 128

#ifndef memmove
#define memmove(dest, src, n) __builtin_memmove((dest), (src), (n))
#endif

#define pr(...) //bpf_printk(__VA_ARGS__)

struct memcached_udp_header {
	__be16 request_id;
	__be16 seq_num;
	__be16 num_dgram;
	__be16 unused;
	char data[];
} __attribute__((__packed__));

/*
 * eBPF maps
 */

/* cache */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct bmc_cache_entry);
	__uint(max_entries, BMC_CACHE_ENTRY_COUNT);
} map_kcache SEC(".maps");

/* keys */
struct memcached_key {
	u32 hash;
	char data[BMC_MAX_KEY_LENGTH];
	unsigned int len;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, unsigned int);
	__type(value, struct memcached_key);
	__uint(max_entries, BMC_MAX_KEY_IN_PACKET);
} map_keys SEC(".maps");

/* context */
struct parsing_context {
	unsigned int key_count;
	unsigned int current_key;
	unsigned short read_pkt_offset;
	unsigned short write_pkt_offset;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, unsigned int);
	__type(value, struct parsing_context);
	__uint(max_entries, 1);
} map_parsing_context SEC(".maps");

/* stats */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, unsigned int);
	__type(value, struct bmc_stats);
	__uint(max_entries, 1);
} map_stats SEC(".maps");

/* program maps */
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, BMC_PROG_XDP_MAX);
} map_progs_xdp SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, BMC_PROG_TC_MAX);
} map_progs_tc SEC(".maps");

static inline u16 compute_ip_checksum(struct iphdr *ip) {
	u32 csum = 0;
	u16 *next_ip_u16 = (u16 *)ip;

	ip->check = 0;

#pragma clang loop unroll(full)
	for (int i = 0; i < (sizeof(*ip) >> 1); i++) {
		csum += *next_ip_u16++;
	}

	return ~((csum & 0xffff) + (csum >> 16));
}

SEC("xdp")
int bmc_rx_filter_main(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_dynptr xdp;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(*eth);
	void *transp = data + sizeof(*eth) + sizeof(*ip);
	struct udphdr *udp;
	struct tcphdr *tcp;
	char buf[8] = {};
	char *payload;
	__be16 dport;
	__u32 off, poff;
	int ret;

	ret = bpf_dynptr_from_xdp(ctx, 0, &xdp);
	if (ret < 0) {
		bpf_printk("Failed to create dynptr for xdp_md: %d", ret);
		return XDP_PASS;
	}

	if (ip + 1 > data_end)
		return XDP_PASS;

	switch (ip->protocol) {
		case IPPROTO_UDP:
			udp = (struct udphdr *)transp;
			if (udp + 1 > data_end)
				return XDP_PASS;
			dport = udp->dest;
			poff = sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(struct memcached_udp_header);
			break;
		case IPPROTO_TCP:
			tcp = (struct tcphdr *)transp;
			if (tcp + 1 > data_end)
				return XDP_PASS;
			dport = tcp->dest;
			poff = sizeof(*eth) + sizeof(*ip) + sizeof(*tcp);
			break;
		default:
			return XDP_PASS;
	}

	payload = bpf_dynptr_slice(&xdp, poff, buf, 4);
	if (!payload)
		return XDP_PASS;
	if (dport == htons(11211) && payload) {
		if (ip->protocol == IPPROTO_UDP && payload[0] == 'g' && payload[1] == 'e' && payload[2] == 't' && payload[3] == ' ') {	// is this a GET request
			unsigned int zero = 0;
			struct bmc_stats *stats = bpf_map_lookup_elem(&map_stats, &zero);
			if (!stats) {
				return XDP_PASS;
			}
			stats->get_recv_count++;

			pr("Got GET packet");

			struct parsing_context *pctx = bpf_map_lookup_elem(&map_parsing_context, &zero);
			if (!pctx) {
				return XDP_PASS;
			}
			pctx->key_count = 0;
			pctx->current_key = 0;
			pctx->write_pkt_offset = 0;

			unsigned int off;
#pragma clang loop unroll(disable)
			for (off = 4; off < BMC_MAX_PACKET_LENGTH; off++) {
				payload = bpf_dynptr_slice(&xdp, poff + off, buf, 1);
				if (!payload || payload[0] != ' ')
					break;
			} // move offset to the start of the first key
			if (off < BMC_MAX_PACKET_LENGTH) {
				pctx->read_pkt_offset = off;												       // save offset
				if (bpf_xdp_adjust_head(ctx, (int)(sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(struct memcached_udp_header) + off))) {  // push headers + 'get ' keyword
					pr("Adjust head error");
					return XDP_PASS;
				}
				pr("Performing hash keys tail call");
				bpf_tail_call(ctx, &map_progs_xdp, BMC_PROG_XDP_HASH_KEYS);
			}
		} else if (ip->protocol == IPPROTO_TCP) {
			bpf_tail_call(ctx, &map_progs_xdp, BMC_PROG_XDP_INVALIDATE_CACHE);
		}
	}

	return XDP_PASS;
}

__attribute__((noinline))
int global_parsing_func(u32 *hashp, int *lenp, unsigned int *done_parsingp, char *p) {
	// TODO(kkd): Quirk of global function
	if (!hashp || !lenp || !done_parsingp || !p)
		return 1;
	if (p[0] == '\r') {
		*done_parsingp = 1;
		return 1;
	} else if (p[0] == ' ') {
		return 1;
	} else if (p[0] != ' ') {
		*hashp ^= p[0];
		*hashp *= FNV_PRIME_32;
		++*lenp;
	}
	return 0;
}

SEC("xdp")
int bmc_hash_keys_main(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	char *payload = (char *)data;
	unsigned int zero = 0;
	struct bpf_dynptr xdp;
	char buf[8] = {};
	int ret;

	ret = bpf_dynptr_from_xdp(ctx, 0, &xdp);
	if (ret < 0) {
		bpf_printk("Failed to create dynptr for xdp_md: %d", ret);
		return XDP_PASS;
	}

	if (payload >= data_end)
		return XDP_PASS;

	struct parsing_context *pctx = bpf_map_lookup_elem(&map_parsing_context, &zero);
	if (!pctx) {
		return XDP_PASS;
	}

	struct memcached_key *key = bpf_map_lookup_elem(&map_keys, &pctx->key_count);
	if (!key) {
		return XDP_PASS;
	}
	key->hash = FNV_OFFSET_BASIS_32;

	unsigned int off, done_parsing = 0, key_len = 0;

	pr("Hashing keys");
	// compute the key hash
#pragma clang loop unroll(disable)
	for (off = 0; off < BMC_MAX_KEY_LENGTH + 1; off++) {
		// TODO(kkd): We cannot pass rdonly mem to global func, so use
		// rdwr here, even though we only read stuff.
		payload = bpf_dynptr_slice_rdwr(&xdp, off, buf, 1);
		// Technically, payload == buf should not be true, in each frag
		// at any offset, we can always obtain a direct pointer to 1
		// byte. But anyway, another day. But since we do not write into
		// payload even though we use rdwr, we do not check it.
		if (!payload)
			break;
		if (global_parsing_func(&key->hash, &key_len, &done_parsing, payload))
			break;
	}

	if (key_len == 0 || key_len > BMC_MAX_KEY_LENGTH) {
		bpf_xdp_adjust_head(ctx, 0 - (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct memcached_udp_header) + pctx->read_pkt_offset));  // unexpected key, let the netstack handle it

		pr("Unexpected key, pass to netstack");
		return XDP_PASS;
	}

	u32 cache_idx = key->hash % BMC_CACHE_ENTRY_COUNT;
	struct bmc_cache_entry *entry = bpf_map_lookup_elem(&map_kcache, &cache_idx);
	if (!entry) {  // should never happen since cache map is of type BPF_MAP_TYPE_ARRAY
		pr("Should never happen since cache map is of type BPF_MAP_TYPE_ARRAY");
		return XDP_PASS;
	}

	pr("get hash payload byte");
	payload = bpf_dynptr_slice(&xdp, off, buf, 1);
	if (!payload)
		return XDP_PASS;
	pr("Spin Lock");
	bpf_spin_lock(&entry->lock);
	if (entry->valid && entry->hash == key->hash) {	 // potential cache hit
		bpf_spin_unlock(&entry->lock);
#pragma clang loop unroll(disable)
		for (unsigned int i = 0; i < key_len; i++) {
			// copy the request key to compare it with the one stored in the cache later
			payload = bpf_dynptr_slice(&xdp, i, buf, 1);
			if (!payload)
				return XDP_PASS;
			// TODO(kkd): Use bpf_asserts to form proper ranges,
			// verifier for instance cannot know about i and rejects
			// our program.
			if (i >= BMC_MAX_KEY_LENGTH)
				return XDP_PASS;
			key->data[i] = payload[0];
		}
		key->len = key_len;
		pctx->key_count++;
		pr("hit: copy key");
	} else {  // cache miss
		bpf_spin_unlock(&entry->lock);
		struct bmc_stats *stats = bpf_map_lookup_elem(&map_stats, &zero);
		if (!stats) {
			return XDP_PASS;
		}
		stats->miss_count++;
		pr("miss:");
	}

	if (done_parsing) {																			     // the end of the request has been reached
		bpf_xdp_adjust_head(ctx, 0 - (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct memcached_udp_header) + pctx->read_pkt_offset));  // pop headers + 'get ' + previous keys
		if (pctx->key_count > 0) {
			pr("Prepare packet");
			bpf_tail_call(ctx, &map_progs_xdp, BMC_PROG_XDP_PREPARE_PACKET);
		}
	} else {	// more keys to process
		off++;	// move offset to the start of the next key
		pctx->read_pkt_offset += off;
		if (bpf_xdp_adjust_head(ctx, off))  // push the previous key
			return XDP_PASS;
		pr("Hash again...");
		bpf_tail_call(ctx, &map_progs_xdp, BMC_PROG_XDP_HASH_KEYS);
	}

	return XDP_PASS;
}

SEC("xdp")
int bmc_prepare_packet_main(struct xdp_md *ctx) {
	if (bpf_xdp_adjust_head(ctx, -ADJUST_HEAD_LEN))	 // // pop empty packet buffer memory to increase the available packet size
		return XDP_PASS;

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(*eth);
	struct udphdr *udp = data + sizeof(*eth) + sizeof(*ip);
	struct memcached_udp_header *memcached_udp_hdr = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
	char *payload = (char *)(memcached_udp_hdr + 1);
	void *old_data = data + ADJUST_HEAD_LEN;
	char *old_payload = (char *)(old_data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(*memcached_udp_hdr));

	if (payload >= data_end || old_payload + 1 >= data_end)
		return XDP_PASS;

	// use old headers as a base; then update addresses and ports to create the new headers
	memmove(eth, old_data, sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(*memcached_udp_hdr));

	unsigned char tmp_mac[ETH_ALEN];
	__be32 tmp_ip;
	__be16 tmp_port;

	__builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

	tmp_ip = ip->saddr;
	ip->saddr = ip->daddr;
	ip->daddr = tmp_ip;

	tmp_port = udp->source;
	udp->source = udp->dest;
	udp->dest = tmp_port;

	if (bpf_xdp_adjust_head(ctx, sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(*memcached_udp_hdr)))  // push new headers
		return XDP_PASS;
	pr("Write reply");
	bpf_tail_call(ctx, &map_progs_xdp, BMC_PROG_XDP_WRITE_REPLY);

	return XDP_PASS;
}

SEC("xdp")
int bmc_write_reply_main(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	char *payload = (char *)data;
	unsigned int zero = 0;
	struct bpf_dynptr xdp;
	char buf[8] = {};
	int ret;

	ret = bpf_dynptr_from_xdp(ctx, 0, &xdp);
	if (ret < 0) {
		bpf_printk("Failed to create dynptr for xdp_md: %d", ret);
		return XDP_PASS;
	}

	if (payload >= data_end)
		return XDP_PASS;

	struct parsing_context *pctx = bpf_map_lookup_elem(&map_parsing_context, &zero);
	if (!pctx) {
		return XDP_PASS;
	}

	struct memcached_key *key = bpf_map_lookup_elem(&map_keys, &pctx->current_key);
	if (!key) {
		return XDP_PASS;
	}

	unsigned int cache_hit = 1, written = 0;
	u32 cache_idx = key->hash % BMC_CACHE_ENTRY_COUNT;
	struct bmc_cache_entry *entry = bpf_map_lookup_elem(&map_kcache, &cache_idx);
	if (!entry) {
		return XDP_DROP;
	}

	bpf_spin_lock(&entry->lock);
	if (entry->valid && key->hash == entry->hash) {	 // if saved key still matches its corresponding cache entry
#pragma clang loop unroll(disable)
		for (int i = 0; i < BMC_MAX_KEY_LENGTH && i < key->len; i++) {	// compare the saved key with the one stored in the cache entry
			if (key->data[i] != entry->data[6 + i]) {
				cache_hit = 0;
			}
		}
		if (cache_hit) {  // if cache HIT then copy cached data
			unsigned int off;
#pragma clang loop unroll(disable)
			for (off = 0; off + sizeof(unsigned long long) < BMC_MAX_CACHE_DATA_SIZE; off++) {
				if (off + sizeof(unsigned long long) > entry->len)
					break;
				payload = bpf_dynptr_slice_rdwr(&xdp, off, buf, sizeof(unsigned long long));
				if (!payload || payload == buf)
					break;
				*((unsigned long long *)payload) = *((unsigned long long *)&entry->data[off]);
				off += sizeof(unsigned long long) - 1;
				written += sizeof(unsigned long long);
			}
#pragma clang loop unroll(disable)
			for (; off < BMC_MAX_CACHE_DATA_SIZE; off++) {
				if (off >= entry->len)
					break;
				payload = bpf_dynptr_slice_rdwr(&xdp, off, buf, 1);
				if (!payload || payload == buf)
					break;
				payload[0] = entry->data[off];
				written += 1;
			}
		}
	}
	bpf_spin_unlock(&entry->lock);
	pr("Cache hit cache hit=%d written=%d entry->len=%d, copy cache data", cache_hit, written, entry->len);

	struct bmc_stats *stats = bpf_map_lookup_elem(&map_stats, &zero);
	if (!stats) {
		return XDP_PASS;
	}
	if (cache_hit) {
		stats->hit_count++;
	} else {
		stats->miss_count++;
	}

	pctx->current_key++;

	pr("pctx cur_key=%d pctx key_count=%d write_pkt_off=%d written=%d", pctx->current_key, pctx->key_count, pctx->write_pkt_offset, written);
	if (pctx->current_key == pctx->key_count && (pctx->write_pkt_offset > 0 || written > 0)) {  // if all saved keys have been processed and a least one cache HIT
		if ((payload = bpf_dynptr_slice_rdwr(&xdp, written, buf, 5)) && payload != buf) {
			payload[0] = 'E';
			payload[1] = 'N';
			payload[2] = 'D';
			payload[3] = '\r';
			payload[4] = '\n';
			written += 5;

			pr("Written END in payload");

			if (bpf_xdp_adjust_head(ctx, 0 - (int)(sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct memcached_udp_header) + pctx->write_pkt_offset))) {	 // pop headers + previously written data
				return XDP_DROP;
			}

			void *data_end = (void *)(long)ctx->data_end;
			void *data = (void *)(long)ctx->data;
			struct iphdr *ip = data + sizeof(struct ethhdr);
			struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(*ip);
			payload = data + sizeof(struct ethhdr) + sizeof(*ip) + sizeof(*udp) + sizeof(struct memcached_udp_header);

			if (udp + 1 > data_end)
				return XDP_PASS;

			ip->tot_len = htons((payload + pctx->write_pkt_offset + written) - (char *)ip);
			ip->check = compute_ip_checksum(ip);
			udp->check = 0;	 // computing udp checksum is not required
			udp->len = htons((payload + pctx->write_pkt_offset + written) - (char *)udp);

			bpf_xdp_adjust_tail(ctx, 0 - (int)((long)data_end - (long)(payload + pctx->write_pkt_offset + written)));  // try to strip additional bytes

			return XDP_TX;
		} else {
			// TODO(kkd): BMC does not work when value > key, since
			// it does not grow the packet at all!!!
			pr("Cannot find linear segment");
			return XDP_DROP;
		}
	} else if (pctx->current_key == pctx->key_count) {  // else if all saved keys have been processed but got no cache HIT; either because of a hash colision or a race with a cache update
		stats->hit_misprediction += pctx->key_count;
		bpf_xdp_adjust_head(ctx, ADJUST_HEAD_LEN - (int)(sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct memcached_udp_header)));	// pop to the old headers and transmit to netstack
		return XDP_PASS;
	} else if (pctx->current_key < BMC_MAX_KEY_IN_PACKET) {	 // else if there are still keys to process
		pctx->write_pkt_offset += written;		 // save packet write offset
		if (bpf_xdp_adjust_head(ctx, written))		 // push written data
			return XDP_DROP;
		pr("Write reply again");
		bpf_tail_call(ctx, &map_progs_xdp, BMC_PROG_XDP_WRITE_REPLY);
	}

	return XDP_DROP;
}

SEC("xdp")
int bmc_invalidate_cache_main(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(*eth);
	struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip);
	char *payload = (char *)(tcp + 1);
	u32 poff = sizeof(*eth) + sizeof(*ip) + sizeof(*tcp);
	unsigned int zero = 0;
	struct bpf_dynptr xdp;
	char buf[8] = {};
	int ret;

	ret = bpf_dynptr_from_xdp(ctx, 0, &xdp);
	if (ret < 0) {
		bpf_printk("Failed to create dynptr for xdp_md: %d", ret);
		return XDP_PASS;
	}

	if (payload >= data_end)
		return XDP_PASS;

	struct bmc_stats *stats = bpf_map_lookup_elem(&map_stats, &zero);
	if (!stats) {
		return XDP_PASS;
	}

	u32 hash;
	int set_found = 0, key_found = 0;

#pragma clang loop unroll(disable)
	for (unsigned int off = 0; off < BMC_MAX_PACKET_LENGTH; off++) {
		payload = bpf_dynptr_slice(&xdp, poff + off, buf, 1);
		if (!payload)
			break;
		if (set_found == 0 && (payload = bpf_dynptr_slice(&xdp, poff + off, buf, 3)) && payload[0] == 's' && payload[1] == 'e' && payload[2] == 't') {
			set_found = 1;
			off += 3;  // move offset after the set keywork, at the next iteration 'off' will either point to a space or the start of the key
			stats->set_recv_count++;
		} else if (key_found == 0 && set_found == 1 && payload[0] != ' ') {
			if (payload[0] == '\r') {  // end of packet
				set_found = 0;
				key_found = 0;
			} else {  // found the start of the key
				hash = FNV_OFFSET_BASIS_32;
				hash ^= payload[0];
				hash *= FNV_PRIME_32;
				key_found = 1;
			}
		} else if (key_found == 1) {
			if (payload[0] == ' ') {  // found the end of the key
				u32 cache_idx = hash % BMC_CACHE_ENTRY_COUNT;
				struct bmc_cache_entry *entry = bpf_map_lookup_elem(&map_kcache, &cache_idx);
				if (!entry) {
					return XDP_PASS;
				}
				bpf_spin_lock(&entry->lock);
				if (entry->valid) {
					entry->valid = 0;
					stats->invalidation_count++;
				}
				bpf_spin_unlock(&entry->lock);
				set_found = 0;
				key_found = 0;
			} else {  // still processing the key
				hash ^= payload[0];
				hash *= FNV_PRIME_32;
			}
		}
	}

	return XDP_PASS;
}

SEC("tc")
int bmc_tx_filter_main(struct __sk_buff *skb) {
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(*eth);
	struct udphdr *udp = data + sizeof(*eth) + sizeof(*ip);
	char *payload = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(struct memcached_udp_header);
	unsigned int zero = 0;

	// if the size exceeds the size of a cache entry do not bother going further
	if (skb->len > BMC_MAX_CACHE_DATA_SIZE + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct memcached_udp_header))
		return TC_ACT_OK;

	if (ip + 1 > data_end)
		return XDP_PASS;

	if (ip->protocol != IPPROTO_UDP)
		return TC_ACT_OK;

	if (udp + 1 > data_end)
		return TC_ACT_OK;

	__be16 sport = udp->source;

	if (sport == htons(11211) && payload + 5 + 1 <= data_end && payload[0] == 'V' && payload[1] == 'A' && payload[2] == 'L' && payload[3] == 'U' && payload[4] == 'E' && payload[5] == ' ') {  // if this is a GET reply

		struct bmc_stats *stats = bpf_map_lookup_elem(&map_stats, &zero);
		if (!stats) {
			return XDP_PASS;
		}
		stats->get_resp_count++;

		bpf_tail_call(skb, &map_progs_tc, BMC_PROG_TC_UPDATE_CACHE);
	}

	return TC_ACT_OK;
}

SEC("tc")
int bmc_update_cache_main(struct __sk_buff *skb) {
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	char *payload = (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct memcached_udp_header));
	u32 poff = (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct memcached_udp_header));
	unsigned int zero = 0;
	struct bpf_dynptr dskb;
	char buf[8] = {};
	int ret;

	ret = bpf_dynptr_from_skb(skb, 0, &dskb);
	if (ret < 0) {
		bpf_printk("Failed to create dynptr for xdp_md: %d", ret);
		return XDP_PASS;
	}

	u32 hash = FNV_OFFSET_BASIS_32;

	// compute the key hash
#pragma clang loop unroll(disable)
	for (unsigned int off = 6; off - 6 < BMC_MAX_KEY_LENGTH; off++) {
		payload = bpf_dynptr_slice(&dskb, poff + off, buf, 1);
		if (!payload || payload[0] == ' ')
			break;
		hash ^= payload[0];
		hash *= FNV_PRIME_32;
	}

	u32 cache_idx = hash % BMC_CACHE_ENTRY_COUNT;
	struct bmc_cache_entry *entry = bpf_map_lookup_elem(&map_kcache, &cache_idx);
	if (!entry) {
		return TC_ACT_OK;
	}

	bpf_spin_lock(&entry->lock);
	if (entry->valid && entry->hash == hash) {  // cache is up-to-date; no need to update
		int diff = 0;
		// loop until both bytes are spaces ; or break if they are different
		payload = bpf_dynptr_slice(&dskb, poff + 6, buf, 1);
		if (!payload) {
			bpf_spin_unlock(&entry->lock);
			return TC_ACT_OK;
		}
#pragma clang loop unroll(disable)
		for (unsigned int off = 6; off - 6 < BMC_MAX_KEY_LENGTH && off < entry->len && (payload[0] != ' ' || entry->data[off] != ' '); off++) {
			payload = bpf_dynptr_slice(&dskb, poff + off, buf, 1);
			if (!payload || payload[0] == ' ')
				break;
			if (entry->data[off] != payload[0]) {
				diff = 1;
				break;
			}
		}
		if (diff == 0) {
			bpf_spin_unlock(&entry->lock);
			pr("Saw diff == %d", diff);
			return TC_ACT_OK;
		}
	}

	unsigned int count = 0;
	entry->len = 0;
	// store the reply from start to the '\n' that follows the data
	payload = bpf_dynptr_slice(&dskb, poff, buf, 1);
	if (!payload)
		goto skip;
#pragma clang loop unroll(disable)
	for (unsigned int j = 0; j < BMC_MAX_CACHE_DATA_SIZE && count < 2; j++) {
		payload = bpf_dynptr_slice(&dskb, poff + j, buf, 1);
		if (!payload)
			break;
		entry->data[j] = payload[0];
		entry->len++;
		if (payload[0] == '\n')
			count++;
	}
skip:
	if (count == 2) {  // copy OK
		entry->valid = 1;
		entry->hash = hash;
		bpf_spin_unlock(&entry->lock);
		struct bmc_stats *stats = bpf_map_lookup_elem(&map_stats, &zero);
		if (!stats) {
			return XDP_PASS;
		}
		stats->update_count++;
	} else {
		bpf_spin_unlock(&entry->lock);
	}
	pr("Saw count == %d", count);

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
// to test colisions: keys declinate0123456 and macallums0123456 have hash colision
