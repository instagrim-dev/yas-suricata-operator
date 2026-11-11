// Copyright 2026 jmh. Licensed under the Apache License, Version 2.0.
typedef unsigned char u8; typedef unsigned short u16; typedef unsigned int u32; typedef unsigned long long u64;
#define SEC(x) __attribute__((section(x), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
struct xdp_md { u32 data; u32 data_end; u32 data_meta; u32 ingress_ifindex; u32 rx_queue_index; u32 egress_ifindex; };
struct flowkey { u8 src[4]; u8 dst[4]; u8 sport[2]; u8 dport[2]; u8 proto; u8 pad[3]; };
struct dropval {u64 expires;u64 hits;};
struct { __uint(type, 9); __uint(max_entries, 4096); __type(key, struct flowkey); __type(value, struct dropval); } drops SEC(".maps");
static void *(*map_lookup)(void *, const void *)=(void *)1;
static long (*map_delete)(void *, const void *)=(void *)3;
static u64 (*ktime)(void)=(void *)5;
SEC("xdp") int xdp_verdict(struct xdp_md *ctx) {
 u8 *d=(void *)(long)ctx->data, *end=(void *)(long)ctx->data_end;
 if (d+34>end) return 2;
 if (d[12]!=0x08 || d[13]!=0x00 || (d[14]>>4)!=4) return 2;
 u32 ihl=(d[14]&15)*4; if(ihl<20) return 2;
 if ((d[20]&0x3f) || d[21]) return 2;
 u8 proto=d[23];if(proto!=6 && proto!=17) return 2;
 if (d+14+ihl+4>end) return 2;
 struct flowkey k={};
 __builtin_memcpy(k.src,d+26,4); __builtin_memcpy(k.dst,d+30,4);
 __builtin_memcpy(k.sport,d+14+ihl,2); __builtin_memcpy(k.dport,d+14+ihl+2,2); k.proto=proto;
 struct dropval *val=map_lookup(&drops,&k);if(!val)return 2;
 if(ktime()>=val->expires){map_delete(&drops,&k);return 2;}
 __sync_fetch_and_add(&val->hits,1);return 1;
}
char LICENSE[] SEC("license")="Apache-2.0";
