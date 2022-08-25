#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "monitor_hash_futex.h"

#define MAX_ENTRIES 0x100000
// TODO: fetch the actually possible cpu numbers
#define CPU_NUMBER 256 * 8

struct inner_data {
    __u32 hash;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct inner_data);
} starts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");


/* jhash2 - hash an array of u32's
 * @k: the key which must be an array of u32's
 * @length: the number of u32's in the key
 * @initval: the previous hash, or an arbitray value
 *
 * Returns the hash value of the key.
 */
static inline u32 jhash2(const u32 *k, u32 length, u32 initval)
{
    u32 a, b, c;
    u32 tmp;

    /* Set up the internal state */
    a = b = c = JHASH_INITVAL + (length<<2) + initval;

    /* Handle most of the key */
    while (length > 3) {
        bpf_core_read(&tmp, sizeof(u32), k);
        a += tmp;
        bpf_core_read(&tmp, sizeof(u32), k + 1);
        b += tmp;
        bpf_core_read(&tmp, sizeof(u32), k + 2);
        c += tmp;
        __jhash_mix(a, b, c);
        length -= 3;
        k += 3;
    }

    /* Handle the last 3 u32's */
    switch (length) {
        case 3:
            bpf_core_read(&tmp, sizeof(u32), k + 2);
            c += tmp;
        case 2:
            bpf_core_read(&tmp, sizeof(u32), k + 1);
            b += tmp;
        case 1:
            bpf_core_read(&tmp, sizeof(u32), k);
            a += tmp;
            break;
        case 0: /* Nothing left to add */
            break;
    }

    return c;
}

/*
 * Use following method to fetch event you want to probe:
 *
 * #cat /proc/kallsyms | grep hash_futex
 * 0000000000000000 t hash_futex
 *
 * vmlinux.h would be generated automatically when building bpftools.
 *
 */
SEC("kprobe/hash_futex")
int monitor_hash_futex(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    union futex_key *key = (union futex_key *)PT_REGS_PARM1(ctx);
    u32 hash = 0;
    u32 offset = 0;
    struct inner_data data;

    bpf_core_read(&offset, sizeof(u32), &key->both.offset);

    hash = jhash2((u32 *)key, offsetof(typeof(*key), both.offset) / 4, offset);

    data.hash = hash & (roundup_pow_of_two(CPU_NUMBER) - 1);

    bpf_map_update_elem(&starts, &pid, &data, BPF_ANY);

    return 0;
}

SEC("kretprobe/hash_futex")
int monitor_hash_futex_ret(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *current = (void *)bpf_get_current_task();
    struct data_t data = {};
    struct inner_data *datap;

    datap = bpf_map_lookup_elem(&starts, &pid);
    if (datap == NULL)
        return 0;

    bpf_map_delete_elem(&starts, &pid);

    data.pid = pid;
    data.hash_size = roundup_pow_of_two(CPU_NUMBER);
    data.hash = datap->hash;

    BPF_CORE_READ_STR_INTO(&data.comm, current, group_leader, comm);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
