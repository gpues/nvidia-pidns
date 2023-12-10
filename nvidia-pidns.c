#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/pseudo_fs.h>

#define NVIDIA_CTL_RDEV (MKDEV(195, 255))
#define MAX_PID_COUNT (4096)

enum nvidia_fixer_state {
    NVIDIA_FIXER_INIT,
    NVIDIA_FIXER_SUCCESS,
    NVIDIA_FIXER_ERROR,
};

struct nvidia_req_arg {
    u32 rsv0;
    u32 rsv1;
    u32 version;
    void *u_ptr __attribute__((aligned(8)));
    u32 tag;
};

typedef struct mpu_nvml_process_list {
    u32 _0;
    u32 _1;
    u32 cnt;
    u32 pl[];
} mpu_nvml_process_list_t;

// ver. 440
typedef struct mpu_nvml_process_mem_item_1f48 {
    u32 pid;
    u32 _0[9];
} mpu_nvml_process_mem_item_1f48_t;

typedef struct mpu_nvml_process_mem_list_1f48 {
    u32 cnt;
    u32 _0;
    mpu_nvml_process_mem_item_1f48_t pl[];
} mpu_nvml_process_mem_list_1f48_t;

// ver. 460
typedef struct mpu_nvml_process_mem_item_2588 {
    u32 pid;
    u32 _0[11];
} mpu_nvml_process_mem_item_2588_t;

typedef struct mpu_nvml_process_mem_list_2588 {
    u32 cnt;
    u32 _0;
    mpu_nvml_process_mem_item_2588_t pl[];
} mpu_nvml_process_mem_list_2588_t;

// ver. 530
typedef struct mpu_nvml_process_mem_item_3848 {
    u32 pid;
    u32 _0[17];
} mpu_nvml_process_mem_item_3848_t;

typedef struct mpu_nvml_process_mem_list_3848 {
    u32 cnt;
    u32 _0;
    mpu_nvml_process_mem_item_3848_t pl[];
} mpu_nvml_process_mem_list_3848_t;

struct nvidia_pidns_call;

typedef int (*nvidia_fixer_t)(struct nvidia_pidns_call *, enum nvidia_fixer_state);

struct nvidia_pidns_call {
    nvidia_fixer_t fixer;
    void *priv;
    void __user *u_ptr;
};

static struct file *nvidia_ctl;

static long (*nvidia_orig_unlocked_ioctl)(struct file *, unsigned int, unsigned long);

static long (*nvidia_orig_compat_ioctl)(struct file *, unsigned int, unsigned long);

static int dummy_fs_init_fs_context(struct fs_context *fc) {
    return init_pseudo(fc, 0xd09858b3) ? 0 : -ENOMEM;
}

static struct file_system_type dummy_fs_type = {
    .owner = THIS_MODULE,
    .name = "nvidia_pidns",
    .init_fs_context = dummy_fs_init_fs_context,
    .kill_sb = kill_anon_super,
};

#define MPU_NV_CAST_PIDS_IMPL(call, st, list_type, item_type)                                                                        \
    {                                                                                                                                \
        u32 pid_count;                                                                                                               \
        u32 *orig_pids = (st == NVIDIA_FIXER_INIT) ? NULL : call->priv;                                                              \
        u32 i;                                                                                                                       \
        int ret = 0;                                                                                                                 \
        if (copy_from_user(&pid_count, call->u_ptr, sizeof(u32))) {                                                                  \
            ret = -EFAULT;                                                                                                           \
            goto out;                                                                                                                \
        }                                                                                                                            \
        if (pid_count > MAX_PID_COUNT) {                                                                                             \
            ret = -EOVERFLOW;                                                                                                        \
            goto out;                                                                                                                \
        }                                                                                                                            \
        switch (st) {                                                                                                                \
            case NVIDIA_FIXER_INIT:                                                                                                  \
                /* save original PIDs */                                                                                             \
                orig_pids = kmalloc(pid_count * sizeof(u32), GFP_KERNEL);                                                            \
                if (!orig_pids) {                                                                                                    \
                    ret = -ENOMEM;                                                                                                   \
                    goto out;                                                                                                        \
                }                                                                                                                    \
                for (i = 0; i < pid_count; i++) {                                                                                    \
                    if (copy_from_user(&orig_pids[i], call->u_ptr + offsetof(list_type, pl) + sizeof(item_type) * i, sizeof(u32))) { \
                        ret = -EFAULT;                                                                                               \
                        goto out;                                                                                                    \
                    }                                                                                                                \
                }                                                                                                                    \
                rcu_read_lock(); /* translate the PIDs */                                                                            \
                for (i = 0; i < pid_count; i++) {                                                                                    \
                    struct pid *pid = find_vpid(orig_pids[i]);                                                                       \
                    u32 ipid = pid ? pid_nr(pid) : 0;                                                                                \
                    if (copy_to_user(call->u_ptr + offsetof(list_type, pl) + sizeof(item_type) * i, &ipid, sizeof(u32))) {           \
                        ret = -EFAULT;                                                                                               \
                        break; /* check ret after leaving loop */                                                                    \
                    }                                                                                                                \
                }                                                                                                                    \
                rcu_read_unlock();                                                                                                   \
                if (ret)                                                                                                             \
                    goto out;                                                                                                        \
                /* save original PIDs into priv */                                                                                   \
                call->priv = orig_pids;                                                                                              \
                orig_pids = NULL;                                                                                                    \
                break;                                                                                                               \
            case NVIDIA_FIXER_ERROR:                                                                                                 \
            case NVIDIA_FIXER_SUCCESS:                                                                                               \
                /* restore original PIDs */                                                                                          \
                for (i = 0; i < pid_count; i++) {                                                                                    \
                    if (copy_to_user(call->u_ptr + offsetof(list_type, pl) + sizeof(item_type) * i, &orig_pids[i], sizeof(u32))) {   \
                        ret = -EFAULT;                                                                                               \
                        break;                                                                                                       \
                    }                                                                                                                \
                }                                                                                                                    \
                break;                                                                                                               \
        }                                                                                                                            \
    out:                                                                                                                             \
        kfree(orig_pids);                                                                                                            \
        return ret;                                                                                                                  \
    }

static int fixer_0x0ee4(struct nvidia_pidns_call *call, enum nvidia_fixer_state st) {
    u32 pid_count;
    u32 *pid_items = NULL;

    u32 wr, rd, i;
    int ret = 0;

    switch (st) {
        case NVIDIA_FIXER_INIT:
            rcu_read_lock();
            break;
        case NVIDIA_FIXER_ERROR:
            rcu_read_unlock();
            break;
        case NVIDIA_FIXER_SUCCESS:
            if (copy_from_user(&pid_count, call->u_ptr + 8, sizeof(u32))) {
                ret = -EFAULT;
                goto out;
            }
            if (pid_count > MAX_PID_COUNT) {
                ret = -EOVERFLOW;
                goto out;
            }

            pid_items = kmalloc(pid_count * sizeof(u32), GFP_KERNEL);
            if (!pid_items) {
                ret = -ENOMEM;
                goto out;
            }

            if (copy_from_user(pid_items, call->u_ptr + 12, pid_count * sizeof(u32))) {
                ret = -EFAULT;
                goto out;
            }

            /* translate PIDs to current namespace */
            for (wr = rd = 0; rd < pid_count; rd++) {
                struct pid *pid = find_pid_ns(pid_items[rd], &init_pid_ns);
                u32 vpid = pid ? pid_vnr(pid) : 0;
                if (vpid) {
                    pid_items[wr++] = vpid;
                }
            }

            /* clear entries after end */
            for (i = wr; i < pid_count; i++) pid_items[i] = 0;

            /* copy results back to userspace */
            if (copy_to_user(call->u_ptr + 8, &wr, sizeof(u32))) {
                ret = -EFAULT;
                goto out;
            }
            if (copy_to_user(call->u_ptr + 12, pid_items, pid_count * sizeof(u32))) {
                ret = -EFAULT;
                goto out;
            }

        out:
            rcu_read_unlock();
            kfree(pid_items);
            break;
        default:
            break;
    }

    return ret;
}

static int fixer_0x1f48(struct nvidia_pidns_call *call, enum nvidia_fixer_state st) MPU_NV_CAST_PIDS_IMPL(call, st, mpu_nvml_process_mem_list_1f48_t, mpu_nvml_process_mem_item_1f48_t);

static int fixer_0x2588(struct nvidia_pidns_call *call, enum nvidia_fixer_state st) MPU_NV_CAST_PIDS_IMPL(call, st, mpu_nvml_process_mem_list_2588_t, mpu_nvml_process_mem_item_2588_t);

static int fixer_0x3848(struct nvidia_pidns_call *call, enum nvidia_fixer_state st) MPU_NV_CAST_PIDS_IMPL(call, st, mpu_nvml_process_mem_list_3848_t, mpu_nvml_process_mem_item_3848_t);

static long fix_before_call(struct nvidia_pidns_call *call, struct file *f, unsigned int cmd, unsigned long ularg) {
    struct nvidia_req_arg arg;
    //    char hex_string[9];
    call->fixer = NULL;

    if (file_inode(f)->i_rdev != NVIDIA_CTL_RDEV) {
        return 0;
    }

    if (cmd != _IOC(_IOC_READ | _IOC_WRITE, 'F', 0x2a, sizeof(arg))) {
        return 0;
    }

    if (copy_from_user(&arg, (void __user *)ularg, sizeof(arg))) {
        return -EFAULT;
    }
    //    snprintf(hex_string, sizeof(hex_string), "%x", arg.tag);
    //    printk(KERN_INFO "fix_before_call arg.cmd:%u-%s  \n", arg.tag, hex_string);
    switch (arg.tag) {
        case 0x0ee4:
            call->fixer = fixer_0x0ee4;
            break;
        case 0x1f48:
            call->fixer = fixer_0x1f48;
            break;
        case 0x2588:
            call->fixer = fixer_0x2588;
            break;
        case 0x3848:
            call->fixer = fixer_0x3848;
            break;
        default:
            return 0;
    }
    call->u_ptr = arg.u_ptr;
    call->priv = NULL;
    return call->fixer(call, NVIDIA_FIXER_INIT);
}

static long fix_after_call(struct nvidia_pidns_call *call, long ret) {
    if (call->fixer) {
        if (ret == 0)
            ret = call->fixer(call, NVIDIA_FIXER_SUCCESS);
        else
            call->fixer(call, NVIDIA_FIXER_ERROR);
    }
    return ret;
}

static long nvidia_pidns_unlocked_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    struct nvidia_pidns_call call;
    long ret;

    ret = fix_before_call(&call, f, cmd, arg);
    if (ret == 0) {
        ret = nvidia_orig_unlocked_ioctl(f, cmd, arg);
    }
    ret = fix_after_call(&call, ret);
    return ret;
}

static long nvidia_pidns_compat_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    struct nvidia_pidns_call call;
    long ret;

    ret = fix_before_call(&call, f, cmd, arg);
    if (ret == 0) {
        ret = nvidia_orig_compat_ioctl(f, cmd, arg);
    }
    ret = fix_after_call(&call, ret);

    return ret;
}

static struct file *find_nvidia_ctl(void) {
    struct vfsmount *mnt = NULL;
    struct inode *inode = NULL;
    struct file *file = NULL;
    struct dentry *dentry = NULL;
    struct path path;

    mnt = kern_mount(&dummy_fs_type);
    if (IS_ERR(mnt)) {
        file = ERR_CAST(mnt);
        mnt = NULL;
        goto out;
    }

    inode = alloc_anon_inode(mnt->mnt_sb);
    if (IS_ERR(inode)) {
        file = ERR_CAST(inode);
        inode = NULL;
        goto out;
    }
    init_special_inode(inode, S_IFCHR | 0666, NVIDIA_CTL_RDEV);

    dentry = d_alloc_anon(mnt->mnt_sb);
    if (!dentry) {
        file = ERR_PTR(-ENOMEM);
        goto out;
    }
    dentry = d_instantiate_anon(dentry, inode);
    inode = NULL;

    path.mnt = mnt;
    path.dentry = dentry;
    file = dentry_open(&path, O_RDWR, current_cred());

    if (IS_ERR(file))
        pr_err("nvidia-pidns: failed to open nvidiactl (%ld), is the nvidia module loaded?\n", PTR_ERR(file));

out:
    if (dentry)
        dput(dentry);
    if (inode)
        iput(inode);
    if (mnt)
        kern_unmount(mnt);
    return file;
}

static int nvidia_pidns_init(void) {
    struct file_operations *fops;
    struct file *f = find_nvidia_ctl();
    printk(KERN_INFO "nvidia_pidns_init \n");

    if (IS_ERR(f))
        return PTR_ERR(f);

    nvidia_ctl = f;
    fops = (struct file_operations *)f->f_op;

    /* Save original callbacks so we can use them later */
    nvidia_orig_unlocked_ioctl = fops->unlocked_ioctl;
    nvidia_orig_compat_ioctl = fops->compat_ioctl;

    /* Replace with our wrappers */
    wmb();
    fops->unlocked_ioctl = nvidia_pidns_unlocked_ioctl;
    fops->compat_ioctl = nvidia_pidns_compat_ioctl;

    return 0;
}

static void nvidia_pidns_exit(void) {
    struct file *f = nvidia_ctl;
    struct file_operations *fops = (struct file_operations *)f->f_op;
    printk(KERN_INFO "nvidia_pidns_exit \n");
    fops->unlocked_ioctl = nvidia_orig_unlocked_ioctl;
    fops->compat_ioctl = nvidia_orig_compat_ioctl;
    wmb();
    fput(nvidia_ctl);
}

module_init(nvidia_pidns_init);
module_exit(nvidia_pidns_exit);
MODULE_LICENSE("GPL");
MODULE_SOFTDEP("pre: nvidia");

// vim: noet
