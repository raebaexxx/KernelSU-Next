#include <linux/compiler.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/workqueue.h>
#include <linux/thread_info.h>
#include <linux/seccomp.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/susfs_def.h>
#include "selinux/selinux.h"

#include "policy/allowlist.h"
#include "hook/setuid_hook.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_identity.h"
#include "infra/seccomp_cache.h"
#include "supercall/supercall.h"
#include "hook/tp_marker.h"
#include "feature/kernel_umount.h"

#ifdef CONFIG_KSU_SUSFS
extern struct work_struct susfs_extra_works;

static inline void ksu_handle_extra_susfs_work(void)
{
    if (work_pending(&susfs_extra_works))
        return;

    schedule_work(&susfs_extra_works);
}
#endif // #ifdef CONFIG_KSU_SUSFS

int ksu_handle_setresuid(uid_t old_uid, uid_t new_uid)
{
    // we rely on the fact that zygote always call setresuid(3) with same uids

    pr_info("handle_setresuid from %d to %d\n", old_uid, new_uid);

    if (unlikely(is_uid_manager(new_uid))) {
        spin_lock_irq(&current->sighand->siglock);
        ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
        ksu_set_task_tracepoint_flag(current);
        spin_unlock_irq(&current->sighand->siglock);

        pr_info("install fd for manager: %d\n", new_uid);
        ksu_install_fd();
        return 0;
    }

    if (ksu_is_allow_uid_for_current(new_uid)) {
        if (current->seccomp.mode == SECCOMP_MODE_FILTER &&
            current->seccomp.filter) {
            spin_lock_irq(&current->sighand->siglock);
            ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
            spin_unlock_irq(&current->sighand->siglock);
        }
        ksu_set_task_tracepoint_flag(current);
    } else {
        ksu_clear_task_tracepoint_flag_if_needed(current);
#ifdef CONFIG_KSU_SUSFS
        susfs_set_current_proc_no_su();
#endif // #ifdef CONFIG_KSU_SUSFS
    }

#ifdef CONFIG_KSU_SUSFS
    // Mirror susfs4ksu: tell susfs which of the zygote-spawned processes run in a
    // mount namespace without the sus mounts, so it can apply sus_path / sus_mount /
    // sus_kstat / sus_map spoofing only where it is supposed to apply.
    //
    // Scenarios: zygote -> appuid (normal), zygote -> isolated process,
    // zygote -> app zygote, zygote -> webview zygote. The isolated processes
    // forked from app/webview zygotes are covered by those two cases.
    if (is_isolated_process(new_uid) ||
        (is_appuid(new_uid) && ksu_uid_should_umount(new_uid))) {
        susfs_set_current_proc_umounted();
    } else if (!is_appuid(new_uid) && new_uid != WEBVIEW_ZYGOTE_UID) {
        susfs_set_current_proc_no_su();
    }
#endif // #ifdef CONFIG_KSU_SUSFS

    // Handle kernel umount
    ksu_handle_umount(old_uid, new_uid);

#ifdef CONFIG_KSU_SUSFS
    // Run the extra susfs work after the umount so it sees a settled namespace.
    if (susfs_is_current_proc_umounted())
        ksu_handle_extra_susfs_work();
#endif // #ifdef CONFIG_KSU_SUSFS

    return 0;
}

void __init ksu_setuid_hook_init(void)
{
    ksu_kernel_umount_init();
}

void __exit ksu_setuid_hook_exit(void)
{
    pr_info("ksu_core_exit\n");
    ksu_kernel_umount_exit();
}
