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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Ftrace-based syscall hooking module");
MODULE_VERSION("1.0");

// Retrieve the address of the funtion used for hooking
static unsigned long lookup_name(const char *name) {

  // Resolution of the function address is taken care of by the Kernel as per
  // API reference
  struct kprobe kp = {.symbol_name = name};

  unsigned long retval;

  if (register_kprobe(&kp) > 0)
    return 0;

  printk(KERN_INFO "%px\n", kp.addr);

  retval = (unsigned long)kp.addr;
  unregister_kprobe(&kp);
  printk(KERN_ERR "Address %x\n", retval);
  return retval;
}

#define HOOK(_name, _hook, _orig)                                              \
  {                                                                            \
      .name = (_name),                                                         \
      .function = (_hook),                                                     \
      .original = (_orig),                                                     \
  }

struct ftrace_hook {
  const char *name;
  void *function;
  void *original;
  unsigned long address;
  struct ftrace_ops ops;
};

static int fh_resolve_hook_address(struct ftrace_hook *hook) {
  hook->address = lookup_name(hook->name);
  if (!hook->address) {
    printk(KERN_ERR "Failed to resolve %s\n", hook->name);
    return -ENOENT;
  }
  *((unsigned long *)hook->original) = hook->address;
  return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops,
                                    struct ftrace_regs *fregs) {
  struct pt_regs *regs = ftrace_get_regs(fregs);
  struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

  if (!within_module(parent_ip, THIS_MODULE))
    regs->ip = (unsigned long)hook->function;
}

int fh_install_hook(struct ftrace_hook *hook);
int fh_install_hook(struct ftrace_hook *hook) {
  int err;

  err = fh_resolve_hook_address(hook);
  if (err)
    return err;

  hook->ops.func = fh_ftrace_thunk;
  hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION |
                    FTRACE_OPS_FL_IPMODIFY;

  err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
  if (err) {
    pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
    return err;
  }

  err = register_ftrace_function(&hook->ops);
  if (err) {
    pr_debug("register_ftrace_function() failed: %d\n", err);
    ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    return err;
  }

  return 0;
}

void fh_remove_hook(struct ftrace_hook *hook);
void fh_remove_hook(struct ftrace_hook *hook) {
  int err;

  err = unregister_ftrace_function(&hook->ops);
  if (err) {
    pr_debug("unregister_ftrace_function() failed: %d\n", err);
  }

  err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
  if (err) {
    pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
  }
}

static asmlinkage long (*real_sys_openat)(struct pt_regs *regs);

static asmlinkage long openat_hook(struct pt_regs *regs) {
  long ret;

  printk(KERN_ERR "Hooked Function\n");
  // printk((char __user *)regs->di);
  ret = real_sys_openat(regs);

  return ret;
}

struct ftrace_hook demo_hook =
    HOOK("__x64_sys_openat", openat_hook, &real_sys_openat);

static int fh_init(void) {
  int err;

  err = fh_install_hook(&demo_hook);
  if (err)
    return err;

  pr_info("module loaded\n");

  return 0;
}
module_init(fh_init);

static void fh_exit(void) {
  fh_remove_hook(&demo_hook);

  pr_info("module unloaded\n");
}
module_exit(fh_exit);
