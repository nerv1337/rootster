#ifndef OPENAT_H_ /* Include guard */
#define OPENAT_H_

#include "linux/linkage.h"
#include "linux/ptrace.h"

extern asmlinkage long (*real_sys_openat)(struct pt_regs *regs);
extern asmlinkage long openat_hook(struct pt_regs *regs);

#endif // OPENAT_H_
