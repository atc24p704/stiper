#ifndef _UAPI_ASM_X86_STIPER_H
#define _UAPI_ASM_X86_STIPER_H

#ifndef __ASSEMBLY__
#include <linux/types.h>
#include <linux/time.h>
#include <linux/compiler.h>

#ifdef CONFIG_STIPER
struct sm_info {
	char *ptr;
	unsigned long size;
};

struct meta_info {
	unsigned long mi_flags;
	unsigned long mi_size;
};
#endif /* CONFIG_STIPER */

#endif /* ! __ASSEMBLY__ */

#endif /* _UAPI_ASM_X86_STIPER_H */
