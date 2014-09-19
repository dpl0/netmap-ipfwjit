#include "ip_fw_private.h"

typedef int (*funcptr)();

funcptr compile_code(struct ip_fw_args *, struct ip_fw_chain *);
