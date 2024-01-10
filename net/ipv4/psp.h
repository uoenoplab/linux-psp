#include <linux/types.h>

// 25 seems like a good number
#define AF_PSP		25
#define PF_PSP		AF_PSP
#define PSP_PROTO_NAME			"PSP"
#define PSP_PROC_NET_FILENAME		"PSP_stats"
#define PSP_PROC_FULL_FILENAME		"/proc/net/" PSP_PROC_NET_FILENAME
