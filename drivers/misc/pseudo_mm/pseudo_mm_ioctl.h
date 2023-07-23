#ifndef __PSEUDO_MM_IOCTL_H__
#define __PSEUDO_MM_IOCTL_H__

#include <linux/ioctl.h>
#include <linux/types.h>

#define PSEUDO_MM_IOC_MAGIC 0x1c

struct pseudo_mm_add_anon_param {
	int id;
	unsigned long start;
	unsigned long end;
	unsigned long prot;
	unsigned long flags;
};

struct pseudo_mm_fill_anon_param {
	int id;
	unsigned long start;
	unsigned long end;
	int fd; // file descriptor of memory image file
	off_t offset;	// offset within the image file
};

struct pseudo_mm_attach_param {
	pid_t pid;
	int id;
};

#define PSEUDO_MM_IOC_CREATE _IOR(PSEUDO_MM_IOC_MAGIC, 0x00, int *)
#define PSEUDO_MM_IOC_DELETE _IOW(PSEUDO_MM_IOC_MAGIC, 0x01, int *)
#define PSEUDO_MM_IOC_ADD_ANON \
	_IOW(PSEUDO_MM_IOC_MAGIC, 0x02, struct pseudo_mm_add_anon_param *)
#define PSEUDO_MM_IOC_FILL_ANON \
	_IOW(PSEUDO_MM_IOC_MAGIC, 0x03, struct pseudo_mm_fill_anon_param *)
#define PSEUDO_MM_IOC_ATTACH \
	_IOW(PSEUDO_MM_IOC_MAGIC, 0x04, struct pseudo_mm_attach_param *)

#endif
