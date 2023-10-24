// SPDX-License-Identifier: GPL-2.0-only
/*
 * This module provides an interface to operate pseudo_mm
 */

#define pr_fmt(fmt) "pseudo_mm_driver:%s: " fmt, __func__

#include <linux/device.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/pseudo_mm.h>

#include "pseudo_mm_memory.h"
#include "pseudo_mm_ioctl.h"

static int pseudo_mm_open(struct inode *, struct file *);
static int pseudo_mm_release(struct inode *, struct file *);
static long pseudo_mm_unlocked_ioctl(struct file *, unsigned int,
				     unsigned long);

static const struct file_operations fops = {
	.open = pseudo_mm_open,
	.release = pseudo_mm_release,
	.unlocked_ioctl = pseudo_mm_unlocked_ioctl,
};

struct miscdevice pseudo_mm_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "pseudo_mm",
	.fops = &fops,
};

static int pseudo_mm_open(struct inode *inode, struct file *filp)
{
	// actually we do nothing here when open the file for now
	return 0;
}

static int pseudo_mm_release(struct inode *inode, struct file *filp)
{
	// actually we do nothing here when close the file for now
	return 0;
}

// Return 0 when succeed
static inline long _pseudo_mm_add_map(void *__user args)
{
	struct pseudo_mm_add_map_param param;
	unsigned long err = 0;
	unsigned long start, size;

	err = copy_from_user(&param, args, sizeof(param));
	if (err)
		return err;
	start = param.start;
	if (param.end < param.start)
		return -EINVAL;
	size = param.end - param.start;

	err = pseudo_mm_add_map(param.id, start, size, param.prot, param.flags,
				param.fd, param.offset >> PAGE_SHIFT);
	return err;
}

static inline long _pseudo_mm_attach(void *__user args)
{
	struct pseudo_mm_attach_param param;
	unsigned long err;

	err = copy_from_user(&param, args, sizeof(param));
	if (err)
		return err;
	err = pseudo_mm_attach(param.pid, param.id);
	return err;
}

static inline long _pseudo_mm_setup_pt(void *__user args)
{
	struct pseudo_mm_setup_pt_param param;
	unsigned long err;
	err = copy_from_user(&param, args, sizeof(param));
	if (err)
		return err;
	err = pseudo_mm_setup_pt(param.id, param.start, param.size,
				 param.pgoff);
	return err;
}

static inline long _pseudo_mm_bring_back(void *__user args)
{
	struct pseudo_mm_bring_back_param param;
	unsigned long err;
	err = copy_from_user(&param, args, sizeof(param));
	if (err)
		return err;
	err = pseudo_mm_bring_back(param.id, param.start, param.size);
	return err;
}

static long pseudo_mm_unlocked_ioctl(struct file *filp, unsigned int cmd,
				     unsigned long args)
{
	int pseudo_mm_id, fd;
	long err = 0;

	// all ioctl in pseudo_mm need args
	if (!args)
		return -EINVAL;

	switch (cmd) {
	case PSEUDO_MM_IOC_REGISTER:
		err = copy_from_user(&fd, (const void *)args, sizeof(fd));
		if (err)
			return err;
		err = register_backend_dax_device(fd);
		if (err)
			return err;
		break;
	case PSEUDO_MM_IOC_CREATE:
		// create a new pseudo_mm and return the id of it
		pseudo_mm_id = create_pseudo_mm();
		if (pseudo_mm_id < 0)
			return pseudo_mm_id;
		err = copy_to_user((void *)args, &pseudo_mm_id,
				   sizeof(pseudo_mm_id));
		if (err)
			return err;
		break;
	case PSEUDO_MM_IOC_DELETE:
		err = copy_from_user(&pseudo_mm_id, (const void *)args,
				     sizeof(pseudo_mm_id));
		if (err)
			return err;
		put_pseudo_mm_with_id(pseudo_mm_id);
		break;
	case PSEUDO_MM_IOC_ADD_MAP:
		err = _pseudo_mm_add_map((void *)args);
		if (err)
			return err;
		break;
	case PSEUDO_MM_IOC_SETUP_PT:
		err = _pseudo_mm_setup_pt((void *)args);
		if (err)
			return err;
		break;
	case PSEUDO_MM_IOC_ATTACH:
		err = _pseudo_mm_attach((void *)args);
		if (err)
			return err;
		break;
	case PSEUDO_MM_IOC_BRING_BACK:
		err = _pseudo_mm_bring_back((void *)args);
		if (err)
			return err;
		break;
	default:
		pr_warn("pseudo_mm_misc driver receive known cmd %u\n", cmd);
		return -EINVAL;
	}

	return 0;
}

static int __init pseudo_mm_driver_init(void)
{
	int err;

	err = misc_register(&pseudo_mm_device);
	if (err) {
		pr_err("pseudo_mm_misc driver register failed\n");
		return err;
	}

	pr_info("pseudo_mm_misc driver register succeed !\n");
	return 0;
}

static void __exit pseudo_mm_driver_exit(void)
{
	misc_deregister(&pseudo_mm_device);
	pr_info("pseudo_mm_misc driver exit !\n");
}

module_init(pseudo_mm_driver_init);
module_exit(pseudo_mm_driver_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("huang-jl <huangjl22@mails.tsinghua.edu.cn>");
MODULE_DESCRIPTION("A driver used for exposing interface of pseudo_mm");
MODULE_VERSION("0.1");
