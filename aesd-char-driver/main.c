/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h>   // file_operations
#include <linux/slab.h> // kmalloc

#include "aesd_ioctl.h"
#include "aesdchar.h"

int aesd_major = 0; // use dynamic major
int aesd_minor = 0;

MODULE_AUTHOR("Florian Depraz");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device; // should be put in privae data..

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    return 0;
}
ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                  loff_t *f_pos)
{
    ssize_t retval = 0;
    size_t entry_offset = 0;

    if (filp == NULL || buf == NULL)
    {
        PDEBUG("arguments");
        return -EINVAL;
    }

    if (mutex_lock_interruptible(&aesd_device.mutex) != 0)
    {
        PDEBUG("on acquire mutex");
        return -ERESTARTSYS;
    }

    struct aesd_buffer_entry *entry = aesd_circular_buffer_find_entry_offset_for_fpos(&aesd_device.buffer, *f_pos, &entry_offset);
    if (entry != NULL)
    {
        retval = copy_to_user(buf, (entry->buffptr + entry_offset), (entry->size - entry_offset));
        retval = (entry->size - entry_offset) - retval;
        *f_pos += retval;
    }

    PDEBUG("aesd_read returns %ld", retval);

    mutex_unlock(&aesd_device.mutex);

    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                   loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;

    PDEBUG("write %zu bytes with offset %lld", count, *f_pos);

    if (filp == NULL || buf == NULL)
    {
        PDEBUG("invalid arguments");
        return -EINVAL;
    }

    if (mutex_lock_interruptible(&aesd_device.mutex) != 0)
    {
        PDEBUG("on acquire mutex");
        return -ERESTARTSYS;
    }

    if (aesd_device.current_entry_c.size == 0)
    {
        aesd_device.current_entry_c.buffptr = (char *)kmalloc(count, GFP_KERNEL);
    }
    else
    {
        aesd_device.current_entry_c.buffptr = (char *)krealloc(aesd_device.current_entry_c.buffptr,
                                              aesd_device.current_entry_c.size + count, GFP_KERNEL);
    }

    if (aesd_device.current_entry_c.buffptr == NULL)
    {
        PDEBUG("on memory");
        retval = -ENOMEM;
        // Continue for unlock lock
    }
    else
    {
        if (copy_from_user((void *)aesd_device.current_entry_c.buffptr + aesd_device.current_entry_c.size, buf, count) != 0)
        {
            return -EFAULT;
        }

        aesd_device.current_entry_c.size += count;
        if (aesd_device.current_entry_c.buffptr[(aesd_device.current_entry_c.size - 1)] == '\n')
        {
            void* ptrToBeFreed = aesd_circular_buffer_add_entry(&aesd_device.buffer, &aesd_device.current_entry_c);
            if (ptrToBeFreed != NULL)
            {
                kfree(ptrToBeFreed);
            }

            aesd_device.current_entry_c.buffptr = NULL;
            aesd_device.current_entry_c.size = 0;
        }

        retval = count;
    }

    mutex_unlock(&aesd_device.mutex);

    return retval;
}

static long aesd_adjust_file_offset(struct file *filp, unsigned int write_cmd, unsigned int write_cmd_offset)
{
    long retval = 0;
    int index = 0;

    if (filp == NULL)
    {
        PDEBUG("arguments");
        return -EINVAL;
    }

    if (mutex_lock_interruptible(&aesd_device.mutex) != 0)
    {
        PDEBUG("on acquire mutex");
        return -ERESTARTSYS;
    }

    struct aesd_buffer_entry *entry = NULL;
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, index){}

    if (write_cmd > index ||
        write_cmd > AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED ||
        write_cmd_offset >= aesd_device.buffer.entry[write_cmd].size)
    {
        retval = -EINVAL;
        // Continue for unlock
    }
    else
    {
        for (index = 0; index < write_cmd; index++)
        {
            filp->f_pos += aesd_device.buffer.entry[index].size;
        }

        filp->f_pos += write_cmd_offset;
    }

    mutex_unlock(&aesd_device.mutex);

    return retval;
}

long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    long retval = 0;
    struct aesd_seekto seekto;

    if (filp == NULL)
    {
        PDEBUG("arguments");
        return -EINVAL;
    }

    if (_IOC_TYPE(cmd) != AESD_IOC_MAGIC)
        return -ENOTTY;
    if (_IOC_NR(cmd) > AESDCHAR_IOC_MAXNR)
        return -ENOTTY;

    switch (cmd)
    {
    case AESDCHAR_IOCSEEKTO:
        if (copy_from_user(&seekto, (const void __user *)arg, sizeof(seekto)) != 0)
            retval = -EFAULT;
        else
            retval = aesd_adjust_file_offset(filp, seekto.write_cmd, seekto.write_cmd_offset);
        break;

    default:
        retval = -ENOTTY;
        break;
    }

    return retval;
}

loff_t aesd_llseek(struct file *filp, loff_t off, int whence)
{
    loff_t newpos;
    loff_t size = 0;
    int index = 0;
    struct aesd_buffer_entry *entry = NULL;

    if (filp == NULL)
    {
        PDEBUG("arguments");
        return -EINVAL;
    }

    if (mutex_lock_interruptible(&aesd_device.mutex) != 0)
    {
        PDEBUG("on acquire mutex");
        return -ERESTARTSYS;
    }

    {
        AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, index)
        size += entry->size;

        newpos = fixed_size_llseek(filp, off, whence, size);

    } mutex_unlock(&aesd_device.mutex);

    return newpos;
}

struct file_operations aesd_fops = {
    .owner = THIS_MODULE,
    .read = aesd_read,
    .write = aesd_write,
    .open = aesd_open,
    .release = aesd_release,
    .llseek = aesd_llseek,
    .unlocked_ioctl = aesd_ioctl};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add(&dev->cdev, devno, 1);
    if (err)
    {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}

int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
                                 "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0)
    {
        printk(KERN_WARNING "Can't get major %d", aesd_major);
        return result;
    }
    memset(&aesd_device, 0, sizeof(struct aesd_dev));
    // init mutex
    mutex_init(&aesd_device.mutex);

    aesd_circular_buffer_init(&aesd_device.buffer);

    result = aesd_setup_cdev(&aesd_device);

    if (result)
    {
        unregister_chrdev_region(dev, 1);
    }
    return result;
}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    uint8_t index;
    struct aesd_buffer_entry *entry;
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, index)
    {
        kfree(entry->buffptr);
    }

    // Cleanup mutex
    mutex_destroy(&aesd_device.mutex);

    aesd_device.buffer.in_offs = 0;
    aesd_device.buffer.out_offs = 0;
    aesd_device.buffer.full = false;

    unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
