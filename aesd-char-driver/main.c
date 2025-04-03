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
struct aesd_dev aesd_dev;

MODULE_AUTHOR("Florian Depraz");
MODULE_LICENSE("Dual BSD/GPL");

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    filp->private_data = container_of(inode->i_cdev, struct aesd_dev, cdev);
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    filp->private_data = NULL;
    return 0;
}

/* Reads count of data from kernel space driver file into user space buf */
ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                  loff_t *f_pos)
{
    ssize_t retval = 0;
    PDEBUG("read %zu bytes with offset %lld", count, *f_pos);

    struct aesd_dev *dev = filp->private_data;
    // Invalid arguments
    if (filp == NULL || buf == NULL || f_pos == NULL)
    {
        PDEBUG("Invalid arguments");
        return -EINVAL;
    }

    // Try to lock the device mutex
    int res = mutex_lock_interruptible(&dev->mutex);
    if (res != 0)
    {
        PDEBUG("Unable to lock device mutex");
        return -ERESTARTSYS;
    }

    // Looks for the entry in buffer based on given fpos
    size_t entry_offset = 0;
    struct aesd_buffer_entry *entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->buffer, *f_pos, &entry_offset);
    if (entry == NULL)
    {
        PDEBUG("Unable to find entry");
        mutex_unlock(&dev->mutex);
        return retval;
    }

    // Find the available bytes remaining to be read
    size_t bytes_remaining = entry->size - entry_offset;

    // Reads only up to count maximum bytes
    if (bytes_remaining >= count)
    {
        bytes_remaining = count;
    }

    // Copy remaining bytes to user space buf from the location indicated by fpos
    unsigned long bytes_not_copied = copy_to_user(buf, entry->buffptr + entry_offset, bytes_remaining);

    // All bytes to be copied should be copied
    if (bytes_not_copied != 0)
    {
        PDEBUG("Unable to do user-kernel copy");
        mutex_unlock(&dev->mutex);
        return -EFAULT;
    }

    // Increment fpos by number of bytes read
    *f_pos += bytes_remaining;
    // Release the mutex
    mutex_unlock(&dev->mutex);
    // Set return value to number of bytes copied
    retval = bytes_remaining;

    return retval;
}

/* Writes count of data from user space buf into kernel space driver file */
ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                   loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    PDEBUG("write %zu bytes with offset %lld", count, *f_pos);

    // Invalid arguments
    if (filp == NULL || buf == NULL || f_pos == NULL)
    {
        PDEBUG("Invalid arguments");
        return -EINVAL;
    }

    char *data = kmalloc(count, GFP_KERNEL);

    if (data == NULL)
    {
        PDEBUG("Unable to allocate memory");
        return -ENOMEM;
    }

    // Copy data to be written from user space
    unsigned long bytes_not_copied = copy_from_user(data, buf, count);
    PDEBUG("Data: %s", data);

    if (bytes_not_copied != 0)
    {
        PDEBUG("Unable to copy data from user space");
        kfree(data);
        return -EFAULT;
    }

    // Check if newline present in data up to count
    int newline_pos = 0;
    bool write_complete = false;
    char *newline_ptr = memchr(data, '\n', count);
    // If no newline, write not complete, so newline_pos set to maximal count
    if (newline_ptr == NULL)
    {
        newline_pos = count;
        // Newline present, write complete and set newline_pos to offset of newline char from start of data
    }
    else
    {
        newline_pos = newline_ptr - data + 1;
        write_complete = true;
    }

    struct aesd_dev *dev = filp->private_data;

    int res = mutex_lock_interruptible(&dev->mutex);
    if (res != 0)
    {
        PDEBUG("Unable to lock device mutex");
        kfree(data);
        return -ERESTARTSYS;
    }

    // New data size adds up to newline
    size_t old_size = dev->entry.size;
    dev->entry.size += newline_pos;

    // Reallocate memory to append new write data
    char *new_entry_loc = krealloc(dev->entry.buffptr, dev->entry.size, GFP_KERNEL);

    if (new_entry_loc == NULL)
    {
        PDEBUG("Unable to reallocate memory");
        kfree(data);
        mutex_unlock(&dev->mutex);
        return -ENOMEM;
    }

    // Update entry to new memory location
    dev->entry.buffptr = new_entry_loc;

    // Copy data into newly allocated space
    memcpy(dev->entry.buffptr + old_size, data, newline_pos);

    // Write complete
    if (write_complete)
    {
        // Add entry to circular buffer
        aesd_circular_buffer_add_entry(&dev->buffer, &dev->entry);
        PDEBUG("Entry added to buffer");
        // Reset device entry
        dev->entry.size = 0;
        dev->entry.buffptr = NULL;
    }

    // Unlock mutex
    mutex_unlock(&dev->mutex);
    // Release data
    kfree(data);

    return newline_pos;
}

long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct aesd_dev *dev = filp->private_data;

    if (cmd == AESDCHAR_IOCSEEKTO)
    {

        PDEBUG("IOCTL Detected");

        // Try to lock the device mutex
        int res = mutex_lock_interruptible(&dev->mutex);
        if (res != 0)
        {
            PDEBUG("Unable to lock device mutex");
            return -ERESTARTSYS;
        }

        // Define type of seek performed on the aesdchar driver
        struct aesd_seekto seek_details;

        // Copy user arg into seekto struct
        unsigned long bytes_not_copied = copy_from_user(&seek_details, (const void __user *)arg, sizeof(seek_details));

        if (bytes_not_copied != 0)
        {
            PDEBUG("Unable to copy arg from user space");
            mutex_unlock(&dev->mutex);
            return -EFAULT;
        }

        // If write cmd out of range of the number of write commands, error
        if (seek_details.write_cmd > AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
        {
            PDEBUG("Out of range write command");
            mutex_unlock(&dev->mutex);
            return -EINVAL;
        }
        // If write cmd offset out of range of the command length, error
        else if (seek_details.write_cmd_offset > dev->buffer.entry[seek_details.write_cmd].size)
        {
            PDEBUG("Out of range write offset");
            mutex_unlock(&dev->mutex);
            return -EINVAL;
        }

        PDEBUG("seek command: %d, %d", seek_details.write_cmd, seek_details.write_cmd_offset);

        // Seek to start of command and add the offset within the command
        loff_t new_offset = 0;
        for (int i = 0; i < seek_details.write_cmd; i++)
        {
            new_offset += dev->buffer.entry[i].size;
        }
        new_offset += seek_details.write_cmd_offset;

        // Update file position pointer to new offset
        filp->f_pos = new_offset;
        mutex_unlock(&dev->mutex);
        return 0;
    }
    else
    {
        mutex_unlock(&dev->mutex);
        return -ENOTTY;
    }
}

loff_t aesd_llseek(struct file *filp, loff_t offset, int whence)
{
    PDEBUG("llseek Triggered");

    struct aesd_dev *dev = filp->private_data;

    // Try to lock the device mutex
    int res = mutex_lock_interruptible(&dev->mutex);
    if (res != 0)
    {
        PDEBUG("Unable to lock device mutex");
        return -ERESTARTSYS;
    }

    // Total size of all entries in the buffer
    loff_t total_size = 0;
    struct aesd_buffer_entry *entry;
    uint8_t index = 0;
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &dev->buffer, index)
    {
        if (entry->buffptr)
        {
            total_size += entry->size;
        }
    }

    PDEBUG("total_size: %d", total_size);

    // Reposition offset for fixed-sized device
    loff_t fixed_size_offset = fixed_size_llseek(filp, offset, whence, total_size);

    PDEBUG("llseek offset: %d", fixed_size_offset);

    mutex_unlock(&dev->mutex);

    return fixed_size_offset;
}

struct file_operations aesd_fops = {
    .owner = THIS_MODULE,
    .read = aesd_read,
    .write = aesd_write,
    .open = aesd_open,
    .release = aesd_release,
    .llseek = aesd_llseek,
    .unlocked_ioctl = aesd_ioctl,
};

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
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_dev, 0, sizeof(struct aesd_dev));

    aesd_circular_buffer_init(&aesd_dev.buffer);
    mutex_init(&aesd_dev.mutex);

    result = aesd_setup_cdev(&aesd_dev);

    if (result)
    {
        unregister_chrdev_region(dev, 1);
    }
    return result;
}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_dev.cdev);

    struct aesd_buffer_entry *entry;
    uint8_t index = 0;
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_dev.buffer, index)
    {
        if (entry->buffptr)
        {
            kfree(entry->buffptr);
        }
    }

    mutex_destroy(&aesd_dev.mutex);
    unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);