/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-crypto device 
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 */
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"

#include "cryptodev.h"

/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;
//spinlock_t devlock;
/**
 * Given the minor number of the inode return the crypto device 
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
	struct crypto_device *crdev;
	unsigned long flags;

	debug("Entering");

	spin_lock_irqsave(&crdrvdata.lock, flags);
	list_for_each_entry(crdev, &crdrvdata.devs, list) {
		if (crdev->minor == minor)
			goto out;
	}
	crdev = NULL;

out:
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	debug("Leaving");
	return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
	int ret = 0;
	int err;
	unsigned int len;
	struct crypto_open_file *crof;
	struct crypto_device *crdev;
	unsigned int *syscall_type;
	//int *host_fd;
	struct virtqueue *vq;
	unsigned int num_in = 0;
        unsigned int num_out = 0;
	struct scatterlist syscall_type_sg, host_fd_sg,
                           *sgs[2];

	unsigned long flags;

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_OPEN;
	//host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	//*host_fd = -1;

	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0){
		goto fail;
	}

	/* Associate this open file with the relevant crypto device. */
	crdev = get_crypto_dev_by_minor(iminor(inode));
	if (!crdev) {
		debug("Could not find crypto device with %u minor", 
		      iminor(inode));
		ret = -ENODEV;
		goto fail;
	}

	crof = kzalloc(sizeof(*crof), GFP_KERNEL);
	if (!crof) {
		ret = -ENOMEM;
		goto fail;
	}
	crof->crdev = crdev;
	crof->host_fd = -1;
	filp->private_data = crof;

	vq = crdev->vq;

	/**
	 * We need two sg lists, one for syscall_type and one to get the 
	 * file descriptor from the host.
	 **/

	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;

	sg_init_one(&host_fd_sg, &crof->host_fd, sizeof(crof->host_fd));
	sgs[num_out + num_in++] = &host_fd_sg;
	
	spin_lock_irqsave(&crdev->devlock, flags);
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);

	virtqueue_kick(vq);
	/* ?? */
	//spin_unlock_irqrestore(&crdev->devlock, flags);
	/**
	 * Wait for the host to process our data.
	 **/
	while(virtqueue_get_buf(vq, &len) == NULL)
		/*do nothing*/;
	/* ?? */
	spin_unlock_irqrestore(&crdev->devlock, flags);
	//debug("Backend returned the following fd: %d\n", ret);

	/* If host failed to open() return -ENODEV. */
	if(crof->host_fd < 0){
		debug("Host failed to open an fd\n");
	}
	else
		debug("Host returned the following fd: %d\n", crof->host_fd);
	/* ?? */
fail:
	debug("Leaving");
	return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
	int ret = 0;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	unsigned int *syscall_type;
	int err;
	struct virtqueue *vq;
        //int host_fd;
        unsigned int num_in = 0;
        unsigned int num_out = 0;
        unsigned int len;
	struct scatterlist syscall_type_sg, host_fd_sg,
                           *sgs[2];

	unsigned long flags;

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_CLOSE;

	/**
	 * Send data to the host.
	 **/

	vq  = crdev->vq;

	//host_fd = crof->host_fd;

	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;

	sg_init_one(&host_fd_sg, &crof->host_fd, sizeof(crof->host_fd));
	sgs[num_out++] = &host_fd_sg;
	
	spin_lock_irqsave(&crdev->devlock, flags);
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);

	virtqueue_kick(vq);
	/* ?? */
	//spin_unlock_irqrestore(&crdev->devlock, flags);
	/**
	 * Wait for the host to process our data.
	 **/
	while(virtqueue_get_buf(vq, &len) == NULL)
		/*do nothing*/;
	/* ?? */
	spin_unlock_irqrestore(&crdev->devlock, flags);

	kfree(crof);
	debug("Leaving");
	return ret;

}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd, 
                                unsigned long arg)
{
	long ret = 0;
	int err;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	struct scatterlist syscall_type_sg, host_fd_sg, cmd_sg, return_val_sg, session_key_sg, session_op_sg, cryp_op_sg, cryp_src_sg, 
			cryp_iv_sg, cryp_dst_sg, ses_id_sg,
	                *sgs[8];
	unsigned int num_out, num_in, len;
#define MSG_LEN 100
	struct session_op *sess, host_sess, *temp;
	struct crypt_op *cryp;
	//__u8 __user *sess_key;
	unsigned char *cryp_src, *cryp_iv, *cryp_dst, sess_key_value;
	char *sess_key;
	//void __user *arg_ = (void __user *)arg;
	unsigned int *syscall_type;
	int *ret_val;
	unsigned int *cmd_;
	__u32 *ses_id;

	unsigned long flags;

	debug("Entering");

	/**
	 * Allocate all data that will be sent to the host.
	 **/

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_IOCTL;

	ret_val = kzalloc(sizeof(*ret_val), GFP_KERNEL);
	*ret_val = 0;

	cmd_ = kzalloc(sizeof(unsigned int), GFP_KERNEL);
	*cmd_ = cmd;

	//sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	//sess = NULL;
	sess = (struct session_op *)arg;
	cryp = kzalloc(sizeof(*cryp), GFP_KERNEL);

	//sess_key = kmalloc(sizeof(*sess_key), GFP_KERNEL);

	//sess_key = kmalloc(25, GFP_KERNEL);

	cryp_src = kzalloc(sizeof(*cryp_src), GFP_KERNEL);
	cryp_iv = kzalloc(sizeof(*cryp_iv), GFP_KERNEL);
	cryp_dst = kzalloc(sizeof(*cryp_dst), GFP_KERNEL);

	ses_id = kzalloc(sizeof(*ses_id), GFP_KERNEL);

	num_out = 0;
	num_in = 0;
	
	/**
	 *  These are common to all ioctl commands.
	 **/
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;

	sg_init_one(&host_fd_sg, &crof->host_fd, sizeof(crof->host_fd));
	sgs[num_out++] = &host_fd_sg;

	sg_init_one(&cmd_sg, cmd_, sizeof(*cmd_));
	sgs[num_out++] = &cmd_sg;
	/* ?? */

	/**
	 *  Add all the cmd specific sg lists.
	 **/
	switch (*cmd_) {
	case CIOCGSESSION:
		debug("CIOCGSESSION");
		
		//sess = kzalloc(sizeof(*sess), GFP_KERNEL);

		//sess = (struct session_op *)arg;
		/*if(copy_from_user(sess, arg_, sizeof(struct session_op))){
			ret = -EFAULT;
		}*/
		if(copy_from_user(&host_sess, sess, sizeof(struct session_op))){
			ret = -EFAULT;
		}

		temp = kzalloc(sizeof(*temp), GFP_KERNEL);

		//sess_key = kzalloc((host_sess.keylen + 1)*sizeof(char), GFP_KERNEL);
		//sess_key = (char*)__get_free_page(GFP_KERNEL);
		temp->key = kzalloc(host_sess.keylen + 1, GFP_KERNEL);
		//if(copy_from_user(sess_key, sess->key, host_sess.keylen)){
		//	ret = -EFAULT;
		//}
		//sess_key = sess->key;
                if(copy_from_user(temp->key, sess->key, host_sess.keylen)){
                      ret = -EFAULT;
                }
		//sess_key[host_sess.keylen] = '\0';
		//memcpy(sess_key, sess->key, host_sess.keylen);
		//sess_key = *host_sess.key;
		temp->key[host_sess.keylen] = '\0';
		//sess_key = kzalloc(sizeof(*sess_key), GFP_KERNEL);
		//sess_key = sess->key;	
		//sess_key_value = *sess->key;
		//if(sess_key == sess->key) debug("OLA KALA");
		//debug("The key we're about to pass to backend is %lu\n", (unsigned long) sess->key);

		debug("the key we're about to pass to backend from host_sess is %lu\n", (unsigned long) host_sess.key);
		debug("the keylen we're about to pass to backend is %d\n", (int) host_sess.keylen);
		debug("the key we're about to pass to backend is %lu\n",  (unsigned long) temp->key);
		//debug("sess->key size is: %d\n", (int) sizeof(sess->key));
		//debug("sess_key size is: %d\n", (int) sizeof(sess_key));
		//debug("The key we're about to pass to backend is:\n");
		//debug("%lu\n", (unsigned long) *sess_key++);
		//debug("%lu\n", (unsigned long) *sess_key++);
		//debug("%lu\n", (unsigned long) *sess_key++);
		//debug("%lu\n", (unsigned long) *sess_key++);
		//debug("%lu\n", (unsigned long) *sess_key++);
		//debug("%lu\n", (unsigned long) *sess_key++);
		//debug("%lu\n", (unsigned long) *sess_key++);
		
		//sess_key_value = *sess_key;

		//sess_key_value = *sess_key;
		sg_init_one(&session_key_sg, temp->key, host_sess.keylen);
		//sg_init_one(&session_key_sg, sess_key, host_sess.keylen);
		//sg_init_one(&session_key_sg, &sess_key_value, sizeof(sess_key_value));
		//sg_init_one(&session_key_sg, &sess_key_value, sess->keylen);
		sgs[num_out++] = &session_key_sg;

		//sess->key = sess_key;
		sg_init_one(&session_op_sg, &host_sess, sizeof(host_sess));
		//sg_init_one(&session_op_sg, sess, sizeof(struct session_op));
		sgs[num_out + num_in++] = &session_op_sg;

		sg_init_one(&return_val_sg, ret_val, sizeof(int));
		sgs[num_out + num_in++] = &return_val_sg;

		//kfree(sess_key);
		kfree(temp->key);
		kfree(temp);
		//kfree(sess);

		break;

	case CIOCFSESSION:
		debug("CIOCFSESSION");

                /*if(copy_from_user(ses_id, arg_, sizeof(__u32))){
                        ret = -EFAULT;
                }

		sg_init_one(&ses_id_sg, ses_id, sizeof(__u32));
		sgs[num_out++] = &ses_id_sg;

                sg_init_one(&return_val_sg, ret_val, sizeof(int));
                sgs[num_out + num_in++] = &return_val_sg;*/

		break;

	case CIOCCRYPT:
		debug("CIOCCRYPT");

		//num_out_temp = num_out;

                //cryp = kzalloc(sizeof(*cryp), GFP_KERNEL);

                /*if(copy_from_user(cryp, arg_, sizeof(struct crypt_op))){
                        ret = -EFAULT;
                }

		//cryp_src = kzalloc(sizeof(*cryp_src), GFP_KERNEL);
		*cryp_src = *cryp->src;
		//cryp_iv = kzalloc(sizeof(*cryp_iv), GFP_KERNEL);
		*cryp_iv = *cryp->iv;
		//cryp_dst = kzalloc(sizeof(*cryp_dst), GFP_KERNEL);
		*cryp_dst = *cryp->dst;

                sg_init_one(&cryp_op_sg, cryp, sizeof(struct crypt_op));
                sgs[num_out++] = &cryp_op_sg;

		//num_out++;
		
                sg_init_one(&cryp_src_sg, cryp_src, sizeof(*cryp->src));
		//sg_init_one(&cryp_src_sg, cryp_src, 16384 * sizeof(unsigned char));
                sgs[num_out++] = &cryp_src_sg;
		
		sg_init_one(&cryp_iv_sg, cryp_iv, sizeof(*cryp->iv));
		sgs[num_out++] = &cryp_iv_sg;

		sg_init_one(&cryp_dst_sg, cryp_dst, sizeof(*cryp->dst));
		sgs[num_out + num_in++] = &cryp_dst_sg;

                //cryp->src = cryp_src;
                //cryp->iv = cryp_iv;
                //cryp->dst = cryp_dst;

                //sg_init_one(&cryp_op_sg, cryp, sizeof(struct crypt_op));
                //sgs[num_out_temp] = &cryp_op_sg;

                sg_init_one(&return_val_sg, ret_val, sizeof(int));
                sgs[num_out + num_in++] = &return_val_sg;

		//kfree(cryp);
		//kfree(cryp_src);
		//kfree(cryp_iv);
		//kfree(cryp_dst);
*/
		break;

	default:
		debug("Unsupported ioctl command");

		break;
	}

	
	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	/* ?? Lock ?? */

	spin_lock_irqsave(&crdev->devlock, flags);
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
	                        &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(vq);

	//spin_unlock_irqrestore(&crdev->devlock, flags);

	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;
	
	spin_unlock_irqrestore(&crdev->devlock, flags);

	switch(*cmd_){
	case CIOCGSESSION:
		debug("pao na bo stin copy_to_user gia to CIOCGSESSION");
		/*if(copy_to_user(arg_, sess, sizeof(struct session_op))){
                        ret = -EFAULT;
                }*/
		if(copy_to_user(&sess->ses, &host_sess.ses, sizeof(host_sess.ses))){
			ret = -EFAULT;
		}
		debug("metefera sto userspace to sess");
		break;
	case CIOCCRYPT:
		debug("pao na bo stin copy_to_user gia to CIOCCRYPT");
		//debug("pirame apo backend cryp_src gamo ta panta sas iso me %s", cryp->src);
                /*if(copy_to_user(arg_, cryp, sizeof(struct crypt_op))){
                        ret = -EFAULT;
                }
		debug("metefera sto userspace to cryp");*/
				
                break;
	}
	//spin_unlock(&crdev->devlock, flags);

	kfree(cmd_);
	kfree(ret_val);
	kfree(syscall_type);
	kfree(sess);
	kfree(cryp);
	//kfree(sess_key);
	kfree(cryp_src);
	kfree(cryp_iv);
	kfree(cryp_dst);
	kfree(ses_id);
	debug("Leaving");

	return ret;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf, 
                                  size_t cnt, loff_t *f_pos)
{
	debug("Entering");
	debug("Leaving");
	return -EINVAL;
}

static struct file_operations crypto_chrdev_fops = 
{
	.owner          = THIS_MODULE,
	.open           = crypto_chrdev_open,
	.release        = crypto_chrdev_release,
	.read           = crypto_chrdev_read,
	.unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
	int ret;
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;
	
	debug("Initializing character device...");
	cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
	crypto_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
	if (ret < 0) {
		debug("failed to register region, ret = %d", ret);
		goto out;
	}
	ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device");
		goto out_with_chrdev_region;
	}

	debug("Completed successfully");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
	return ret;
}

void crypto_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("entering");
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	cdev_del(&crypto_chrdev_cdev);
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
	debug("leaving");
}
