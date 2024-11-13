#include "util.h"
#include <linux/our_ipc.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/ipc.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/rcupdate.h>
#include <linux/hugetlb.h>
#include <linux/security.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mman.h>
#include <asm/page.h>

MODULE_LICENSE("GPL");

// Triển khai hàm do_shmat
long my_do_shmat(int shmid, char __user *shmaddr, int shmflg,
		 unsigned long *raddr, unsigned long shmlba)
{
	struct shmid_kernel *shp;
	unsigned long addr = (unsigned long)shmaddr;
	unsigned long size;
	struct file *file, *base;
	int err;
	unsigned long flags = MAP_SHARED;
	unsigned long prot;
	int acc_mode;
	struct ipc_namespace *ns;
	struct shm_file_data *sfd;
	int f_flags;
	unsigned long populate = 0;

	err = -EINVAL;
	if (shmid < 0)
		goto out;

	if (addr) {
		if (addr & (shmlba - 1)) {
			if (shmflg & SHM_RND) {
				addr &= ~(shmlba - 1);
				if (!addr && (shmflg & SHM_REMAP))
					goto out;
			} else
#ifndef __ARCH_FORCE_SHMLBA
				if (addr & ~PAGE_MASK)
#endif
				goto out;
		}
		flags |= MAP_FIXED;
	} else if ((shmflg & SHM_REMAP))
		goto out;

	if (shmflg & SHM_RDONLY) {
		prot = PROT_READ;
		acc_mode = S_IRUGO;
		f_flags = O_RDONLY;
	} else {
		prot = PROT_READ | PROT_WRITE;
		acc_mode = S_IRUGO | S_IWUGO;
		f_flags = O_RDWR;
	}
	if (shmflg & SHM_EXEC) {
		prot |= PROT_EXEC;
		acc_mode |= S_IXUGO;
	}

	ns = current->nsproxy->ipc_ns;
	rcu_read_lock();
	shp = shm_obtain_object_check(ns, shmid);
	if (IS_ERR(shp)) {
		err = PTR_ERR(shp);
		goto out_unlock;
	}

	err = -EACCES;
	if (ipcperms(ns, &shp->shm_perm, acc_mode))
		goto out_unlock;

	err = security_shm_shmat(&shp->shm_perm, shmaddr, shmflg);
	if (err)
		goto out_unlock;

	ipc_lock_object(&shp->shm_perm);

	if (!ipc_valid_object(&shp->shm_perm)) {
		ipc_unlock_object(&shp->shm_perm);
		err = -EIDRM;
		goto out_unlock;
	}

	base = get_file(shp->shm_file);
	shp->shm_nattch++;
	size = i_size_read(file_inode(base));
	ipc_unlock_object(&shp->shm_perm);
	rcu_read_unlock();

	err = -ENOMEM;
	sfd = kzalloc(sizeof(*sfd), GFP_KERNEL);
	if (!sfd) {
		fput(base);
		goto out_nattch;
	}

	file = alloc_file_clone(base, f_flags,
				is_file_hugepages(base) ?
					&shm_file_operations_huge :
					&shm_file_operations);
	err = PTR_ERR(file);
	if (IS_ERR(file)) {
		kfree(sfd);
		fput(base);
		goto out_nattch;
	}

	sfd->id = shp->shm_perm.id;
	sfd->ns = get_ipc_ns(ns);
	sfd->file = base;
	sfd->vm_ops = NULL;
	file->private_data = sfd;

	err = security_mmap_file(file, prot, flags);
	if (err)
		goto out_fput;

	if (mmap_write_lock_killable(current->mm)) {
		err = -EINTR;
		goto out_fput;
	}

	if (addr && !(shmflg & SHM_REMAP)) {
		err = -EINVAL;
		if (addr + size < addr)
			goto invalid;

		if (find_vma_intersection(current->mm, addr, addr + size))
			goto invalid;
	}

	addr = do_mmap(file, addr, size, prot, flags, 0, 0, &populate, NULL);
	*raddr = addr;
	err = 0;
	if (IS_ERR_VALUE(addr))
		err = (long)addr;
invalid:
	mmap_write_unlock(current->mm);
	if (populate)
		mm_populate(addr, populate);

out_fput:
	fput(file);

out_nattch:
	down_write(&shm_ids(ns).rwsem);
	shp = shm_lock(ns, shmid);
	shp->shm_nattch--;

	if (shm_may_destroy(shp))
		shm_destroy(ns, shp);
	else
		shm_unlock(shp);
	up_write(&shm_ids(ns).rwsem);
	return err;

out_unlock:
	rcu_read_unlock();
out:
	return err;
}

// Triển khai hàm ksys_shmget
long my_ksys_shmget(key_t key, size_t size, int shmflg)
{
	struct ipc_namespace *ns;
	static const struct ipc_ops shm_ops = {
		.getnew = newseg,
		.associate = security_shm_associate,
		.more_checks = shm_more_checks,
	};
	struct ipc_params shm_params;

	ns = current->nsproxy->ipc_ns;
	shm_params.key = key;
	shm_params.flg = shmflg;
	shm_params.u.size = size;

	return ipcget(ns, &shm_ids(ns), &shm_ops, &shm_params);
}

// Triển khai hàm ksys_shmdt
long my_ksys_shmdt(char __user *shmaddr)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long addr = (unsigned long)shmaddr;
	int retval = -EINVAL;

	if (addr & ~PAGE_MASK)
		return retval;

	if (mmap_write_lock_killable(mm))
		return -EINTR;

	vma = vma_lookup(mm, addr);
	if (vma && vma->vm_start == addr && vma->vm_ops == &shm_vm_ops) {
		do_munmap(mm, vma->vm_start, vma->vm_end - vma->vm_start, NULL);
		retval = 0;
	}

	mmap_write_unlock(mm);
	return retval;
}

// Triển khai hàm ksys_shmctl
long my_ksys_shmctl(int shmid, int cmd, struct shmid_ds __user *buf)
{
	struct ipc_namespace *ns = current->nsproxy->ipc_ns;
	struct shmid_kernel *shp;
	int err;

	down_read(&shm_ids(ns).rwsem);
	shp = shm_obtain_object(ns, shmid);
	if (IS_ERR(shp)) {
		err = PTR_ERR(shp);
		goto out_up;
	}

	switch (cmd) {
	case IPC_STAT:
		err = security_shm_shmctl(&shp->shm_perm, cmd);
		if (err)
			goto out_up;
		err = copy_shmid_to_user(buf, shp);
		break;
	case IPC_SET:
		err = security_shm_shmctl(&shp->shm_perm, cmd);
		if (err)
			goto out_up;
		err = shmctl_set(buf, shp);
		break;
	case IPC_RMID:
		err = security_shm_shmctl(&shp->shm_perm, cmd);
		if (err)
			goto out_up;
		shm_destroy(ns, shp);
		break;
	default:
		err = -EINVAL;
		break;
	}

out_up:
	up_read(&shm_ids(ns).rwsem);
	return err;
}

// Định nghĩa các hàm syscall trong my_ipc.c
SYSCALL_DEFINE3(my_shmat, int, shmid, char __user *, shmaddr, int, shmflg)
{
	unsigned long ret;
	long err;

	err = my_do_shmat(shmid, shmaddr, shmflg, &ret, SHMLBA);
	if (err)
		return err;
	force_successful_syscall_return();
	return (long)ret;
}

SYSCALL_DEFINE3(my_shmget, key_t, key, size_t, size, int, shmflg)
{
	return my_ksys_shmget(key, size, shmflg);
}

SYSCALL_DEFINE1(my_shmdt, char __user *, shmaddr)
{
	return my_ksys_shmdt(shmaddr);
}

SYSCALL_DEFINE3(my_shmctl, int, shmid, int, cmd, struct shmid_ds __user *, buf)
{
	return my_ksys_shmctl(shmid, cmd, buf);
}
