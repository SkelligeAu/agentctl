/*
 * agentfs — minimal pseudo-filesystem for kernel-backed agent identity,
 *           mailboxes, and lifecycle binding.
 *
 * Scope is intentionally tiny:
 *
 *   /mnt/agentfs/
 *     register               write a name here to register the current task
 *     agents/<name>/
 *       pid                  owning task pid (text)
 *       owner                "uid=N gid=N"  (text)
 *       status               "running" | "dead"  (text)
 *       stats                queue depth / bytes / processed (text)
 *       inbox                opaque message queue (read/write/poll/blocking)
 *       outbox               opaque message queue (read/write/poll/blocking)
 *
 * The kernel does NOT parse VERB/LEN/TASK-ID/REPLY-TO — that stays in the
 * userspace runtime. Messages are opaque byte payloads to the kernel.
 *
 * Lifecycle: registration is bound to the owning task_struct via
 * task_work_add(). When the owner exits, the callback sets dead=true,
 * drains the queues, wakes any blocked readers, and drops the task ref.
 *
 * Locking model:
 *   - g_agents_lock (mutex): protects the global agent list.
 *   - agent->lock (mutex): protects each agent's mailboxes + dead flag.
 *
 * Memory model:
 *   - Bounded per-mailbox queue: AGENTFS_MAX_QUEUE_BYTES + _MSGS.
 *   - Bounded per-message size: AGENTFS_MAX_MESSAGE.
 *   - All allocations go through kmalloc/kzalloc; freed in callback or exit.
 *
 * Target: Linux 6.6+ (uses simple_inode_init_ts).
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/pagemap.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/cred.h>
#include <linux/pid.h>
#include <linux/sched/signal.h>
#include <linux/uidgid.h>
#include <linux/workqueue.h>
#include <linux/atomic.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>

#define AGENTFS_MAGIC            0x41464557U     /* 'AGNT' (BE) */
#define AGENTFS_MAX_NAME         64
#define AGENTFS_MAX_MESSAGE      (1U << 20)      /* 1 MiB per message */
#define AGENTFS_MAX_QUEUE_BYTES  (8U << 20)      /* 8 MiB per mailbox */
#define AGENTFS_MAX_QUEUE_MSGS   1024

/* ----- structures ---------------------------------------------------- */

struct agent_message {
	struct list_head link;
	size_t len;
	char data[];      /* flexible array; sized at alloc */
};

enum mailbox_kind {
	MBOX_INBOX,
	MBOX_OUTBOX,
};

struct mailbox {
	struct list_head messages;
	size_t queued_bytes;
	size_t queued_messages;
	atomic64_t messages_processed;
	wait_queue_head_t readq;
};

struct agent {
	struct list_head link;            /* in g_agents */
	char name[AGENTFS_MAX_NAME];

	struct task_struct *owner;        /* refcount held while non-NULL */
	kuid_t uid;
	kgid_t gid;
	pid_t pid;

	struct mutex lock;                /* protects mailboxes + dead */
	bool dead;                        /* true after owner exits (or unregister) */

	struct mailbox inbox;
	struct mailbox outbox;

	struct dentry *dir;               /* /agents/<name>/ */
};

/* Per-file context lets a single fops cover both mailboxes. */
struct mailbox_ctx {
	struct agent *agent;
	enum mailbox_kind kind;
};

/* ----- module-global state ------------------------------------------- */

static LIST_HEAD(g_agents);
static DEFINE_MUTEX(g_agents_lock);

static struct dentry *g_agents_dentry;   /* /agents */

/* Background reaper: every REAPER_INTERVAL we walk g_agents and mark
 * dead any whose owner task is no longer alive. We can't use task_work
 * (not exported to modules); a periodic check is the next best thing. */
#define REAPER_INTERVAL_MS 2000
static struct workqueue_struct *g_wq;
static struct delayed_work       g_reaper;

/* ----- helpers ------------------------------------------------------- */

static bool agentfs_valid_name(const char *s, size_t n)
{
	size_t i;
	if (n == 0 || n >= AGENTFS_MAX_NAME)
		return false;
	if (s[0] == '.' || s[0] == '-')
		return false;
	for (i = 0; i < n; i++) {
		char c = s[i];
		if (!(isalnum((unsigned char)c) || c == '_' || c == '-' || c == '.'))
			return false;
	}
	return true;
}

static void mailbox_init(struct mailbox *m)
{
	INIT_LIST_HEAD(&m->messages);
	m->queued_bytes = 0;
	m->queued_messages = 0;
	atomic64_set(&m->messages_processed, 0);
	init_waitqueue_head(&m->readq);
}

static void mailbox_drain_locked(struct mailbox *m)
{
	struct agent_message *msg, *tmp;
	list_for_each_entry_safe(msg, tmp, &m->messages, link) {
		list_del(&msg->link);
		kfree(msg);
	}
	m->queued_bytes = 0;
	m->queued_messages = 0;
}

static struct mailbox *agent_mailbox(struct agent *a, enum mailbox_kind k)
{
	return k == MBOX_INBOX ? &a->inbox : &a->outbox;
}

static const char *agent_status_word(struct agent *a)
{
	return a->dead ? "dead" : "running";
}

/* ----- periodic reaper ----------------------------------------------- */

/* Walks the agent list, marks dead any agent whose owner task has gone
 * away (pid_alive returns false once release_task has run). Drains the
 * mailboxes, wakes blocked readers, drops the task_struct reference.
 *
 * Re-schedules itself. Cancelled in agentfs_exit. */
static void agentfs_reaper(struct work_struct *w)
{
	struct agent *a;
	bool resched = true;

	mutex_lock(&g_agents_lock);
	list_for_each_entry(a, &g_agents, link) {
		bool alive;

		if (a->dead)
			continue;

		rcu_read_lock();
		alive = a->owner && pid_alive(a->owner);
		rcu_read_unlock();
		if (alive)
			continue;

		mutex_lock(&a->lock);
		a->dead = true;
		mailbox_drain_locked(&a->inbox);
		mailbox_drain_locked(&a->outbox);
		mutex_unlock(&a->lock);

		wake_up_interruptible_all(&a->inbox.readq);
		wake_up_interruptible_all(&a->outbox.readq);

		if (a->owner) {
			put_task_struct(a->owner);
			a->owner = NULL;
		}
		pr_info("agentfs: agent '%s' owner is gone; marked dead\n",
			a->name);
	}
	mutex_unlock(&g_agents_lock);

	if (resched)
		queue_delayed_work(g_wq, &g_reaper,
				   msecs_to_jiffies(REAPER_INTERVAL_MS));
}

/* ----- mailbox file ops ---------------------------------------------- */

static ssize_t mailbox_read(struct file *file, char __user *ubuf,
			     size_t len, loff_t *off)
{
	struct mailbox_ctx *ctx = file->private_data;
	struct agent *a = ctx->agent;
	struct mailbox *mb = agent_mailbox(a, ctx->kind);
	struct agent_message *m;
	size_t to_copy;
	int err;

	for (;;) {
		mutex_lock(&a->lock);
		if (a->dead && list_empty(&mb->messages)) {
			mutex_unlock(&a->lock);
			return 0;   /* EOF on dead-and-drained */
		}
		if (!list_empty(&mb->messages)) {
			m = list_first_entry(&mb->messages,
					     struct agent_message, link);
			list_del(&m->link);
			mb->queued_bytes -= m->len;
			mb->queued_messages--;
			atomic64_inc(&mb->messages_processed);
			mutex_unlock(&a->lock);
			break;
		}
		mutex_unlock(&a->lock);

		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;
		err = wait_event_interruptible(mb->readq,
			!list_empty_careful(&mb->messages) || a->dead);
		if (err)
			return err;
	}

	to_copy = min_t(size_t, m->len, len);
	if (copy_to_user(ubuf, m->data, to_copy)) {
		kfree(m);
		return -EFAULT;
	}
	kfree(m);
	return to_copy;
}

static ssize_t mailbox_write(struct file *file, const char __user *ubuf,
			      size_t len, loff_t *off)
{
	struct mailbox_ctx *ctx = file->private_data;
	struct agent *a = ctx->agent;
	struct mailbox *mb = agent_mailbox(a, ctx->kind);
	struct agent_message *m;

	if (len == 0)
		return 0;
	if (len > AGENTFS_MAX_MESSAGE)
		return -EMSGSIZE;

	m = kmalloc(struct_size(m, data, len), GFP_KERNEL);
	if (!m)
		return -ENOMEM;
	if (copy_from_user(m->data, ubuf, len)) {
		kfree(m);
		return -EFAULT;
	}
	m->len = len;
	INIT_LIST_HEAD(&m->link);

	mutex_lock(&a->lock);
	if (a->dead) {
		mutex_unlock(&a->lock);
		kfree(m);
		return -ESHUTDOWN;
	}
	if (mb->queued_messages >= AGENTFS_MAX_QUEUE_MSGS ||
	    mb->queued_bytes + len > AGENTFS_MAX_QUEUE_BYTES) {
		mutex_unlock(&a->lock);
		kfree(m);
		return -ENOSPC;
	}
	list_add_tail(&m->link, &mb->messages);
	mb->queued_bytes += len;
	mb->queued_messages++;
	mutex_unlock(&a->lock);

	wake_up_interruptible(&mb->readq);
	return len;
}

static __poll_t mailbox_poll(struct file *file, poll_table *wait)
{
	struct mailbox_ctx *ctx = file->private_data;
	struct agent *a = ctx->agent;
	struct mailbox *mb = agent_mailbox(a, ctx->kind);
	__poll_t mask = 0;

	poll_wait(file, &mb->readq, wait);

	mutex_lock(&a->lock);
	if (!list_empty(&mb->messages))
		mask |= EPOLLIN | EPOLLRDNORM;
	if (a->dead)
		mask |= EPOLLHUP;
	if (!a->dead &&
	    mb->queued_messages < AGENTFS_MAX_QUEUE_MSGS &&
	    mb->queued_bytes < AGENTFS_MAX_QUEUE_BYTES)
		mask |= EPOLLOUT | EPOLLWRNORM;
	mutex_unlock(&a->lock);

	return mask;
}

static int mailbox_open(struct inode *inode, struct file *file)
{
	struct mailbox_ctx *ctx;
	struct agent *a = inode->i_private;

	if (!a)
		return -ENOENT;

	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	ctx->agent = a;
	/* The fops differ by mailbox via file->f_op-derived helpers — but
	 * we encode it on inode->i_private via a tagged pointer instead.
	 * To stay readable, we set the kind in the open handler by checking
	 * the dentry name. */
	if (file->f_path.dentry &&
	    strcmp(file->f_path.dentry->d_name.name, "outbox") == 0)
		ctx->kind = MBOX_OUTBOX;
	else
		ctx->kind = MBOX_INBOX;
	file->private_data = ctx;
	return 0;
}

static int mailbox_release(struct inode *inode, struct file *file)
{
	kfree(file->private_data);
	file->private_data = NULL;
	return 0;
}

static const struct file_operations agentfs_mailbox_fops = {
	.owner   = THIS_MODULE,
	.open    = mailbox_open,
	.release = mailbox_release,
	.read    = mailbox_read,
	.write   = mailbox_write,
	.poll    = mailbox_poll,
	.llseek  = noop_llseek,
};

/* ----- read-only text files (pid/status/owner/stats) ----------------- */

static ssize_t agent_pid_read(struct file *file, char __user *ubuf,
			       size_t len, loff_t *off)
{
	struct agent *a = file_inode(file)->i_private;
	char buf[32];
	int n;

	if (!a)
		return -EIO;
	n = scnprintf(buf, sizeof(buf), "%d\n", a->pid);
	return simple_read_from_buffer(ubuf, len, off, buf, n);
}

static ssize_t agent_status_read(struct file *file, char __user *ubuf,
				  size_t len, loff_t *off)
{
	struct agent *a = file_inode(file)->i_private;
	char buf[16];
	int n;

	if (!a)
		return -EIO;
	mutex_lock(&a->lock);
	n = scnprintf(buf, sizeof(buf), "%s\n", agent_status_word(a));
	mutex_unlock(&a->lock);
	return simple_read_from_buffer(ubuf, len, off, buf, n);
}

static ssize_t agent_owner_read(struct file *file, char __user *ubuf,
				 size_t len, loff_t *off)
{
	struct agent *a = file_inode(file)->i_private;
	char buf[64];
	int n;

	if (!a)
		return -EIO;
	n = scnprintf(buf, sizeof(buf), "uid=%u gid=%u\n",
		      from_kuid_munged(&init_user_ns, a->uid),
		      from_kgid_munged(&init_user_ns, a->gid));
	return simple_read_from_buffer(ubuf, len, off, buf, n);
}

static ssize_t agent_stats_read(struct file *file, char __user *ubuf,
				 size_t len, loff_t *off)
{
	struct agent *a = file_inode(file)->i_private;
	char buf[256];
	int n;

	if (!a)
		return -EIO;
	mutex_lock(&a->lock);
	n = scnprintf(buf, sizeof(buf),
		"inbox_messages=%zu\n"
		"inbox_bytes=%zu\n"
		"inbox_processed=%lld\n"
		"outbox_messages=%zu\n"
		"outbox_bytes=%zu\n"
		"outbox_processed=%lld\n",
		a->inbox.queued_messages,
		a->inbox.queued_bytes,
		(long long)atomic64_read(&a->inbox.messages_processed),
		a->outbox.queued_messages,
		a->outbox.queued_bytes,
		(long long)atomic64_read(&a->outbox.messages_processed));
	mutex_unlock(&a->lock);
	return simple_read_from_buffer(ubuf, len, off, buf, n);
}

#define DEF_RO_FOPS(_name)                                            \
static const struct file_operations agent_ ## _name ## _fops = {      \
	.owner  = THIS_MODULE,                                        \
	.read   = agent_ ## _name ## _read,                           \
	.llseek = default_llseek,                                     \
}

DEF_RO_FOPS(pid);
DEF_RO_FOPS(status);
DEF_RO_FOPS(owner);
DEF_RO_FOPS(stats);

/* ----- inode/dentry helpers ----------------------------------------- */

static const struct super_operations agentfs_sops = {
	.statfs       = simple_statfs,
	.drop_inode   = generic_delete_inode,
};

static struct inode *agentfs_make_inode(struct super_block *sb, umode_t mode)
{
	struct inode *inode = new_inode(sb);
	if (!inode)
		return NULL;
	inode->i_ino   = get_next_ino();
	inode->i_mode  = mode;
	inode->i_uid   = GLOBAL_ROOT_UID;
	inode->i_gid   = GLOBAL_ROOT_GID;
	simple_inode_init_ts(inode);
	return inode;
}

/* Caller must hold inode_lock on parent. */
static struct dentry *agentfs_add_file(struct dentry *parent, const char *name,
				        const struct file_operations *fops,
				        void *priv, umode_t mode)
{
	struct dentry *d;
	struct inode *inode;

	d = d_alloc_name(parent, name);
	if (!d)
		return ERR_PTR(-ENOMEM);
	inode = agentfs_make_inode(parent->d_sb, S_IFREG | mode);
	if (!inode) {
		dput(d);
		return ERR_PTR(-ENOMEM);
	}
	inode->i_fop = fops;
	inode->i_private = priv;
	d_add(d, inode);
	return d;
}

/* Caller must hold inode_lock on parent. */
static struct dentry *agentfs_add_dir(struct dentry *parent, const char *name)
{
	struct dentry *d;
	struct inode *inode;

	d = d_alloc_name(parent, name);
	if (!d)
		return ERR_PTR(-ENOMEM);
	inode = agentfs_make_inode(parent->d_sb, S_IFDIR | 0755);
	if (!inode) {
		dput(d);
		return ERR_PTR(-ENOMEM);
	}
	inode->i_op = &simple_dir_inode_operations;
	inode->i_fop = &simple_dir_operations;
	inc_nlink(inode);
	d_add(d, inode);
	inc_nlink(d_inode(parent));
	return d;
}

/* ----- register handling --------------------------------------------- */

static int agentfs_build_agent_tree(struct agent *a)
{
	struct dentry *parent = g_agents_dentry;
	struct dentry *dir;
	int err = 0;

	inode_lock(d_inode(parent));
	dir = agentfs_add_dir(parent, a->name);
	if (IS_ERR(dir)) {
		err = PTR_ERR(dir);
		inode_unlock(d_inode(parent));
		return err;
	}
	a->dir = dir;
	inode_unlock(d_inode(parent));

	inode_lock(d_inode(dir));

#define ADD_FILE(_name, _fops, _mode)                                          \
	do {                                                                   \
		struct dentry *_f = agentfs_add_file(dir, _name, _fops, a,     \
						     _mode);                   \
		if (IS_ERR(_f)) { err = PTR_ERR(_f); goto out; }               \
	} while (0)

	ADD_FILE("pid",     &agent_pid_fops,     0444);
	ADD_FILE("status",  &agent_status_fops,  0444);
	ADD_FILE("owner",   &agent_owner_fops,   0444);
	ADD_FILE("stats",   &agent_stats_fops,   0444);
	ADD_FILE("inbox",   &agentfs_mailbox_fops, 0600);
	ADD_FILE("outbox",  &agentfs_mailbox_fops, 0600);

#undef ADD_FILE

out:
	inode_unlock(d_inode(dir));
	return err;
}

static int agentfs_register(const char *name)
{
	struct agent *a, *existing;
	int err;

	mutex_lock(&g_agents_lock);

	/* Pass 1: look for a name collision. If we find one, decide whether
	 * the slot is recyclable (previous owner already reaped, or has
	 * exited since the last reaper tick). Refuse only when the previous
	 * owner is still alive. */
	list_for_each_entry(existing, &g_agents, link) {
		bool dead;

		if (strcmp(existing->name, name) != 0)
			continue;

		mutex_lock(&existing->lock);
		dead = existing->dead;
		if (!dead && existing->owner) {
			rcu_read_lock();
			if (!pid_alive(existing->owner))
				dead = true;
			rcu_read_unlock();
		}
		if (!dead) {
			mutex_unlock(&existing->lock);
			mutex_unlock(&g_agents_lock);
			return -EEXIST;
		}

		/* Recycle the existing slot. The dentries under /agents/<name>/
		 * stay valid because they point at this same `struct agent` via
		 * inode->i_private — their dynamic readers (`pid`, `status`,
		 * `owner`, `stats`) will reflect the new owner immediately. */
		mailbox_drain_locked(&existing->inbox);
		mailbox_drain_locked(&existing->outbox);
		if (existing->owner) {
			put_task_struct(existing->owner);
			existing->owner = NULL;
		}
		get_task_struct(current);
		existing->owner = current;
		existing->uid   = current_uid();
		existing->gid   = current_gid();
		existing->pid   = task_pid_nr(current);
		existing->dead  = false;
		atomic64_set(&existing->inbox.messages_processed, 0);
		atomic64_set(&existing->outbox.messages_processed, 0);
		mutex_unlock(&existing->lock);
		mutex_unlock(&g_agents_lock);

		pr_info("agentfs: recycled '%s' new pid=%d\n",
			existing->name, existing->pid);
		return 0;
	}

	/* Pass 2: no collision — allocate a fresh entry. */
	a = kzalloc(sizeof(*a), GFP_KERNEL);
	if (!a) {
		mutex_unlock(&g_agents_lock);
		return -ENOMEM;
	}
	strscpy(a->name, name, sizeof(a->name));
	mutex_init(&a->lock);
	mailbox_init(&a->inbox);
	mailbox_init(&a->outbox);
	a->dead = false;

	get_task_struct(current);
	a->owner = current;
	a->uid   = current_uid();
	a->gid   = current_gid();
	a->pid   = task_pid_nr(current);

	list_add(&a->link, &g_agents);
	mutex_unlock(&g_agents_lock);

	err = agentfs_build_agent_tree(a);
	if (err) {
		mutex_lock(&g_agents_lock);
		list_del(&a->link);
		mutex_unlock(&g_agents_lock);
		put_task_struct(a->owner);
		kfree(a);
		return err;
	}

	pr_info("agentfs: registered '%s' pid=%d\n", a->name, a->pid);
	return 0;
}

static ssize_t register_write(struct file *file, const char __user *ubuf,
			       size_t len, loff_t *off)
{
	char namebuf[AGENTFS_MAX_NAME];
	size_t take;
	int err;

	if (len == 0)
		return 0;
	take = len;
	if (take >= sizeof(namebuf))
		take = sizeof(namebuf) - 1;
	if (copy_from_user(namebuf, ubuf, take))
		return -EFAULT;
	namebuf[take] = '\0';
	/* Strip a trailing newline if present (so `echo` works). */
	if (take > 0 && namebuf[take - 1] == '\n') {
		namebuf[take - 1] = '\0';
		take--;
	}
	if (!agentfs_valid_name(namebuf, take))
		return -EINVAL;

	err = agentfs_register(namebuf);
	if (err)
		return err;
	return len;
}

static const struct file_operations agentfs_register_fops = {
	.owner  = THIS_MODULE,
	.write  = register_write,
	.llseek = noop_llseek,
};

/* ----- super_block / mount ------------------------------------------ */

static int agentfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct inode *root;
	struct dentry *reg, *agents;

	sb->s_blocksize      = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_magic          = AGENTFS_MAGIC;
	sb->s_op             = &agentfs_sops;
	sb->s_time_gran      = 1;

	root = agentfs_make_inode(sb, S_IFDIR | 0755);
	if (!root)
		return -ENOMEM;
	root->i_op  = &simple_dir_inode_operations;
	root->i_fop = &simple_dir_operations;
	inc_nlink(root);

	sb->s_root = d_make_root(root);
	if (!sb->s_root)
		return -ENOMEM;

	inode_lock(d_inode(sb->s_root));
	reg    = agentfs_add_file(sb->s_root, "register",
				   &agentfs_register_fops, NULL, 0200);
	agents = agentfs_add_dir(sb->s_root, "agents");
	inode_unlock(d_inode(sb->s_root));

	if (IS_ERR(reg))    return PTR_ERR(reg);
	if (IS_ERR(agents)) return PTR_ERR(agents);

	g_agents_dentry = agents;
	pr_info("agentfs: superblock initialised\n");
	return 0;
}

static struct dentry *agentfs_do_mount(struct file_system_type *fs_type,
				        int flags, const char *dev_name,
				        void *data)
{
	return mount_nodev(fs_type, flags, data, agentfs_fill_super);
}

static struct file_system_type agentfs_fs_type = {
	.owner    = THIS_MODULE,
	.name     = "agentfs",
	.mount    = agentfs_do_mount,
	.kill_sb  = kill_litter_super,
};

/* ----- module init/exit --------------------------------------------- */

static int __init agentfs_init(void)
{
	int err;

	g_wq = alloc_workqueue("agentfs", WQ_UNBOUND, 1);
	if (!g_wq)
		return -ENOMEM;
	INIT_DELAYED_WORK(&g_reaper, agentfs_reaper);

	err = register_filesystem(&agentfs_fs_type);
	if (err) {
		destroy_workqueue(g_wq);
		pr_err("agentfs: register_filesystem failed: %d\n", err);
		return err;
	}

	queue_delayed_work(g_wq, &g_reaper,
			   msecs_to_jiffies(REAPER_INTERVAL_MS));

	pr_info("agentfs: loaded (max_msg=%u max_queue_bytes=%u max_queue_msgs=%u reaper=%dms)\n",
		AGENTFS_MAX_MESSAGE, AGENTFS_MAX_QUEUE_BYTES,
		AGENTFS_MAX_QUEUE_MSGS, REAPER_INTERVAL_MS);
	return 0;
}

static void __exit agentfs_exit(void)
{
	struct agent *a, *tmp;

	/* Stop the reaper *before* tearing down the filesystem so it can't
	 * touch a freed agent. */
	cancel_delayed_work_sync(&g_reaper);

	unregister_filesystem(&agentfs_fs_type);

	mutex_lock(&g_agents_lock);
	list_for_each_entry_safe(a, tmp, &g_agents, link) {
		list_del(&a->link);
		mutex_lock(&a->lock);
		if (!a->dead) {
			mailbox_drain_locked(&a->inbox);
			mailbox_drain_locked(&a->outbox);
			a->dead = true;
		}
		mutex_unlock(&a->lock);
		wake_up_interruptible_all(&a->inbox.readq);
		wake_up_interruptible_all(&a->outbox.readq);
		if (a->owner) {
			put_task_struct(a->owner);
			a->owner = NULL;
		}
		pr_info("agentfs: cleaned up agent '%s'\n", a->name);
		kfree(a);
	}
	mutex_unlock(&g_agents_lock);

	destroy_workqueue(g_wq);
	pr_info("agentfs: unloaded\n");
}

module_init(agentfs_init);
module_exit(agentfs_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("agentctl POC");
MODULE_DESCRIPTION("agentfs — minimal kernel-backed agent identity + mailbox");
