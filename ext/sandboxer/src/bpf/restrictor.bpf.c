/*
 * Copyright (c) 2023 Unibg Seclab (https://seclab.unibg.it)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "structs.h"

#define EPERM 1

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, PATH_SIZE + 255);
  __uint(max_entries, 1);
} tmp_path SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u64));
  __uint(max_entries, 1  /* placeholder */);
} tmp_prefix_hashes SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
  __uint(map_flags, (BPF_F_NO_PREALLOC));
  __type(key, int);
  __type(value, int);
} task_map SEC(".maps");

// NOTE: Despite the following policy_map declaration, its keys are not of
// type int, but struct collision_key
struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, 1 /* placeholder */);
  __uint(key_size, sizeof(int));
  __uint(value_size, sizeof(int));
  /* anonymous inner map */
  __array(
      values, struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 1 /* placeholder */);
        __type(key, int);
        __type(value, char[PATH_SIZE]);
      });
} policy_map SEC(".maps");

struct ctx_data {
  int policy_idx;
  char *path;
  int nof_prefixes;
  bool to_deny;
};

/* POLICY ATTACHMENT */

/*
 * Inherit the parent task policy in the child task
 */
static __always_inline void inherit_policy(struct task_struct *parent,
                                           struct task_struct *child) {
  int *parent_task_policy = ((pid_t *)bpf_task_storage_get(&task_map,
                                                           parent, 0, 0));
  if (parent_task_policy)
    bpf_task_storage_get(&task_map, child, parent_task_policy,
                         BPF_LOCAL_STORAGE_GET_F_CREATE);
}

/*
 * Force policy inheritance when a process forks itself
 */
SEC("tp_btf/sched_process_fork")
int BPF_PROG(check_fork, struct task_struct *parent,
             struct task_struct *child) {
  inherit_policy(parent, child);
  return 0;
}

/*
 * Force policy inheritance when a process clones itself
 */
SEC("lsm/task_alloc")
int BPF_PROG(check_task_alloc, struct task_struct *task,
             unsigned long clone_flags, int ret_prev) {
  struct task_struct *parent = task->real_parent;
  inherit_policy(parent, task);
  return 0;
}

/*
 * Drop policy of the current task. It is used on process exit to free
 * any policy configuration associated with the pid of the process.
 */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(check_exit, struct task_struct *task) {
  bpf_task_storage_delete(&task_map, task);
  return 0;
}

/*
 * Attach policy to the current task. It is used on subprocess initialization
 * to ensure it runs within the policy defined boundaries
 */
SEC("uprobe/attach_policy")
int BPF_KPROBE(attach_policy, u32 policy_idx) {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
  bpf_task_storage_get(&task_map, task, &policy_idx,
                       BPF_LOCAL_STORAGE_GET_F_CREATE);
  return 0;
}

/* POLICY ENFORCEMENT */

/*
 * Initialize the char buffer given with the requested path
 */
static int set_full_path(struct path *path, struct dentry *dentry,
                         char *full_path) {
  int pos = bpf_d_path(path, full_path, PATH_SIZE) - 1;
  // Ensure full path not empty and not exceeding PATH_SIZE characters
  if (pos < 0 || pos >= PATH_SIZE)
    return 1;

  if (dentry) {
    full_path[pos] = '/';

    // // Ensure the path component does not exceed 255 characters and the full
    // // path does not exceed PATH_SIZE characters
    // unsigned int max_size = 255;
    // int remaining_size = PATH_SIZE - (pos + 1);
    // if (remaining_size >= 0 && max_size > remaining_size)
    //   max_size = remaining_size;

    // bpf_probe_read_str(full_path + pos + 1, max_size, dentry->d_name.name);
    bpf_probe_read_str(full_path + pos + 1, 255, dentry->d_name.name);
  }

  return 0;
}

/*
 * Compute djb2 hashes of prefix paths, store them in the tmp_prefix_hashes
 * array map and return the number of computed hashes (i.e., the number of
 * prefix paths)
 */
static int compute_prefix_hashes(char *str) {
  int nof_hashes = 0;
  u64 hash = 5381;
  bool done = false;

  if (!str || !str[0])
    return 0;

  for (int i = 0; i < PATH_SIZE && !done; i++) {
    if (str[i] == '/') {
      bpf_map_update_elem(&tmp_prefix_hashes, &nof_hashes, &hash, BPF_EXIST);
      nof_hashes++;
    }
    hash = ((hash << 5) + hash) + str[i]; // hash * 33 + str[i]
    done = !str[i + 1];
  }
  bpf_map_update_elem(&tmp_prefix_hashes, &nof_hashes, &hash, BPF_EXIST);
  nof_hashes++;

  return nof_hashes;
}

/*
 * Callback setting ctx->to_deny = true when the prohibited path is a prefix of
 * the requested path, otherwise ctx->to_deny = false.
 */
static bool is_prefix_wrapper(struct bpf_map *map, u32 *key, char *prohib,
                              struct ctx_data *ctx) {
  int i;

  // Initializing i = 1 is necessary to avoid exceeding the verifier complexity
  // and it is not a problem since every path starts with '/'
  // NOTE: This loop may parse PATH_SIZE characters despite the path termination
  for (i = 1; i < PATH_SIZE /*&& prohib[i]*/ && prohib[i] == ctx->path[i]; i++);

  if (i == PATH_SIZE)
    return ctx->to_deny = true;

  bool is_ancestor = (!prohib[i] && (/* i > 0 && */ prohib[i - 1] == '/' ||
                      ctx->path[i] == '/'));
  bool is_equal = (/* i > 0 && */ !prohib[i - 1]);

  // Stop iteration when the prohibited path is a prefix of the requested path
  return ctx->to_deny = is_equal || is_ancestor;
}

/*
 * Callback setting ctx->to_deny = true if any of the prohibited path in the
 * collision chain is a prefix of the requested path, otherwise
 * ctx->to_deny = false
 */
static bool check_prohibition_chain(struct bpf_map *map, u32 *i, u64 *hash,
                                    struct ctx_data *ctx) {
  // Stop iteration when the requested path is denied or every colliding path
  // has been checked
  if (ctx->to_deny || *i == ctx->nof_prefixes)
    return true;

  // Retrieve the chain of colliding prohibited paths
  struct collision_key key = {ctx->policy_idx, *hash};
  struct bpf_map *collision_chain = bpf_map_lookup_elem(&policy_map, &key);
  if (collision_chain)
    bpf_for_each_map_elem(collision_chain, is_prefix_wrapper, ctx, 0);
  return false;
}

/*
 * Check wether the access request of the current task is denied by the policy
 */
static int check_access_request(struct path *path, struct dentry *dentry) {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

  // Look whether the current task is restricted by a policy
  int *policy_idx = ((int *)bpf_task_storage_get(&task_map, task, 0, 0));
  if (!policy_idx)
    return 0;

  int idx = 0;
  char *request = bpf_map_lookup_elem(&tmp_path, &idx);
  if (!request)
    return 0;

  // Retrieve the path of the access request
  int err = set_full_path(path, dentry, request);
  if (err)
    return 0;

  // Store prefix hashes of the requested path in the tmp_prohib array
  int nof_prefixes = compute_prefix_hashes(request);

  // Configure context data necessary for the following prohibition checks
  struct ctx_data ctx = { *policy_idx, request, nof_prefixes,
                          false /* result of the deny evaluation */ };

  // NOTE: We may evaluate multiple times the same collision chain when some of
  // the prefix hashes collide
  bpf_for_each_map_elem(&tmp_prefix_hashes, check_prohibition_chain, &ctx, 0);
  if (ctx.to_deny)
    return -EPERM;

  return 0;
}

static __always_inline void log_tmp_path() {
  int idx = 0;
  char *path = bpf_map_lookup_elem(&tmp_path, &idx);
  if (!path)
    return;

  bpf_printk("eBPF module blocked operation on: %s\n", path);
}

SEC("lsm/path_unlink")
int BPF_PROG(restrict_unlink, const struct path *dir, struct dentry *dentry) {
  const int err = check_access_request(dir, dentry);
  if (err)
    log_tmp_path();
  return err;
}

SEC("lsm/path_rmdir")
int BPF_PROG(restrict_rmdir, const struct path *dir, struct dentry *dentry) {
  const int err = check_access_request(dir, dentry);
  if (err)
    log_tmp_path();
  return err;
}

SEC("lsm/path_mkdir")
int BPF_PROG(restrict_mkdir, struct inode *dir, struct dentry *dentry,
             umode_t mode) {
  const int err = check_access_request(dir, dentry);
  if (err)
    log_tmp_path();
  return err;
}

SEC("lsm/path_mknod")
int BPF_PROG(restrict_mknod, const struct path *dir, struct dentry *dentry,
             umode_t mode, unsigned int dev) {
  const int err = check_access_request(dir, dentry);
  if (err)
    log_tmp_path();
  return err;
}

/*
 * Do not allow creation of hard links in the denied paths
*/
SEC("lsm/path_link")
int BPF_PROG(restrict_link_dst, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry) {
  const int err = check_access_request(new_dir, new_dentry);
  if (err)
    log_tmp_path();
  return err;
}

/*
 * Do not allow creation of hard links pointing at the content of the denied
 * paths
 * NOTE: Since Landlock is in place, it can only be done in the same directory
 * Reparenting cannot be allowed for deny list so LANDLOCK_ACCESS_FS_REFER
 * (https://lwn.net/Articles/885788/) will not be allowed for pathnames in the
 * deny list
*/
SEC("lsm/path_link")
int BPF_PROG(restrict_link_src, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry) {
  const int err = check_access_request(new_dir, old_dentry);
  if (err)
    log_tmp_path();
  return err;
}

/*
 * Do not allow to move an object to a denied path
*/
SEC("lsm/path_rename")
int BPF_PROG(restrict_rename_src,
             const struct path *old_dir, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry) {
  const int err = check_access_request(new_dir, new_dentry);
  if (err)
    log_tmp_path();
  return err;
}

/*
 * Do not allow to exfiltrate an object from the denied path
*/
SEC("lsm/path_rename")
int BPF_PROG(restrict_rename_dst,
             const struct path *old_dir, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry) {
  const int err = check_access_request(old_dir, old_dentry);
  if (err)
    log_tmp_path();
  return err;
}

SEC("lsm/file_open")
int BPF_PROG(restrict_open, struct file *file, int mask) {
  const int err = check_access_request(&file->f_path, NULL);
  if (err)
    log_tmp_path();
  return err;
}

/*
 * Do not allow creation of symlinks in the denied paths
*/
SEC("lsm/path_symlink") 
int BPF_PROG(restrict_symlink, const struct path *dir, struct dentry *dentry,
             const char *old_name) {
  const int err = check_access_request(dir, dentry);
  if (err)
    log_tmp_path();
  return err;
}
