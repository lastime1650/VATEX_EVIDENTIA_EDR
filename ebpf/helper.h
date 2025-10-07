
#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86
#endif


#ifndef OWN_HELPER_H
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <linux/limits.h>


#include "events.h"
#include "fmode.h"
#ifndef __typeof_unqual__
#define __typeof_unqual__ typeof
#endif

__always_inline void Set_inode_meta(struct inode *inode, struct inode_meta* meta)
{
    
    if (!inode)
        return;

    umode_t mode = BPF_CORE_READ(inode, i_mode);
    meta->mode = mode;

    /* 권한 */
    meta->permission.is_IRUSR = (mode & S_IRUSR) != 0;
    meta->permission.is_IWUSR = (mode & S_IWUSR) != 0;
    meta->permission.is_IXUSR = (mode & S_IXUSR) != 0;

    meta->permission.is_IRGRP = (mode & S_IRGRP) != 0;
    meta->permission.is_IWGRP = (mode & S_IWGRP) != 0;
    meta->permission.is_IXGRP = (mode & S_IXGRP) != 0;

    meta->permission.is_IROTH = (mode & S_IROTH) != 0;
    meta->permission.is_IWOTH = (mode & S_IWOTH) != 0;
    meta->permission.is_IXOTH = (mode & S_IXOTH) != 0;

    meta->permission.is_SUID = (mode & S_ISUID) != 0;
    meta->permission.is_SGID = (mode & S_ISGID) != 0;
    meta->permission.is_sticky = (mode & S_ISVTX) != 0;

    /* 소유자/그룹 */
    meta->uid = (__u32)BPF_CORE_READ(inode, i_uid.val);
    meta->gid = (__u32)BPF_CORE_READ(inode, i_gid.val);

    /* 파일 타입 */
    meta->is_symlink     = (mode & S_IFMT) == S_IFLNK;
    meta->is_regular     = (mode & S_IFMT) == S_IFREG;
    meta->is_directory   = (mode & S_IFMT) == S_IFDIR;
    meta->is_char_device = (mode & S_IFMT) == S_IFCHR;
    meta->is_block_device= (mode & S_IFMT) == S_IFBLK;
    meta->is_fifo        = (mode & S_IFMT) == S_IFIFO;
    meta->is_socket      = (mode & S_IFMT) == S_IFSOCK;

    /* inode 정보 */
    meta->size       = BPF_CORE_READ(inode, i_size);
    meta->blocks     = BPF_CORE_READ(inode, i_blocks);
    meta->nlink      = BPF_CORE_READ(inode, i_nlink);
    meta->ino        = BPF_CORE_READ(inode, i_ino);
    meta->generation = BPF_CORE_READ(inode, i_generation);
    meta->rdev       = BPF_CORE_READ(inode, i_rdev);

    /* ACL */
    meta->has_acl         = BPF_CORE_READ(inode, i_acl) != NULL;
    meta->has_default_acl = BPF_CORE_READ(inode, i_default_acl) != NULL;

    /* 암호화/검증 */
    meta->is_encrypted = BPF_CORE_READ(inode, i_crypt_info) != NULL;
    meta->is_verified  = BPF_CORE_READ(inode, i_verity_info) != NULL;

    /* open 상태 */
    meta->write_count = BPF_CORE_READ(inode, i_writecount.counter);
    meta->read_count  = BPF_CORE_READ(inode, i_readcount.counter);

    /* 시간 정보 */
    #ifdef HAVE_STRUCT_INODE_I_ATIME
    meta->atime = BPF_CORE_READ(inode, i_atime.tv_sec);
    meta->mtime = BPF_CORE_READ(inode, i_mtime.tv_sec);
    meta->ctime = BPF_CORE_READ(inode, i_ctime.tv_sec);
    #else
    meta->atime = BPF_CORE_READ(inode, i_atime_sec);
    meta->mtime = BPF_CORE_READ(inode, i_mtime_sec);
    meta->ctime = BPF_CORE_READ(inode, i_ctime_sec);
    #endif

    #ifdef HAVE_STRUCT_INODE_I_BTIME
    meta->btime = BPF_CORE_READ(inode, i_birthtime.tv_sec);
    #else
    meta->btime = 0;
    #endif
}


/* capture_file_open */
#define MAX_PATH_LEN 512

/* capture_inode_rename*/
#define MAX_DEPTH 30
#define MAX_NAME_LEN 255
#define MAX_PATH_LEN 2048

// 루프 콜백에 전달할 데이터 구조
struct loop_ctx {
    struct dentry *cur;
    char *filepath;
    __u32 offset;
};

// bpf_loop의 각 반복에서 호출될 콜백 함수
static __always_inline int get_path_segment(unsigned int index, struct loop_ctx *ctx) {
    // 경계 검사: 콜백 시작 시점에 offset을 확인
    if (ctx->offset >= MAX_PATH_LEN - (MAX_NAME_LEN + 1)) {
        return 1; // 1을 반환하면 루프 중단
    }

    struct dentry *cur = ctx->cur;
    if (!cur) return 1;

    struct dentry *parent = BPF_CORE_READ(cur, d_parent);
    if (!parent || cur == parent) return 1;

    struct qstr d_name = BPF_CORE_READ(cur, d_name);
    __u32 len_tmp = BPF_CORE_READ(&d_name, len);

    if (len_tmp > 0) {
        if (len_tmp > MAX_NAME_LEN) len_tmp = MAX_NAME_LEN;

        if (ctx->offset + len_tmp + 2 > MAX_PATH_LEN) return 1;

        const unsigned char *name_ptr = BPF_CORE_READ(&d_name, name);
        bpf_probe_read_kernel_str(&ctx->filepath[ctx->offset], len_tmp + 1, name_ptr);
        
        ctx->offset += len_tmp;
        ctx->filepath[ctx->offset++] = '/';
    }

    ctx->cur = parent; // 다음 dentry로 업데이트
    return 0; // 0을 반환하면 루프 계속
}

// 기존 Get_Full_Path_by_dentry 함수 수정
void Get_Reverse_Full_Path_by_dentry(struct dentry* dentry, char* filepath)
{
    struct loop_ctx ctx = {
        .cur = dentry,
        .filepath = filepath,
        .offset = 0,
    };
    
    // bpf_loop 호출: 최대 MAX_DEPTH 만큼 콜백 함수를 실행
    bpf_loop(MAX_DEPTH, get_path_segment, &ctx, 0);

    // 루프 종료 후 NULL 문자 처리
    if (ctx.offset > 0) {
        filepath[ctx.offset - 1] = '\0';
    } else {
        filepath[0] = '\0';
    }
}



static inline bool get_user_info(struct task_struct *task, __u32* out_uid, __u32* out_gid )
{
    struct cred* cred = BPF_CORE_READ(task, cred);
    if(!cred) return false;
    kuid_t uid = BPF_CORE_READ(cred, uid);
    kgid_t gid = BPF_CORE_READ(cred, gid);

    *out_uid = uid.val;
    *out_gid = gid.val;

    return true;
}


bool get_default_task_info( struct task_struct *task, enum event_type type, struct EventHeader* out_Header  )
{
    if(!out_Header) return false;

    out_Header->pid = BPF_CORE_READ(task, pid);
    out_Header->type = type;

    get_user_info(task,  &out_Header->uid, &out_Header->gid);

    return true;
}


#endif