

#ifndef EVENTS

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <linux/limits.h>


enum {
    FILE_OP_READ = 0,
    FILE_OP_WRITE = 1,
    FILE_OP_OTHER = 2,
};

// 이벤트 타입을 구분하기 위한 enum
enum event_type {
    Process_fork,
    Process_Exec,
    Process_Terminate,
    
    Network,
    
    Filesystem_Create,
    Filesystem_Unlink,
    Filesystem_Open,
    Filesystem_Read,
    Filesystem_Write,
    Filesystem_Rename,
    Filesystem_mkdir,
    Filesystem_rmdir,
    Filesystem_SetAttr // 속성 변경관련
};

/*
    Ring Buffer Structs
*/

struct EventHeader{
    enum event_type type;

    __u64 pid;

    __u32 uid;
    __u32 gid;

};
struct inode_meta
{
    struct
    {
        bool is_IRUSR;  bool is_IWUSR;  bool is_IXUSR;   // 3
        bool is_IRGRP;  bool is_IWGRP;  bool is_IXGRP;   // 6
        bool is_IROTH;  bool is_IWOTH;  bool is_IXOTH;   // 9
        bool is_SUID;   bool is_SGID;   bool is_sticky;  // 12
    } permission;

    __u32 uid;      // 4바이트
    __u32 gid;      // 4바이트 → 다음 bool 배열 8바이트 alignment 위해 pad 0 추가

    bool is_symlink;
    bool is_regular;
    bool is_directory;
    bool is_char_device;
    bool is_block_device;
    bool is_fifo;
    bool is_socket;

    /* inode 관련 정보 */
    __u64 ino;
    __u64 size;
    __u64 blocks;
    __u32 nlink;
    __u32 mode;
    __u32 generation;
    dev_t rdev;

    /* ACL */
    bool has_acl;
    bool has_default_acl;

    /* 암호화/검증 */
    bool is_encrypted;
    bool is_verified;

    /* open 상태 */
    __u32 write_count;
    __u32 read_count;

    /* 시간 정보 */
    __u64 atime;
    __u64 mtime;
    __u64 ctime;
    __u64 btime;
    char pad[4];
 }  __attribute__((packed)); 

// 프로세스 생성 및 종료
struct Process_Creation_event {
    
    struct EventHeader Header;


    __u64 ppid;

    char exe_file[PATH_MAX]; //revsered
    __u64 exe_file_size;

    char parent_exe_file[PATH_MAX]; //revsered
    __u64 parent_exe_file_size;

    char cmdline[PATH_MAX];
    __u32 cmdline_str_len;
};

// 네트워크
struct Network_event {
    struct EventHeader Header;

    int ifindex;
    unsigned int pkt_len;
    bool is_INGRESS;
    int protocol;
    char ipSrc[16];
    unsigned int portSrc;

    char ipDst[16];
    unsigned int portDst;
};

// 파일 시스템

/* 특수 권한 비트 정의 */
#define S_ISUID  0004000
#define S_ISGID  0002000
#define S_ISVTX  0001000



struct Filesystem_file_meta
{
    struct
    {
        bool is_reverse;           // 1바이트
        char pad[7];               // 8바이트 alignment
        char filepath[PATH_MAX];   // PATH_MAX 바이트
        char pad2[8 - (PATH_MAX % 8)]; // 8바이트 alignment 보장
        unsigned long long filesize;           // 8바이트
    } filename;

    struct inode_meta inode_info;
};
struct Filesystem_dir_meta
{
    struct
    {
        bool is_reverse;           // 경로가 역순인지
        char pad[3];
        char dirpath[PATH_MAX];   // 경로 문자열
        char dirname[PATH_MAX];   // 디렉터리 파일 문자열
    } dirname;

    struct inode_meta inode_info;
};



typedef struct Filesystem_event_file
{
    struct EventHeader Header;
    char action[32];

    struct Filesystem_file_meta fileinfo;

}Filesystem_event_file;

typedef Filesystem_event_file Filesystem_event_create;
typedef Filesystem_event_file Filesystem_event_open;
typedef Filesystem_event_file Filesystem_event_write;
typedef Filesystem_event_file Filesystem_event_setattr;

typedef struct Filesystem_event_rename
{
    struct EventHeader Header;
    char action[32];
    

    char old_dir[PATH_MAX];
    char old_filename[PATH_MAX];

    char new_dir[PATH_MAX];
    char new_filename[PATH_MAX];

    struct Filesystem_file_meta fileinfo;

}Filesystem_event_rename;



typedef struct Filesystem_event_dir
{
    struct EventHeader Header;
    char action[32];

    struct Filesystem_dir_meta dirinfo;

}Filesystem_event_dir;

typedef Filesystem_event_dir Filesystem_event_mkdir;
typedef Filesystem_event_dir Filesystem_event_rmdir;
typedef Filesystem_event_dir Filesystem_event_unlink;




#endif