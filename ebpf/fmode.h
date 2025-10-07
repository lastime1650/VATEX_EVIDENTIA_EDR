// bpf/fmode.h

#ifndef FMODE_H_
#define FMODE_H_

/*
 * Dependent definitions for fmode_t.
 * Defined in include/linux/fs.h, but not exported to BPF.
 */
#ifdef __CHECKER__
#define __bitwise __attribute__((bitwise))
#define __force __attribute__((force))
#else
#define __bitwise
#define __force
#endif



typedef unsigned int __bitwise fmode_t;

/* file is open for reading */
#define FMODE_READ ((__force fmode_t)(1 << 0))
/* file is open for writing */
#define FMODE_WRITE ((__force fmode_t)(1 << 1))
/* file is seekable */
#define FMODE_LSEEK ((__force fmode_t)(1 << 2))
/* file can be accessed using pread */
#define FMODE_PREAD ((__force fmode_t)(1 << 3))
/* file can be accessed using pwrite */
#define FMODE_PWRITE ((__force fmode_t)(1 << 4))
/* File is opened for execution with sys_execve / sys_uselib */
#define FMODE_EXEC ((__force fmode_t)(1 << 5))
/* File writes are restricted (block device specific) */
#define FMODE_WRITE_RESTRICTED ((__force fmode_t)(1 << 6))
/* File supports atomic writes */
#define FMODE_CAN_ATOMIC_WRITE ((__force fmode_t)(1 << 7))
/* File is opened with O_PATH; almost nothing can be done with it */
#define FMODE_PATH ((__force fmode_t)(1 << 14))

/* 파일 모드 비트 (i_mode) */
#define S_IFMT   0170000  /* 파일 타입 마스크 */
#define S_IFSOCK 0140000  /* 소켓 */
#define S_IFLNK  0120000  /* 심볼릭 링크 */
#define S_IFREG  0100000  /* 일반 파일 */
#define S_IFBLK  0060000  /* 블록 디바이스 */
#define S_IFDIR  0040000  /* 디렉토리 */
#define S_IFCHR  0020000  /* 문자 디바이스 */
#define S_IFIFO  0010000  /* FIFO */

/* 권한 비트 */
#define S_ISUID  0004000  /* set-user-ID */
#define S_ISGID  0002000  /* set-group-ID */
#define S_ISVTX  0001000  /* sticky bit */

#define S_IRUSR  0000400  /* 소유자 읽기 */
#define S_IWUSR  0000200  /* 소유자 쓰기 */
#define S_IXUSR  0000100  /* 소유자 실행 */

#define S_IRGRP  0000040  /* 그룹 읽기 */
#define S_IWGRP  0000020  /* 그룹 쓰기 */
#define S_IXGRP  0000010  /* 그룹 실행 */

#define S_IROTH  0000004  /* 다른 사용자 읽기 */
#define S_IWOTH  0000002  /* 다른 사용자 쓰기 */
#define S_IXOTH  0000001  /* 다른 사용자 실행 */

/* 타입 체크 매크로 */
#define S_ISREG(m)  (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)
#define S_ISLNK(m)  (((m) & S_IFMT) == S_IFLNK)
#define S_ISBLK(m)  (((m) & S_IFMT) == S_IFBLK)
#define S_ISCHR(m)  (((m) & S_IFMT) == S_IFCHR)
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)

#define MAY_EXEC 1
#define MAY_WRITE 2
#define MAY_READ 4
#define MAY_APPEND 8
#define MAY_ACCESS 16
#define MAY_OPEN 32


#define ATTR_MODE 0x0001
#define ATTR_UID  0x0002
#define ATTR_GID  0x0004



#endif // FMODE_H_