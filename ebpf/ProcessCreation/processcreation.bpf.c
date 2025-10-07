#include "../helper.h"

char LICENSE[] SEC("license") = "GPL";

/*
    < Ring Buffer >
    Kernel -> User 
*/
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} processcreation_ringbuffer SEC(".maps");

/*
    <HASH MAP>
    User -> Kernel
*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32); // Process ID ( except the User AGENT Event )
    __type(value, __u8); 
} user_hash SEC(".maps");

// Helper
static inline bool ProcessCreation_Header(struct task_struct* process_task, enum event_type type, struct EventHeader* inout_header);
static inline bool exe_name_copy(void* exefile_buffer_addr, struct mm_struct * mm);
static inline bool cmdline_copy( void* cmdLine_buffer_addr, __u32* output_cmdline_size, struct mm_struct * mm);
static inline bool get_exe_file_size(__u64* output_exefile_size, struct mm_struct *mm);

static inline bool ProcessCreation_logic(enum event_type type);

SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    return ProcessCreation_logic(Process_fork);
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_template *ctx)
{
    return ProcessCreation_logic(Process_Exec);
}

SEC("kprobe/do_exit")
int BPF_KPROBE(handle_do_exit, long code)
{
    return ProcessCreation_logic(Process_Terminate);
}

// Helper
static inline bool ProcessCreation_logic(enum event_type type)
{
    struct Process_Creation_event* e = bpf_ringbuf_reserve(&processcreation_ringbuffer, sizeof(struct Process_Creation_event), 0);
    if (!e)
        return 0;

    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if( !ProcessCreation_Header(task, type, &e->Header) )
        goto FAIL_EXIT1;

    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(parent, pid);

    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    struct mm_struct *p_mm = BPF_CORE_READ(parent, mm);
    if (!mm || !p_mm)
        goto FAIL_EXIT1;

    // exe_file 복사
    // Self
    exe_name_copy(
        &e->exe_file,
        mm
    );
    get_exe_file_size(
        &e->exe_file_size,
        mm
    );
    // Parent
    exe_name_copy(
        &e->parent_exe_file,
        p_mm
    );
    get_exe_file_size(
        &e->parent_exe_file_size,
        p_mm
    );

    // CommandLine
    cmdline_copy(&e->cmdline, &e->cmdline_str_len, mm);
    bpf_ringbuf_submit(e, 0);
    goto RETURN;

    FAIL_EXIT1:
    {
        bpf_ringbuf_discard(e, 0);
        goto RETURN;
    }
    RETURN:
    {
        return 0;
    }
}

static inline bool ProcessCreation_Header(struct task_struct* process_task, enum event_type type, struct EventHeader* inout_header)
{
    return get_default_task_info( process_task, type, inout_header );
}

static inline bool cmdline_copy( void* cmdLine_buffer_addr, __u32* output_cmdline_size, struct mm_struct * mm)
{
    if(!mm) return false;

    long unsigned int arg_start = BPF_CORE_READ(mm, arg_start);
    long unsigned int arg_end   = BPF_CORE_READ(mm, arg_end);

    // 실제 읽을 길이를 cmdline 크기로 제한
    size_t max_len = PATH_MAX;
    size_t read_len = arg_end > arg_start ? arg_end - arg_start : 0;
    if (read_len > max_len)
        read_len = max_len;

    *output_cmdline_size = read_len;

    // arg_start ~ arg_end 를 온전히 다 읽어야함!
    /*
        Example)
        "sleep 1" -> 일 때,,
        s l e e p \0 1 \0 -> 이런형태임 중간에 \0이 있으므로 그대로 메모리 자체를 카피해야함
    */
    bpf_probe_read_user(cmdLine_buffer_addr, read_len, (void*)arg_start); 

    return true;
}


static inline bool get_exe_file_size(__u64* output_exefile_size, struct mm_struct *mm)
{
    struct file *exe_file = BPF_CORE_READ(mm, exe_file);
    struct inode *inode = BPF_CORE_READ(exe_file, f_inode);
    loff_t exe_size = BPF_CORE_READ(inode, i_size);

    *output_exefile_size = exe_size;
    return true;
}

static inline bool exe_name_copy(void* exefile_buffer_addr, struct mm_struct * mm)
{
    struct file *exe = NULL;
    if (mm)
        exe = BPF_CORE_READ(mm, exe_file);
    else
        return false;

    if (exe) {
        struct path p = BPF_CORE_READ(exe, f_path);
        
        struct dentry *dentry = NULL;
        bpf_probe_read_kernel(&dentry, sizeof(dentry), &p.dentry);

        Get_Reverse_Full_Path_by_dentry(dentry, exefile_buffer_addr);

        /*
        const char *name_ptr = NULL;
        bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr), &dentry->d_name.name);

        bpf_probe_read_str(exefile_buffer_addr, exefile_buffer_size, name_ptr);
        */
    }
    else
        return false;
    
    return true;
}