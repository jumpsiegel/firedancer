#ifndef HEADER_fd_src_ballet_runtime_vm_fd_sbpf_interp_h
#define HEADER_fd_src_ballet_runtime_vm_fd_sbpf_interp_h

#include "fd_opcodes.h"
#include "fd_mem_map.h"
#include "fd_stack.h"
#include "fd_log_collector.h"

#define FD_VM_HEAP_SZ (32*1024)

#define FD_VM_SBPF_VALIDATE_SUCCESS               (0UL)
#define FD_VM_SBPF_VALIDATE_ERR_INVALID_OPCODE    (1UL)
#define FD_VM_SBPF_VALIDATE_ERR_INVALID_SRC_REG   (2UL)
#define FD_VM_SBPF_VALIDATE_ERR_INVALID_DST_REG   (3UL)
#define FD_VM_SBPF_VALIDATE_ERR_INF_LOOP          (4UL)
#define FD_VM_SBPF_VALIDATE_ERR_JMP_OUT_OF_BOUNDS (5UL)
#define FD_VM_SBPF_VALIDATE_ERR_JMP_TO_ADDL_IMM   (6UL)
#define FD_VM_SBPF_VALIDATE_ERR_INVALID_END_IMM   (7UL)
#define FD_VM_SBPF_VALIDATE_ERR_INCOMPLETE_LDQ    (8UL)
#define FD_VM_SBPF_VALIDATE_ERR_LDQ_NO_ADDL_IMM   (9UL)
#define FD_VM_SBPF_VALIDATE_ERR_NO_SUCH_EXT_CALL  (10UL)

typedef uchar fd_pubkey_t[32];

struct fd_vm_sbpf_exec_context;
typedef struct fd_vm_sbpf_exec_context fd_vm_sbpf_exec_context_t;

typedef ulong (*fd_vm_sbpf_syscall_fn_ptr_t)(fd_vm_sbpf_exec_context_t * ctx, ulong arg0, ulong arg1, ulong arg2, ulong arg3, ulong arg4, ulong * ret);

struct fd_vm_sbpf_syscall_map {
  uint key;
  uint hash;

  fd_vm_sbpf_syscall_fn_ptr_t syscall_fn_ptr;
};
typedef struct fd_vm_sbpf_syscall_map fd_vm_sbpf_syscall_map_t;

#define MAP_NAME        fd_vm_sbpf_syscall_map
#define MAP_T           fd_vm_sbpf_syscall_map_t
#define MAP_LG_SLOT_CNT 6
#include "../util/tmpl/fd_map.c"

struct fd_vm_sbpf_exec_account_info {
  fd_pubkey_t * pubkey;
  ulong *       lamports;
  ulong         data_len;
  uchar *       data;
  fd_pubkey_t * owner;
  ulong         rent_epoch;
  uint          is_signer;
  uint          is_writable;
  uint          is_executable;
};
typedef struct fd_vm_sbpf_exec_account_info fd_vm_sbpf_exec_account_info_t;

struct fd_vm_sbpf_exec_params {
  fd_vm_sbpf_exec_account_info_t *  accounts;
  ulong                             accounts_len;
  uchar *                           data;
  ulong                             data_len;
  fd_pubkey_t *                     program_id;
};
typedef struct fd_vm_sbpf_exec_params fd_vm_sbpf_exec_params_t;

struct fd_vm_sbpf_exec_context {
  long                      entrypoint;
  fd_vm_sbpf_syscall_map_t  syscall_map;
  fd_vm_sbpf_instr_t *      instrs;
  ulong                     instrs_sz;
  
  ulong                 register_file[11];
  ulong                 program_counter;
  ulong                 instruction_counter;
  fd_vm_log_collector_t log_collector;
  ulong                 compute_budget;

  uchar *       read_only;
  ulong         read_only_sz;
  uchar *       input;
  ulong         input_sz;
  fd_vm_stack_t stack;
  uchar         heap[FD_VM_HEAP_SZ];
};

struct fd_vm_sbpf_program {
  ulong num_ext_funcs;
};
typedef struct fd_vm_sbpf_program fd_vm_sbpf_program_t;

void fd_vm_sbpf_interp_register_syscall( fd_vm_sbpf_exec_context_t * ctx, char const * name, fd_vm_sbpf_syscall_fn_ptr_t fn_ptr ); 

void fd_vm_sbpf_interp_instrs(fd_vm_sbpf_exec_context_t * ctx );

ulong fd_vm_sbpf_interp_validate( fd_vm_sbpf_exec_context_t * ctx );

ulong fd_vm_sbpf_interp_translate_vm_to_host( fd_vm_sbpf_exec_context_t * ctx,
                                              uchar                       write,
                                              ulong                       vm_addr,
                                              ulong                       sz,
                                              void * *                   host_addr );

#endif /* HEADER_fd_src_ballet_runtime_vm_fd_sbpf_interp_h */