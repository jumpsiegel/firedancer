/* Automatically generated nanopb header */
<<<<<<< HEAD
/* Generated by nanopb-0.4.8 */
=======
/* Generated by nanopb-0.4.8-dev */
>>>>>>> main

#ifndef PB_SOLANA_CAPTURE_SRC_FLAMENCO_CAPTURE_FD_SOLCAP_PB_H_INCLUDED
#define PB_SOLANA_CAPTURE_SRC_FLAMENCO_CAPTURE_FD_SOLCAP_PB_H_INCLUDED
#include "../nanopb/pb_firedancer.h"

#if PB_PROTO_HEADER_VERSION != 40
#error Regenerate this file with the current version of nanopb generator.
#endif

/* Struct definitions */
/* FileMeta is the metadata blob part of the file header */
typedef struct _fd_solcap_FileMeta {
    /* Number of the first slot in this capture file */
    uint64_t first_slot;
    /* Total number of slots in this capture file */
    uint64_t slot_cnt;
    /* Magic number of main block type */
    uint64_t main_block_magic;
} fd_solcap_FileMeta;

/* BankPreimage contains the pre-image of the bank hash for a given slot.
 Only present for slots that were not skipped. */
typedef struct _fd_solcap_BankPreimage {
    uint64_t slot;
    pb_byte_t bank_hash[32];
    /* prev_bank_hash is the bank hash of the previous block */
    pb_byte_t prev_bank_hash[32];
    /* account_delta_hash is the hash of the changed accounts */
    pb_byte_t account_delta_hash[32];
    /* poh_hash is the Proof-of-History hash of the current block */
    pb_byte_t poh_hash[32];
    /* signature_cnt is the number of transactions in the current block
 TODO is this correct? */
    uint64_t signature_cnt;
    /* account_cnt is the number of accounts changed in the current
 block.  This is also the number of leaves in the account delta
 Merkle tree. */
    uint64_t account_cnt;
    /* account_table_coff is offset from the first byte of the current
 chunk to the first byte of the account table chunk. */
    int64_t account_table_coff;
} fd_solcap_BankPreimage;

typedef struct _fd_solcap_AccountTableMeta {
    /* slot is the slot number that this accounts table refers to. */
    uint64_t slot;
    /* account_table_coff is the chunk offset to the first entry of the
 accounts table. */
    uint64_t account_table_coff;
    /* account_table_cnt is the number of records in the accounts table.
 Equals BankPreimage.account_cnt. */
    uint64_t account_table_cnt;
} fd_solcap_AccountTableMeta;

typedef struct _fd_solcap_AccountMeta {
    uint64_t lamports;
    uint64_t slot;
    uint64_t rent_epoch;
    pb_byte_t owner[32];
    bool executable;
    /* data_coff is the chunk offset to account data. */
    int64_t data_coff;
    uint64_t data_sz;
} fd_solcap_AccountMeta;

typedef struct _fd_solcap_Transaction {
    pb_byte_t txn_sig[64];
    uint64_t slot;
    int32_t fd_txn_err;
    uint32_t fd_custom_err;
    uint64_t solana_txn_err;
    uint64_t fd_cus_used;
    uint64_t solana_cus_used;
<<<<<<< HEAD
=======
    /* failed_instr_path is the tree path to the failed instruction.
 Zero length implies success. */
    pb_size_t failed_instr_path_count;
    uint32_t failed_instr_path[4];
    /* instr_err is the instruction processing error code. */
    uint32_t instr_err;
>>>>>>> main
} fd_solcap_Transaction;


#ifdef __cplusplus
extern "C" {
#endif

/* Initializer values for message structs */
#define fd_solcap_FileMeta_init_default          {0, 0, 0}
#define fd_solcap_BankPreimage_init_default      {0, {0}, {0}, {0}, {0}, 0, 0, 0}
#define fd_solcap_AccountTableMeta_init_default  {0, 0, 0}
#define fd_solcap_AccountMeta_init_default       {0, 0, 0, {0}, 0, 0, 0}
<<<<<<< HEAD
#define fd_solcap_Transaction_init_default       {{0}, 0, 0, 0, 0, 0, 0}
=======
#define fd_solcap_Transaction_init_default       {{0}, 0, 0, 0, 0, 0, 0, 0, {0, 0, 0, 0}, 0}
>>>>>>> main
#define fd_solcap_FileMeta_init_zero             {0, 0, 0}
#define fd_solcap_BankPreimage_init_zero         {0, {0}, {0}, {0}, {0}, 0, 0, 0}
#define fd_solcap_AccountTableMeta_init_zero     {0, 0, 0}
#define fd_solcap_AccountMeta_init_zero          {0, 0, 0, {0}, 0, 0, 0}
<<<<<<< HEAD
#define fd_solcap_Transaction_init_zero          {{0}, 0, 0, 0, 0, 0, 0}
=======
#define fd_solcap_Transaction_init_zero          {{0}, 0, 0, 0, 0, 0, 0, 0, {0, 0, 0, 0}, 0}
>>>>>>> main

/* Field tags (for use in manual encoding/decoding) */
#define fd_solcap_FileMeta_first_slot_tag        1
#define fd_solcap_FileMeta_slot_cnt_tag          2
#define fd_solcap_FileMeta_main_block_magic_tag  3
#define fd_solcap_BankPreimage_slot_tag          1
#define fd_solcap_BankPreimage_bank_hash_tag     2
#define fd_solcap_BankPreimage_prev_bank_hash_tag 3
#define fd_solcap_BankPreimage_account_delta_hash_tag 4
#define fd_solcap_BankPreimage_poh_hash_tag      5
#define fd_solcap_BankPreimage_signature_cnt_tag 6
#define fd_solcap_BankPreimage_account_cnt_tag   7
#define fd_solcap_BankPreimage_account_table_coff_tag 8
#define fd_solcap_AccountTableMeta_slot_tag      1
#define fd_solcap_AccountTableMeta_account_table_coff_tag 2
#define fd_solcap_AccountTableMeta_account_table_cnt_tag 3
#define fd_solcap_AccountMeta_lamports_tag       1
#define fd_solcap_AccountMeta_slot_tag           2
#define fd_solcap_AccountMeta_rent_epoch_tag     3
#define fd_solcap_AccountMeta_owner_tag          4
#define fd_solcap_AccountMeta_executable_tag     5
#define fd_solcap_AccountMeta_data_coff_tag      6
#define fd_solcap_AccountMeta_data_sz_tag        7
#define fd_solcap_Transaction_txn_sig_tag        1
#define fd_solcap_Transaction_slot_tag           2
#define fd_solcap_Transaction_fd_txn_err_tag     3
#define fd_solcap_Transaction_fd_custom_err_tag  4
#define fd_solcap_Transaction_solana_txn_err_tag 5
#define fd_solcap_Transaction_fd_cus_used_tag    6
#define fd_solcap_Transaction_solana_cus_used_tag 7
<<<<<<< HEAD
=======
#define fd_solcap_Transaction_failed_instr_path_tag 8
#define fd_solcap_Transaction_instr_err_tag      9
>>>>>>> main

/* Struct field encoding specification for nanopb */
#define fd_solcap_FileMeta_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UINT64,   first_slot,        1) \
X(a, STATIC,   SINGULAR, UINT64,   slot_cnt,          2) \
X(a, STATIC,   SINGULAR, FIXED64,  main_block_magic,   3)
#define fd_solcap_FileMeta_CALLBACK NULL
#define fd_solcap_FileMeta_DEFAULT NULL

#define fd_solcap_BankPreimage_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UINT64,   slot,              1) \
X(a, STATIC,   SINGULAR, FIXED_LENGTH_BYTES, bank_hash,         2) \
X(a, STATIC,   SINGULAR, FIXED_LENGTH_BYTES, prev_bank_hash,    3) \
X(a, STATIC,   SINGULAR, FIXED_LENGTH_BYTES, account_delta_hash,   4) \
X(a, STATIC,   SINGULAR, FIXED_LENGTH_BYTES, poh_hash,          5) \
X(a, STATIC,   SINGULAR, UINT64,   signature_cnt,     6) \
X(a, STATIC,   SINGULAR, UINT64,   account_cnt,       7) \
X(a, STATIC,   SINGULAR, INT64,    account_table_coff,   8)
#define fd_solcap_BankPreimage_CALLBACK NULL
#define fd_solcap_BankPreimage_DEFAULT NULL

#define fd_solcap_AccountTableMeta_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UINT64,   slot,              1) \
X(a, STATIC,   SINGULAR, UINT64,   account_table_coff,   2) \
X(a, STATIC,   SINGULAR, UINT64,   account_table_cnt,   3)
#define fd_solcap_AccountTableMeta_CALLBACK NULL
#define fd_solcap_AccountTableMeta_DEFAULT NULL

#define fd_solcap_AccountMeta_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UINT64,   lamports,          1) \
X(a, STATIC,   SINGULAR, UINT64,   slot,              2) \
X(a, STATIC,   SINGULAR, UINT64,   rent_epoch,        3) \
X(a, STATIC,   SINGULAR, FIXED_LENGTH_BYTES, owner,             4) \
X(a, STATIC,   SINGULAR, BOOL,     executable,        5) \
X(a, STATIC,   SINGULAR, INT64,    data_coff,         6) \
X(a, STATIC,   SINGULAR, UINT64,   data_sz,           7)
#define fd_solcap_AccountMeta_CALLBACK NULL
#define fd_solcap_AccountMeta_DEFAULT NULL

#define fd_solcap_Transaction_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, FIXED_LENGTH_BYTES, txn_sig,           1) \
X(a, STATIC,   SINGULAR, UINT64,   slot,              2) \
X(a, STATIC,   SINGULAR, INT32,    fd_txn_err,        3) \
X(a, STATIC,   SINGULAR, UINT32,   fd_custom_err,     4) \
X(a, STATIC,   SINGULAR, UINT64,   solana_txn_err,    5) \
X(a, STATIC,   SINGULAR, UINT64,   fd_cus_used,       6) \
<<<<<<< HEAD
X(a, STATIC,   SINGULAR, UINT64,   solana_cus_used,   7)
=======
X(a, STATIC,   SINGULAR, UINT64,   solana_cus_used,   7) \
X(a, STATIC,   REPEATED, UINT32,   failed_instr_path,   8) \
X(a, STATIC,   SINGULAR, UINT32,   instr_err,         9)
>>>>>>> main
#define fd_solcap_Transaction_CALLBACK NULL
#define fd_solcap_Transaction_DEFAULT NULL

extern const pb_msgdesc_t fd_solcap_FileMeta_msg;
extern const pb_msgdesc_t fd_solcap_BankPreimage_msg;
extern const pb_msgdesc_t fd_solcap_AccountTableMeta_msg;
extern const pb_msgdesc_t fd_solcap_AccountMeta_msg;
extern const pb_msgdesc_t fd_solcap_Transaction_msg;

/* Defines for backwards compatibility with code written before nanopb-0.4.0 */
#define fd_solcap_FileMeta_fields &fd_solcap_FileMeta_msg
#define fd_solcap_BankPreimage_fields &fd_solcap_BankPreimage_msg
#define fd_solcap_AccountTableMeta_fields &fd_solcap_AccountTableMeta_msg
#define fd_solcap_AccountMeta_fields &fd_solcap_AccountMeta_msg
#define fd_solcap_Transaction_fields &fd_solcap_Transaction_msg

/* Maximum encoded size of messages (where known) */
<<<<<<< HEAD
#define SOLANA_CAPTURE_FD_SOLCAP_PB_H_MAX_SIZE   fd_solcap_BankPreimage_size
=======
>>>>>>> main
#define fd_solcap_AccountMeta_size               91
#define fd_solcap_AccountTableMeta_size          33
#define fd_solcap_BankPreimage_size              180
#define fd_solcap_FileMeta_size                  31
<<<<<<< HEAD
#define fd_solcap_Transaction_size               127
=======
#define fd_solcap_Transaction_size               157
>>>>>>> main

/* Mapping from canonical names (mangle_names or overridden package name) */
#define solana_capture_FileMeta fd_solcap_FileMeta
#define solana_capture_BankPreimage fd_solcap_BankPreimage
#define solana_capture_AccountTableMeta fd_solcap_AccountTableMeta
#define solana_capture_AccountMeta fd_solcap_AccountMeta
#define solana_capture_Transaction fd_solcap_Transaction
<<<<<<< HEAD
#define solana_capture_FileMeta_init_default fd_solcap_FileMeta_init_default
#define solana_capture_BankPreimage_init_default fd_solcap_BankPreimage_init_default
#define solana_capture_AccountTableMeta_init_default fd_solcap_AccountTableMeta_init_default
#define solana_capture_AccountMeta_init_default fd_solcap_AccountMeta_init_default
#define solana_capture_Transaction_init_default fd_solcap_Transaction_init_default
#define solana_capture_FileMeta_init_zero fd_solcap_FileMeta_init_zero
#define solana_capture_BankPreimage_init_zero fd_solcap_BankPreimage_init_zero
#define solana_capture_AccountTableMeta_init_zero fd_solcap_AccountTableMeta_init_zero
#define solana_capture_AccountMeta_init_zero fd_solcap_AccountMeta_init_zero
#define solana_capture_Transaction_init_zero fd_solcap_Transaction_init_zero
=======
>>>>>>> main

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
