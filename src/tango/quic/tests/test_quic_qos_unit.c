#include "../../../util/fd_util.h"
#include "../../stake/fd_stake.h"
#include "../../tcache/fd_tcache.h"
#include "../fd_quic_qos.h"

#define LG_SLOT_CNT 2
#define SLOT_CNT    ( 1UL << LG_SLOT_CNT )

// fd_stake_pubkey_t pubkeys[SLOT_CNT] = {
//     { .pubkey = { 44, 174, 25,  39, 43, 255, 200, 81, 55, 73, 10,  113, 174, 91, 223, 80,
//                   50, 51,  102, 25, 63, 110, 36,  28, 51, 11, 174, 179, 110, 8,  25,  152 } },
//     { .pubkey = { 250, 56, 248, 84,  190, 46,  154, 76,  15, 72, 181, 205, 32, 96, 128, 213,
//                   158, 33, 81,  193, 63,  154, 93,  254, 15, 81, 32,  175, 54, 60, 179, 224 } },
//     { .pubkey = { 225, 102, 95, 246, 174, 91, 1,  240, 118, 174, 119, 113, 150, 146, 149, 29,
//                   253, 10,  69, 168, 188, 51, 31, 11,  67,  18,  201, 181, 189, 178, 159, 178 } },
//     { .pubkey = { 106, 14,  75, 83,  229, 211, 185, 118, 244, 162, 231,
//                   233, 145, 79, 246, 117, 81,  189, 247, 148, 226, 189,
//                   96,  243, 51, 115, 161, 27,  100, 78,  207, 183 } } };

// void
// test_fd_quic_qos_conn_lru( void ) {
//   fd_wksp_t * wksp = fd_wksp_new_anonymous(
//       FD_SHMEM_GIGANTIC_PAGE_SZ, 1, fd_shmem_cpu_idx( fd_shmem_numa_idx( 0 ) ), "wksp", 0UL );
//   FD_TEST( wksp );

//   ulong depth = SLOT_CNT - 2;
//   ulong map_cnt = SLOT_CNT;
//   void * mem = fd_wksp_alloc_laddr(
//       wksp, fd_tcache_align(), fd_tcache_footprint( depth, map_cnt ), 42UL );
//   fd_tcache_t * tcache = fd_tcache_join( fd_tcache_new( mem, depth, map_cnt ) );
//   FD_LOG_NOTICE(("tcache %lu", tcache));


//   // fd_quic_qos_limits_t qos_limits = {
//   //     .min_streams     = 128,
//   //     .max_streams     = 1,
//   //     .total_streams   = 1,
//   //     .pq_lg_slot_cnt   = LG_SLOT_CNT,
//   //     .lru_lg_slot_cnt = LG_SLOT_CNT,
//   // };
//   // void * mem =
//   //     fd_wksp_alloc_laddr( wksp, fd_quic_qos_align(), fd_quic_qos_footprint( &qos_limits ), 42UL
//   //     );
//   // fd_quic_qos_t * qos = fd_quic_qos_join( fd_quic_qos_new( mem, &qos_limits ) );

//   // /* initialize stakes */
//   // fd_stake_node_t * staked_nodes = fd_stake_nodes_laddr( qos->stake );
//   // for ( ulong i = 0; i < SLOT_CNT; i++ ) {
//   //   fd_stake_node_t * staked_node = fd_stake_node_insert( staked_nodes, pubkeys[i] );
//   //   FD_TEST( staked_node );
//   //   staked_node->stake = i;
//   // }
//   // for ( ulong i = 0; i < SLOT_CNT; i++ ) {
//   //   fd_stake_node_t * staked_node = fd_stake_node_query( staked_nodes, pubkeys[i], NULL );
//   //   FD_TEST( staked_node );
//   //   FD_TEST( staked_node->stake == i );
//   // }

//   // for ( ulong i = 0; i < fd_stake_node_slot_cnt( staked_nodes ); i++ ) {
//   //   fd_stake_node_t staked_node = staked_nodes[i];
//   //   if ( !fd_stake_node_key_inval( staked_node.key ) ) {
//   //     FD_LOG_HEXDUMP_NOTICE( ( "pubkey", &staked_node.key, sizeof( staked_node.key ) ) );
//   //   }
//   // }

//   // for ( ulong i = 0; i < NUM_PUBKEYS; i++ ) {
//   //   for ( ulong j = 0; j < fd_stake_node_slot_cnt( staked_nodes ); j++ ) {
//   //     // fd_stake_node_t staked_node = qos->staked_node_map[j];
//   //     // int rc = !( memcmp( staked_node.key.pubkey, pubkeys[i].pubkey, FD_TXN_PUBKEY_SZ ) );
//   //     // FD_LOG_NOTICE(("rc %d", rc));
//   //   }
//   //   fd_stake_node_t * staked_node =
//   //       fd_stake_node_query( staked_nodes, pubkeys[i], NULL );
//   //   FD_TEST( staked_node );
//   //   FD_TEST( staked_node->stake == i );
//   // }
// }

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  if ( FD_UNLIKELY( argc > 1 ) ) FD_LOG_ERR( ( "unrecognized argument: %s", argv[1] ) );

  ulong x = 0;
  FD_LOG_NOTICE(("x %p x + 4 %p", (void*) &x, (void *)(&x + 4)));


  // test_fd_quic_qos_conn_lru();

  FD_LOG_NOTICE( ( "pass" ) );
  fd_halt();
  return 0;
}