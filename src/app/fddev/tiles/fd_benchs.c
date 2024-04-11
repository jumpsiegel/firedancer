#define _GNU_SOURCE
#include "../../fdctl/run/tiles/tiles.h"
#include "../../../waltz/xdp/fd_xsk_aio.h"
#include "../../../waltz/quic/fd_quic.h"
#include "../../../waltz/tls/test_tls_helper.h"

#include <linux/unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>


// TODO replace with config
#define quic_enabled 0

/* max number of buffers batched for receive */
#define IO_VEC_CNT 16


/* quic_conn_new is invoked by the QUIC engine whenever a new connection
   is being established. */
static void
quic_conn_new( fd_quic_conn_t * conn,
               void *           _ctx ) {
  (void)conn;
  (void)_ctx;
}


/* quic_stream_new is called back by the QUIC engine whenever an open
   connection creates a new stream, at the time this is called, both the
   client and server must have agreed to open the stream.  In case the
   client has opened this stream, it is assumed that the QUIC
   implementation has verified that the client has the necessary stream
   quota to do so. */

static void
quic_stream_new( fd_quic_stream_t * stream,
                 void *             _ctx,
                 int                type ) {
  /* we don't expect the server to initiate streams */
  (void)stream;
  (void)_ctx;
  (void)type;
}

/* quic_stream_receive is called back by the QUIC engine when any stream
   in any connection being serviced receives new data.  Currently we
   simply copy received data out of the xsk (network device memory) into
   a local dcache. */

static void
quic_stream_receive( fd_quic_stream_t * stream,
                     void *             stream_ctx,
                     uchar const *      data,
                     ulong              data_sz,
                     ulong              offset,
                     int                fin ) {
  /* we're not expecting to receive anything */
  (void)stream;
  (void)stream_ctx;
  (void)data;
  (void)data_sz;
  (void)offset;
  (void)fin;
}


static void
quic_stream_notify( fd_quic_stream_t * stream,
                    void *             stream_ctx,
                    int                type ) {
  (void)stream;
  (void)stream_ctx;
  (void)type;
  /* we do not retain stream pointers, so this is not necessary */
}


static void
conn_final( fd_quic_conn_t * conn,
            void *           context ) {
  (void)context;

  fd_quic_conn_t ** ppconn =
    (fd_quic_conn_t**)fd_quic_conn_get_context( conn );
  if( FD_LIKELY( ppconn ) ) {
    *ppconn = NULL;
  }
}


struct signer_ctx {
  fd_sha512_t sha512[ 1 ];

  uchar public_key[ 32UL ];
  uchar private_key[ 32UL ];
};
typedef struct signer_ctx signer_ctx_t;


static void
signer( void *        _ctx,
        uchar         signature[ static 64 ],
        uchar const   payload[ static 130 ] ) {
  fd_tls_test_sign_ctx_t * ctx = (fd_tls_test_sign_ctx_t *)_ctx;
  fd_ed25519_sign( signature, payload, 130UL, ctx->public_key, ctx->private_key, ctx->sha512 );
}

static FD_FN_UNUSED
signer_ctx_t
signer_ctx( fd_rng_t * rng ) {
  signer_ctx_t ctx[1];
  FD_TEST( fd_sha512_join( fd_sha512_new( ctx->sha512 ) ) );
  for( ulong b=0; b<32UL; b++ ) ctx->private_key[b] = fd_rng_uchar( rng );
  fd_ed25519_public_from_private( ctx->public_key, ctx->private_key, ctx->sha512 );

  return *ctx;
}

static int
quic_tx_aio_send( void *                    _ctx,
                  fd_aio_pkt_info_t const * batch,
                  ulong                     batch_cnt,
                  ulong *                   opt_batch_idx,
                  int                       flush );


/* quic_now is called by the QUIC engine to get the current timestamp in
   UNIX time.  */

static ulong
quic_now( void * ctx ) {
  (void)ctx;
  return (ulong)fd_log_wallclock();
}

typedef struct {
  ulong round_robin_cnt;
  ulong round_robin_id;

  ulong packet_cnt;

  ulong         conn_cnt;
  int           conn_fd[ 128UL ];
  struct pollfd poll_fd[ 128UL ];

  signer_ctx_t     signer_ctx;
  fd_quic_t *      quic;
  fd_quic_conn_t * quic_conn;
  const fd_aio_t * quic_rx_aio;
  ulong            no_stream;

  // vector receive members
  struct mmsghdr msgs[IO_VEC_CNT];
  struct iovec   iovecs[IO_VEC_CNT];
  char           rx_bufs[IO_VEC_CNT][2048];

  fd_wksp_t * mem;
} fd_benchs_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof( fd_benchs_ctx_t );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_benchs_ctx_t ), sizeof( fd_benchs_ctx_t ) );
  if( quic_enabled ) {
    fd_quic_limits_t quic_limits = {0};
    int    argc = 0;
    char * args[] = { NULL };
    char ** argv = args;
    fd_quic_limits_from_env( &argc, &argv, &quic_limits );
    //l = FD_LAYOUT_APPEND( l, fd_aio_align(),           fd_aio_footprint()           );
    ulong quic_fp = fd_quic_footprint( &quic_limits );
    l = FD_LAYOUT_APPEND( l, fd_quic_align(),          quic_fp );
    FD_LOG_WARNING(( "QUIC - footprint: %lu", quic_fp ));
  }
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_benchs_ctx_t ) );
}

static void
before_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             int *  opt_filter ) {
  (void)in_idx;
  (void)sig;

  fd_benchs_ctx_t * ctx = (fd_benchs_ctx_t *)_ctx;

  *opt_filter = fd_int_if( (seq%ctx->round_robin_cnt)!=ctx->round_robin_id,
                           1,
                           *opt_filter );
}

static inline void
during_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  (void)in_idx;
  (void)seq;
  (void)sig;
  (void)opt_filter;

  fd_benchs_ctx_t * ctx = (fd_benchs_ctx_t *)_ctx;

  if( !quic_enabled ) {

    if( FD_UNLIKELY( -1==send( ctx->conn_fd[ ctx->packet_cnt % ctx->conn_cnt ], fd_chunk_to_laddr( ctx->mem, chunk ), sz, 0 ) ) )
      FD_LOG_ERR(( "send() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    ctx->packet_cnt++;
  } else {

    if( FD_UNLIKELY( !ctx->quic_conn ) ) {
      /* try to connect */
      uint   dest_ip   = 0;
      ushort dest_port = 0;
      ctx->quic_conn = fd_quic_connect( ctx->quic, dest_ip, dest_port, "client" );

      /* failed? try later */
      if( FD_UNLIKELY( !ctx->quic_conn ) ) return;

      /* set the context to point to the location
         of the quic_conn pointer
         this allows the notification to NULL the value when
         a connection dies */
      fd_quic_conn_set_context( ctx->quic_conn, &ctx->quic_conn );
    }

    // TODO switch this logic
    // copy into a batch
    // when batch is full, send
    fd_quic_stream_t * stream = fd_quic_conn_new_stream( ctx->quic_conn, FD_QUIC_TYPE_UNIDIR );
    if( FD_UNLIKELY( !stream ) ) {
      ctx->no_stream++;
    } else {
      int fin = 1;
      fd_aio_pkt_info_t   batch[1]  = { { .buf    = fd_chunk_to_laddr( ctx->mem, chunk ),
                                          .buf_sz = (ushort)sz } };
      ulong               batch_cnt = 1;
      fd_quic_stream_send( stream, batch, batch_cnt, fin );
      ctx->packet_cnt++;
    }
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile,
                 void *           scratch ) {
  (void)topo;
  (void)tile;
  (void)scratch;

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_benchs_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_benchs_ctx_t ), sizeof( fd_benchs_ctx_t ) );

  if( quic_enabled ) {
    fd_quic_limits_t quic_limits = {0};
    int    argc = 0;
    char * args[] = { NULL };
    char ** argv = args;
    fd_quic_limits_from_env( &argc, &argv, &quic_limits );
    ulong quic_fp = fd_quic_footprint( &quic_limits );
    FD_LOG_WARNING(( "QUIC - footprint: %lu", quic_fp ));
    void * quic_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_quic_align(), quic_fp );
    fd_quic_t * quic = fd_quic_join( fd_quic_new( quic_mem, &quic_limits ) );

    /* Signer */
    uint     seed = 4242424242;
    fd_rng_t _rng[1];
    fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
    ctx->signer_ctx = signer_ctx( rng );

    quic->config.sign_ctx = &ctx->signer_ctx;
    quic->config.sign     = signer;

    fd_memcpy( quic->config.identity_public_key, ctx->signer_ctx.public_key, 32UL );

    /* store the pointer to quic and quic_rx_aio for later use */
    ctx->quic        = quic;
    ctx->quic_rx_aio = fd_quic_get_aio_net_rx( quic );

    /* call wallclock so glibc loads VDSO, which requires calling mmap while
       privileged */
    fd_log_wallclock();
  }

  ushort port = 12000;

  ctx->conn_cnt = fd_topo_tile_name_cnt( topo, "quic" );
  if( quic_enabled ) ctx->conn_cnt = 1;
  FD_TEST( ctx->conn_cnt <=sizeof(ctx->conn_fd)/sizeof(*ctx->conn_fd) );
  for( ulong i=0UL; i<ctx->conn_cnt ; i++ ) {
    int conn_fd = socket( AF_INET, SOCK_DGRAM, 0 );
    if( FD_UNLIKELY( -1==conn_fd ) ) FD_LOG_ERR(( "socket() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    ushort found_port = 0;
    for( ulong j=0UL; j<10UL; j++ ) {
      struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = fd_ushort_bswap( port ),
        .sin_addr.s_addr = fd_uint_bswap( INADDR_ANY ),
      };
      if( FD_UNLIKELY( -1!=bind( conn_fd, fd_type_pun( &addr ), sizeof(addr) ) ) ) {
        found_port = port;
        break;
      }
      if( FD_UNLIKELY( EADDRINUSE!=errno ) ) FD_LOG_ERR(( "bind() failed (%i-%s)", errno, fd_io_strerror( errno ) ) );
      port = (ushort)(port + ctx->conn_cnt); /* Make sure it round robins to the same tile index */
    }
    if( FD_UNLIKELY( !found_port ) ) FD_LOG_ERR(( "bind() failed to find a src port" ));

    struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = fd_ushort_bswap( tile->benchs.send_to_port ),
      .sin_addr.s_addr = tile->benchs.send_to_ip_addr,
    };
    if( FD_UNLIKELY( -1==connect( conn_fd, fd_type_pun( &addr ), sizeof(addr) ) ) ) FD_LOG_ERR(( "connect() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    ctx->conn_fd[ i ]      = conn_fd;
    if( quic_enabled ) {
      ctx->poll_fd[i].fd     = conn_fd;
      ctx->poll_fd[i].events = POLLIN;
    }
    port++;
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_benchs_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_benchs_ctx_t ), sizeof( fd_benchs_ctx_t ) );

  ctx->packet_cnt = 0UL;

  ctx->round_robin_id = tile->kind_id;
  ctx->round_robin_cnt = fd_topo_tile_name_cnt( topo, "benchs" );

  ctx->mem = topo->workspaces[ topo->objs[ topo->links[ tile->in_link_id[ 0UL ] ].dcache_obj_id ].wksp_id ].wksp;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  fd_quic_t * quic = ctx->quic;
  if( quic ) {
    fd_aio_t * quic_tx_aio = fd_aio_join( fd_aio_new( FD_SCRATCH_ALLOC_APPEND( l, fd_aio_align(), fd_aio_footprint() ), ctx, quic_tx_aio_send ) );

    if( FD_UNLIKELY( !quic_tx_aio ) ) FD_LOG_ERR(( "fd_aio_join failed" ));

    uint  quic_ip_addr             = 0;     /* TODO fetch the quic destination ip addr */
    ulong quic_idle_timeout_millis = 100;   /* idle timeout in milliseconds */
    uchar quic_src_mac_addr[6]     = {0};   /* source MAC address */
    quic->config.role                       = FD_QUIC_ROLE_CLIENT;
    quic->config.net.ip_addr                = quic_ip_addr;
    quic->config.net.listen_udp_port        = 42424; /* should be unused */
    quic->config.idle_timeout               = quic_idle_timeout_millis * 1000000UL;
    quic->config.initial_rx_max_stream_data = 1<<15;
    quic->config.retry                      = 0; /* unused on clients */
    fd_memcpy( quic->config.link.src_mac_addr, quic_src_mac_addr, 6 );

    quic->cb.conn_new         = quic_conn_new;
    quic->cb.conn_hs_complete = NULL;
    quic->cb.conn_final       = conn_final;
    quic->cb.stream_new       = quic_stream_new;
    quic->cb.stream_receive   = quic_stream_receive;
    quic->cb.stream_notify    = quic_stream_notify;
    quic->cb.now              = quic_now;
    quic->cb.now_ctx          = NULL;
    quic->cb.quic_ctx         = ctx;

    fd_quic_set_aio_net_tx( quic, quic_tx_aio );
    if( FD_UNLIKELY( !fd_quic_init( quic ) ) ) FD_LOG_ERR(( "fd_quic_init failed" ));

    for( ulong i = 0; i < IO_VEC_CNT; i++ ) {
      ctx->iovecs[i].iov_base         = ctx->rx_bufs[i];
      ctx->iovecs[i].iov_len          = sizeof(ctx->rx_bufs[i]);
      ctx->msgs[i].msg_hdr.msg_iov    = &ctx->iovecs[i];
      ctx->msgs[i].msg_hdr.msg_iovlen = 1;
    }
  }

}

static int
quic_tx_aio_send( void *                    _ctx,
                  fd_aio_pkt_info_t const * batch,
                  ulong                     batch_cnt,
                  ulong *                   opt_batch_idx,
                  int                       flush ) {
  (void)_ctx;
  (void)batch;
  (void)batch_cnt;
  (void)opt_batch_idx;
  (void)flush;

  fd_benchs_ctx_t * ctx = (fd_benchs_ctx_t *)_ctx;

  if( FD_LIKELY( quic_enabled ) ) {
    // TODO consider using sendmmsg batches
    for( ulong j = 0UL; j < batch_cnt; ++j ) {
      if( FD_UNLIKELY( send( ctx->conn_fd[ ctx->packet_cnt % ctx->conn_cnt ],
                             batch[j].buf,
                             batch[j].buf_sz,
                             0 ) ) == -1 ) {
        FD_LOG_ERR(( "send failed with error: %d %s", errno, strerror( errno ) ));
      }
    }
  }

  return 0;
}

static void
before_credit( void * _ctx,
               fd_mux_context_t * mux ) {
  (void)mux;

  fd_benchs_ctx_t * ctx = (fd_benchs_ctx_t*)_ctx;

  if( quic_enabled ) {
    /* Publishes to mcache via callbacks */
    fd_quic_service( ctx->quic );

    /* receive from socket, and pass to quic */
    int poll_rc = poll( ctx->poll_fd, ctx->conn_cnt, 0 );
    if( FD_UNLIKELY( poll_rc == -1 ) ) {
      if( FD_UNLIKELY( errno == EINTR ) ) return; // will try later
      FD_LOG_ERR(( "Error occurred during poll: %d %s", errno,
            strerror( errno ) ));
    }

    for( ulong j = 0; j < ctx->conn_cnt; ++j ) {
      int revents = ctx->poll_fd[j].revents;
      if( FD_LIKELY( revents & POLLIN ) ) {
        /* data available - receive up to IO_VEC_CNT buffers */
        int retval = recvmmsg( ctx->poll_fd[j].fd, ctx->msgs, IO_VEC_CNT, 0, NULL );
        if( FD_UNLIKELY( retval < 0 ) ) {
          FD_LOG_ERR(( "Error occurred on recvmmsg: %d %s", errno, strerror( errno ) ));
        } else {
          /* pass buffers to QUIC */
          fd_aio_pkt_info_t pkt[IO_VEC_CNT];
          for( ulong j = 0; j < (ulong)retval; ++j ) {
            pkt[j].buf    = ctx->rx_bufs[j];
            pkt[j].buf_sz = (ushort)ctx->msgs[j].msg_len;
          }
          fd_aio_send( ctx->quic_rx_aio, pkt, (ulong)retval, NULL, 1 );
        }
      } else if( FD_UNLIKELY( revents & POLLERR ) ) {
        int error = 0;
        socklen_t errlen = sizeof(error);

        if( getsockopt( ctx->poll_fd[j].fd, SOL_SOCKET, SO_ERROR, (void *)&error, &errlen ) == -1 ) {
          FD_LOG_ERR(( "Unknown error on socket" ));
        } else {
          FD_LOG_ERR(( "Error on socket: %d %s", error, strerror( error ) ));
        }
      }
    }
  }
}

fd_topo_run_tile_t fd_tile_benchs = {
  .name                     = "benchs",
  .mux_flags                = FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
  .burst                    = 1UL,
  .mux_ctx                  = mux_ctx,
  .mux_before_credit        = before_credit,
  .mux_before_frag          = before_frag,
  .mux_during_frag          = during_frag,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
};
