#include "fd_flamenco.h"

<<<<<<< HEAD
=======
#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

>>>>>>> main
int
main( int     argc,
      char ** argv ) {
  fd_boot         ( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  static const uchar buf32[ 32UL ] =
      { 0xad,0x23,0x76,0x6d,0xde,0xe6,0xe9,0x9c,0xa3,0x34,0x0e,0xe5,0xbe,0xac,0x08,0x84,
        0xc8,0x9d,0xdb,0xc7,0x4d,0xfe,0x24,0x8f,0xea,0x56,0x13,0x56,0x98,0xba,0xfd,0xd1 };
  static const uchar buf64[ 64UL ] =
      { 0xe8,0x52,0xe3,0x69,0x0d,0xa0,0xeb,0xf5,0xb4,0x66,0xed,0x0c,0x89,0x6b,0x2c,0x8f,
        0xea,0xe6,0x0e,0x3b,0x23,0xc0,0x37,0xfc,0xdd,0x68,0xbf,0xc2,0xe4,0x60,0x7b,0x47,
        0xb9,0x79,0x02,0x2e,0x4c,0xf6,0x2a,0x04,0x26,0x4e,0xef,0x55,0x94,0x0e,0xc8,0x57,
        0xb3,0x46,0xf1,0xa4,0x11,0x5b,0xaa,0x1a,0xc8,0x3d,0x3b,0x05,0xca,0xa8,0x23,0x00 };

  static const char format[] = "%32J %64J %3J %J %32J ...";
  static const char expected[] =
      "Certusm1sa411sMpV9FPqU5dXAYhmmhygvxJ23S6hJ24 "
      "5eQS44iKV8B4b4gTt4tPZLPSHtD7F78fFDhbHDknsrAE1vUipnDf3pK6h5eZ8CqWqFgZPoYY6XHKUuvyt7BLWHpb "
      "<unsupported Base58 width> "
      "<unsupported Base58 width> "
      "<NULL> "
      "...";

  ulong len;
  char buf[ 256UL ];
  fd_cstr_printf( buf, 256UL, &len, format, buf32, buf64, buf32, buf32, NULL );
  FD_TEST( 0==strcmp( buf, expected ) );
  FD_TEST( len==strlen( expected ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_flamenco_halt();
  fd_halt();
  return 0;
}
