BUILDDIR:=linux/gcc/x86_64

include config/base.mk
include config/with-linux.mk
include config/with-gcc.mk
include config/with-debug.mk
include config/with-brutality.mk
include config/with-optimization.mk
include config/with-threads.mk
include config/with-openssl.mk

CPPFLAGS+=-fomit-frame-pointer -falign-functions=32 -falign-jumps=32 -falign-labels=32 -falign-loops=32 \
          -march=haswell -mtune=skylake -mfpmath=sse -mbranch-cost=5 \
	  -DFD_HAS_INT128=1 -DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1 -DFD_HAS_X86=1 -DFD_HAS_SSE=1 -DFD_HAS_AVX=1

FD_HAS_INT128:=1
FD_HAS_DOUBLE:=1
FD_HAS_ALLOCA:=1
FD_HAS_X86:=1
FD_HAS_SSE:=1
FD_HAS_AVX:=1

# AWS-F1
INCLUDES += -I$(SDK_DIR)/userspace/include
INCLUDES += -I$(SDK_DIR)/userspace/fpga_libs/fpga_mgmt/
INCLUDES += -I $(HDK_DIR)/common/software/include
CPPFLAGS+= -mavx2 -DCONFIG_LOGLEVEL=4 $(INCLUDES)
CPPFLAGS+= -DFD_HAS_WIREDANCER=1
LDFLAGS += -L /usr/local/lib64 -lfpga_mgmt