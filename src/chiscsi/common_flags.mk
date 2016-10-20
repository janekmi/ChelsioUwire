#Build flags common to base/t3/t4

ifneq ($(shell $(grep) -c 'peeked:1,' $(KINC)/linux/skbuff.h),0)
  FLAGS += -D__SKB_HAS_PEEKED__
  $(warning SGL DMA enabled.)
else
  $(warning SGL DMA disabled.)
endif

ifeq ($(test_premap),1)
  FLAGS += -D__TEST_PREMAPPED_SKB__
endif

ifneq ($(shell $(grep) -c 'KMALLOC_MAX_SIZE' $(KINC)/linux/slab.h),0)
  FLAGS += -DHAS_KMALLOC_MAX_SIZE
endif

ifneq ($(shell $(grep) -c \
         '^\#define[[:space:]]\+CONFIG_\(IPV6\|IPV6_MODULE\)[[:space:]]\+1' \
			         $(KINC)/generated/autoconf.h),0)
 FLAGS += -DCHISCSI_IPV6_SUPPORT
endif

