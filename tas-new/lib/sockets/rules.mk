include mk/subdir_pre.mk

LIB_SOCKETS_OBJS = $(addprefix $(d)/, \
  control.o transfer.o context.o manage_fd.o epoll.o poll.o libc.o)
LIB_SOCKETS_SOBJS := $(LIB_SOCKETS_OBJS:.o=.shared.o)

LIB_SINT_OBJS = $(addprefix $(d)/,interpose.o)
LIB_SINT_SOBJS := $(LIB_SINT_OBJS:.o=.shared.o)

LIB_ZIO_OBJS = $(addprefix $(d)/,zio_interpose.o)
LIB_ZIO_SOBJS := $(LIB_ZIO_OBJS:.o=.shared.o)


allobjs := $(LIB_SOCKETS_OBJS) $(LIB_SOCKETS_SOBJS) $(LIB_SINT_OBJS) \
  $(LIB_SINT_SOBJS) $(LIB_ZIO_OBJS) $(LIB_ZIO_SOBJS)

LIB_SOCKETS_CPPFLAGS := -I$(d)/include/ -Ilib/tas/include

$(LIB_SOCKETS_OBJS): CPPFLAGS += $(LIB_SOCKETS_CPPFLAGS)
$(LIB_SOCKETS_SOBJS): CPPFLAGS += $(LIB_SOCKETS_CPPFLAGS)
$(LIB_SINT_OBJS): CPPFLAGS += $(LIB_SOCKETS_CPPFLAGS)
$(LIB_SINT_SOBJS): CPPFLAGS += $(LIB_SOCKETS_CPPFLAGS)
$(LIB_ZIO_OBJS): CPPFLAGS += $(LIB_SOCKETS_CPPFLAGS)
$(LIB_ZIO_SOBJS): CPPFLAGS += $(LIB_SOCKETS_CPPFLAGS)

lib/libtas_sockets.so: $(LIB_SOCKETS_SOBJS) $(LIB_TAS_SOBJS) \
  $(LIB_UTILS_SOBJS)

lib/libtas_interpose.so: $(LIB_SINT_SOBJS) $(LIB_SOCKETS_SOBJS) \
  $(LIB_TAS_SOBJS) $(LIB_UTILS_SOBJS)

lib/zio_interpose.so: $(LIB_ZIO_SOBJS) $(LIB_SOCKETS_SOBJS) \
  $(LIB_TAS_SOBJS) $(LIB_UTILS_SOBJS)

DEPS += $(allobjs:.o=.d)
CLEAN += $(allobjs) lib/libtas_sockets.so lib/libtas_interpose.so
TARGETS += lib/libtas_sockets.so lib/libtas_interpose.so lib/zio_interpose.so

include mk/subdir_post.mk
