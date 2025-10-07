CC = clang
CFLAGS = -O2 -g -Wall -target bpf
LIBBPF_CFLAGS := -I.  # events.h 포함

# eBPF 소스 파일
BPF_SRCS := ProcessCreation/processcreation.bpf.c \
            Network/network.bpf.c 

# 출력 오브젝트 파일
BPF_OBJS := $(BPF_SRCS:.c=.o)
BPF_SKELS := $(BPF_SRCS:.c=.skel.h)

# all: .o + .skel.h 빌드
all: $(BPF_OBJS) $(BPF_SKELS)

# .c → .o
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ $(LIBBPF_CFLAGS)

# .o → .skel.h
%.skel.h: %.o
	bpftool gen skeleton $< > $@

# clean
clean:
	rm -f $(BPF_OBJS) $(BPF_SKELS)
