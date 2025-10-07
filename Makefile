# Makefile for PacketSniffer project

CXX := g++
CXXFLAGS := -g -O0 -Wall -std=c++20

# pkg-config로 PcapPlusPlus flags 가져오기

# Libbpf
LIBS := -lbpf -lelf -lz -lrdkafka -lfmt -lcrypto -lssl

# 소스 파일
SRCS := main.cpp
OBJS := $(SRCS:.cpp=.o)

# 실행 파일 이름
TARGET := AGENT

# 기본 빌드
all: $(TARGET)

# 링커
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $@ $(LIBS)

# 객체 파일 생성
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# 클린
clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
