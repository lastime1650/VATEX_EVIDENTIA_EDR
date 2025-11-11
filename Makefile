# 컴파일러
CXX = g++
CXXFLAGS = -std=c++20 -O0 -Wall -g -I./include

# LD_LIBRARY_PATH=/usr/local/lib64:$LD_LIBRARY_PATH ./EDR

# LD_LIBRARY_PATH=/usr/local/lib64:$LD_LIBRARY_PATH gdb ./EDR
# set print thread-events off


# 라이브러리
LDFLAGS = -lcppkafka -lrdkafka++ -lrdkafka -lpthread -lsqlite3 -lfmt

# 소스, 오브젝트, 실행파일
SRCS = main.cpp
OBJS = $(SRCS:.cpp=.o)
TARGET = EDR

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
