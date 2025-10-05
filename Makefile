# 컴파일러
CXX = g++
CXXFLAGS = -std=c++20 -O0 -Wall -g -I./include

# 라이브러리
LDFLAGS = -lcppkafka -lrdkafka++ -lrdkafka -lpthread

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
