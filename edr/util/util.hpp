#ifndef UITLHPP
#define UITLHPP

#include "hash/hash.hpp"
#include "queue/Queue.h"

#define FMT_UNICODE 0
#include <fmt/format.h>
#include "timestamp/timestamp.hpp"
#include <fmt/ranges.h>

#include <functional>
#include <string>
#include <iostream>
#include <stdexcept>
#include <memory>
#include <csignal>
#include <cerrno>
#include <cstring>   // strerror
#include <net/if.h>  // if_nametoindex
#include <ifaddrs.h>
#include <vector>
#include <thread> 
#include <tuple>
#include <unordered_map>
#include <cstdlib>
#include <chrono>    // C++11 chrono 라이브러리
#include <cstdint>   // uint64_t를 위해
#include <atomic>
#include <cstdlib>
#include <utility>
#include <fstream>
#include <sstream>

#include <linux/types.h>
#include <linux/errno.h>

#include "json.hpp" // Nlohmann
using json = nlohmann::json;

#include "ebpf/ebpf.hpp"
//#include "kafka/kafka.hpp"
#include "helper/helper.hpp"

#endif