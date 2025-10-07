#ifndef LGGSENDER_HPP
#define LGGSENDER_HPP

#include "../../util/util.hpp"

std::string ProtocolToString(int protocol);

namespace EDR
{
    namespace Agent
    {
        namespace Event
        {
            class LogSender
            {
                public:
                    LogSender(
                        std::string broker_ip, 
                        __u32 broker_port, 
                        std::string topic,

                        std::string AGENT_ID, 
                        std::string OS_VERSION 
                    ):
                    AGENT_ID(AGENT_ID), 
                    OS_VERSION(OS_VERSION), 
                    kafka(broker_ip, broker_port, topic)
                    {
                        // kafka
                        if( !this->kafka.Initialize() )
                            throw std::runtime_error("[LogSender]{Failed} Run -> kafka.Initialize() Failed");

                        std::cout << "[LogSender]{Notice} Run -> kafka.Initialize() Success" << std::endl;
                    }

                    ~LogSender() = default;

                    void Send_ProcessCreate(
                        __u64 pid, 
                        __u64 timestamp, 
                        std::string RootProcessSessionId, 
                        std::string ParentProcessSessionId, 
                        std::string ProcessSessionId, 
                        __u64 ppid, 
                        __u32 uid, 
                        __u32 gid, 

                        std::string self_exe_file_path, 
                        __u64 self_exe_file_size,
                        std::string self_exe_file_sha256,

                        std::string parent_exe_file_path, 
                        __u64 parent_exe_file_size,
                        std::string parent_exe_file_sha256,

                        std::string commandline
                    )
                    {
                        kafka.InsertMessage(
                            {
                                {
                                    "header", {
                                        {"agentid", AGENT_ID},
                                        {"root_sessionid", RootProcessSessionId},
                                        {"parent_sessionid", ParentProcessSessionId},
                                        {"sessionid", ProcessSessionId},
                                        {
                                            "os", {
                                                {"version", OS_VERSION},
                                                {"type", "Linux"}
                                            }
                                        },
                                        {"pid", pid},
                                        {"nano_timestamp", timestamp}
                                    }
                                },
                                {
                                    "body", {
                                        {
                                            "user", {
                                                {"username", EDR::Util::Helper::UIDGID::uid_to_name(uid)},
                                                {"groupname", EDR::Util::Helper::UIDGID::gid_to_name(gid)}
                                            },
                                            
                                        },
                                        {
                                            "process", {
                                                {"action", "create"},
                                                {"exe_path", self_exe_file_path},
                                                {"exe_size", self_exe_file_size},
                                                {"exe_sha256", self_exe_file_sha256},
                                                {"commandline", commandline },

                                                {"ppid" , ppid },
                                                {"parent_exe_path", parent_exe_file_path},
                                                {"parent_exe_size", parent_exe_file_size },
                                                {"parent_exe_sha256", parent_exe_file_sha256 }
                                            }
                                        }
                                    }
                                }
                            }
                        );
                    }
                    void Send_ProcessRemove(__u64 pid,__u64 timestamp, std::string RootProcessSessionId, std::string ParentProcessSessionId, std::string ProcessSessionId )
                    {
                        kafka.InsertMessage(
                            {
                                {
                                    "header", {
                                        {"agentid", AGENT_ID},
                                        {"root_sessionid", RootProcessSessionId},
                                        {"parent_sessionid", ParentProcessSessionId},
                                        {"sessionid", ProcessSessionId},
                                        {
                                            "os", {
                                                {"version", OS_VERSION},
                                                {"type", "Linux"}
                                            }
                                        },
                                        {"pid", pid},
                                        {"nano_timestamp", timestamp}
                                    }
                                },
                                {
                                    "body", {
                                        {
                                            "process", {
                                                {"action", "remove"}
                                            }
                                        }
                                    }
                                }
                            }
                        );
                    }
                    void Send_Network(
                        __u64 pid,
                        __u64 timestamp, 
                        std::string RootProcessSessionId, 
                        std::string ParentProcessSessionId, 
                        std::string ProcessSessionId,
                        __u32 ifindex,
                        __u32 protocol,
                        __u32 pkt_len,
                        std::string ipSrc,
                        __u32 portSrc,
                        std::string ipDst,
                        __u32 portDst,
                        bool is_INGRESS,

                        std::string NetworkSessioninfo_SessionID,
                        __u64 NetworkSessioninfo_first_seen_nanotimestamp,
                        __u64 NetworkSessioninfo_last_seen_nanotimestamp

                    )
                    {
                        kafka.InsertMessage(
                            {
                                {
                                    "header", {
                                        {"agentid", AGENT_ID},
                                        {"root_sessionid", RootProcessSessionId},
                                        {"parent_sessionid", ParentProcessSessionId},
                                        {"sessionid", ProcessSessionId},
                                        {
                                            "os", {
                                                {"version", OS_VERSION},
                                                {"type", "Linux"}
                                            }
                                        },
                                        {"pid", pid},
                                        {"nano_timestamp", timestamp}
                                    }
                                },
                                {
                                    "body", {
                                        {
                                            "network", {
                                                {"interface_index", ifindex},
                                                {"protocol", ProtocolToString(protocol)},
                                                {"packetsize", pkt_len},
                                                {"sourceip", ipSrc},
                                                {"sourceport", portSrc },

                                                {"destinationip" , ipDst },
                                                {"destinationport", portDst},
                                                {"direction", ( is_INGRESS ? "in" : "out" ) },
                                                {
                                                    "session" , {
                                                        {"sessionid", NetworkSessioninfo_SessionID},
                                                        {"first_seen", NetworkSessioninfo_first_seen_nanotimestamp},
                                                        {"last_seen", NetworkSessioninfo_last_seen_nanotimestamp}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        );
                    }

                private:
                    std::string AGENT_ID;
                    std::string OS_VERSION;
                    EDR::Util::Kafka::Kafka kafka;
            };
        }
    }
}

std::string ProtocolToString(int protocol) {
                switch(protocol) {
                    case 0:   return "hopopt";
                    case 1:   return "icmp";
                    case 2:   return "igmp";
                    case 3:   return "ggp";
                    case 4:   return "ipv4";
                    case 5:   return "st";
                    case 6:   return "tcp";
                    case 7:   return "cbt";
                    case 8:   return "egp";
                    case 9:   return "igp";
                    case 10:  return "bbn-rcc-mon";
                    case 11:  return "nvp-ii";
                    case 12:  return "pup";
                    case 13:  return "argus";
                    case 14:  return "emcon";
                    case 15:  return "xnet";
                    case 16:  return "chaos";
                    case 17:  return "udp";
                    case 18:  return "mux";
                    case 19:  return "dcn-meas";
                    case 20:  return "hmp";
                    case 21:  return "prm";
                    case 22:  return "xns-idp";
                    case 23:  return "trunk-1";
                    case 24:  return "trunk-2";
                    case 25:  return "leaf-1";
                    case 26:  return "leaf-2";
                    case 27:  return "rdp";
                    case 28:  return "irtp";
                    case 29:  return "iso-tp4";
                    case 30:  return "netblt";
                    case 31:  return "mfe-nsp";
                    case 32:  return "merit-inp";
                    case 33:  return "dccp";
                    case 34:  return "3pc";
                    case 35:  return "idpr";
                    case 36:  return "xtp";
                    case 37:  return "ddp";
                    case 38:  return "idpr-cmtp";
                    case 39:  return "tp++";
                    case 40:  return "il";
                    case 41:  return "ipv6";
                    case 42:  return "sdrp";
                    case 43:  return "ipv6-route";
                    case 44:  return "ipv6-frag";
                    case 45:  return "idrp";
                    case 46:  return "rsvp";
                    case 47:  return "gre";
                    case 48:  return "dsn";
                    case 49:  return "iatp";
                    case 50:  return "stp";
                    case 51:  return "srp";
                    case 52:  return "uti";
                    case 53:  return "swipe";
                    case 54:  return "narp";
                    case 55:  return "mobile";
                    case 56:  return "ipv6";
                    case 57:  return "cftp";
                    case 58:  return "cal";
                    case 59:  return "mtp";
                    case 60:  return "ax.25";
                    case 61:  return "os";
                    case 62:  return "micp";
                    case 63:  return "scc-sp";
                    case 64:  return "etherip";
                    case 65:  return "encap";
                    case 66:  return "private";
                    case 67:  return "gmtp";
                    case 68:  return "ifmp";
                    case 69:  return "pnni";
                    case 70:  return "pim";
                    case 71:  return "aris";
                    case 72:  return "scps";
                    case 73:  return "qnx";
                    case 74:  return "a/n";
                    case 75:  return "ipcomp";
                    case 76:  return "snp";
                    case 77:  return "compaq-peer";
                    case 78:  return "ipx-in-ip";
                    case 79:  return "vrrp";
                    case 80:  return "pgm";
                    case 81:  return "any";
                    case 82:  return "l2tp";
                    case 83:  return "ddx";
                    case 84:  return "iatp";
                    case 85:  return "stp";
                    case 86:  return "srp";
                    case 87:  return "uti";
                    case 88:  return "swipe";
                    case 89:  return "narp";
                    case 90:  return "mobile";
                    case 91:  return "ipv6";
                    case 92:  return "cftp";
                    case 93:  return "cal";
                    case 94:  return "mtp";
                    case 95:  return "ax.25";
                    case 96:  return "os";
                    case 97:  return "micp";
                    case 98:  return "scc-sp";
                    case 99:  return "etherip";
                    case 100: return "encap";
                    case 101: return "private";
                    case 102: return "gmtp";
                    case 103: return "ifmp";
                    case 104: return "pnni";
                    case 105: return "pim";
                    case 106: return "aris";
                    case 107: return "scps";
                    case 108: return "qnx";
                    case 109: return "a/n";
                    case 110: return "ipcomp";
                    case 111: return "snp";
                    case 112: return "compaq-peer";
                    case 113: return "ipx-in-ip";
                    case 114: return "vrrp";
                    case 115: return "pgm";
                    case 116: return "any";
                    case 117: return "l2tp";
                    case 118: return "ddx";
                    case 119: return "iatp";
                    case 255: return "reserved";
                    default:  return "unknown";
                }
            }

#endif