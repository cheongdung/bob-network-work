#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <pcap.h>
#include <string>

using Mac = std::array<uint8_t, 6>;

struct ApInfo {
    int power = 0;
    bool hasPower = false;
    int beacons = 0;
    int data = 0;
    int channel = 0;
    std::string enc = "OPN";
    std::string essid = "<hidden>";
};

struct RadiotapInfo {
    uint16_t length = 0;
    int power = 0;
    bool hasPower = false;
    int channel = 0;
};

using ApMap = std::map<Mac, ApInfo>;

void usage() {
    std::printf("syntax: airodump <interface>\n");
    std::printf("sample: airodump wlan0\n");
}

uint16_t readLe16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) |
           (static_cast<uint16_t>(p[1]) << 8);
}

uint32_t readLe32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

size_t alignOffset(size_t offset, size_t alignment) {
    return (offset + alignment - 1) & ~(alignment - 1);
}

int frequencyToChannel(uint16_t frequency) {
    if (frequency == 2484)
        return 14;
    if (frequency >= 2412 && frequency <= 2472)
        return (frequency - 2407) / 5;
    if (frequency >= 5000 && frequency <= 5900)
        return (frequency - 5000) / 5;
    return 0;
}

// Radiotap에서 길이, 신호 세기, 채널을 구함
bool parseRadiotap(const uint8_t* packet, size_t caplen,
                   RadiotapInfo& info) {
    if (caplen < 8 || packet[0] != 0)
        return false;

    info.length = readLe16(packet + 2);
    if (info.length < 8 || info.length > caplen)
        return false;

    uint32_t firstPresent = readLe32(packet + 4);
    uint32_t present = firstPresent;
    size_t offset = 8;

    // extended present bitmap을 모두 건너뜀
    while ((present & 0x80000000U) != 0) {
        if (offset + 4 > info.length)
            return false;
        present = readLe32(packet + offset);
        offset += 4;
    }

    // signal field까지 필요한 Radiotap 필드 정보
    const size_t alignment[6] = {8, 1, 1, 2, 2, 1};
    const size_t size[6] = {8, 1, 1, 4, 2, 1};

    for (int field = 0; field <= 5; field++) {
        if ((firstPresent & (1U << field)) == 0)
            continue;

        offset = alignOffset(offset, alignment[field]);
        if (offset + size[field] > info.length)
            return false;

        // Channel field
        if (field == 3) {
            uint16_t frequency = readLe16(packet + offset);
            info.channel = frequencyToChannel(frequency);
        }

        // dBm Antenna Signal field
        if (field == 5) {
            int8_t power;
            std::memcpy(&power, packet + offset, sizeof(power));
            info.power = power;
            info.hasPower = true;
        }
        offset += size[field];
    }
    return true;
}

Mac readMac(const uint8_t* p) {
    return {{p[0], p[1], p[2], p[3], p[4], p[5]}};
}

std::string macToString(const Mac& mac) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                  static_cast<unsigned>(mac[0]),
                  static_cast<unsigned>(mac[1]),
                  static_cast<unsigned>(mac[2]),
                  static_cast<unsigned>(mac[3]),
                  static_cast<unsigned>(mac[4]),
                  static_cast<unsigned>(mac[5]));
    return buf;
}

std::string makeEssid(const uint8_t* data, size_t length) {
    if (length == 0)
        return "<hidden>";

    std::string result;
    length = std::min<size_t>(length, 32);
    for (size_t i = 0; i < length; i++) {
        unsigned char ch = data[i];
        result += std::isprint(ch) ? static_cast<char>(ch) : '.';
    }
    return result;
}

// Beacon frame의 BSSID, ESSID, ENC, Channel을 저장
bool processBeacon(const uint8_t* packet, size_t caplen,
                   size_t dot11Offset, const RadiotapInfo& radio,
                   ApMap& aps) {
    const size_t dot11HeaderLength = 24;
    const size_t fixedParameterLength = 12;
    const size_t minimumLength = dot11Offset + dot11HeaderLength +
                                 fixedParameterLength;
    if (caplen < minimumLength)
        return false;

    const uint8_t* dot11 = packet + dot11Offset;
    Mac bssid = readMac(dot11 + 16); // addr3가 BSSID

    const uint8_t* fixed = dot11 + dot11HeaderLength;
    uint16_t capability = readLe16(fixed + 10);
    bool privacy = (capability & 0x0010) != 0;
    bool hasRsn = false;
    bool hasWpa = false;
    int channel = radio.channel;
    std::string essid = "<hidden>";

    // Tagged Parameters 순회
    size_t offset = minimumLength;
    while (offset + 2 <= caplen) {
        uint8_t tagNumber = packet[offset];
        uint8_t tagLength = packet[offset + 1];
        offset += 2;

        if (offset + tagLength > caplen)
            break;

        const uint8_t* tagData = packet + offset;
        if (tagNumber == 0) {
            essid = makeEssid(tagData, tagLength);
        } else if (tagNumber == 3 && tagLength >= 1) {
            channel = tagData[0];
        } else if (tagNumber == 48) {
            hasRsn = true;
        } else if (tagNumber == 221 && tagLength >= 4 &&
                   tagData[0] == 0x00 && tagData[1] == 0x50 &&
                   tagData[2] == 0xF2 && tagData[3] == 0x01) {
            hasWpa = true;
        }
        offset += tagLength;
    }

    ApInfo& ap = aps[bssid];
    ap.beacons++;
    ap.essid = essid;
    ap.channel = channel;
    if (radio.hasPower) {
        ap.power = radio.power;
        ap.hasPower = true;
    }

    if (!privacy)
        ap.enc = "OPN";
    else if (hasRsn)
        ap.enc = "WPA2";
    else if (hasWpa)
        ap.enc = "WPA";
    else
        ap.enc = "WEP";

    return true;
}

// Data frame에서 BSSID를 구하고 #Data 증가
void processData(const uint8_t* dot11, size_t length,
                 uint16_t frameControl, ApMap& aps) {
    if (length < 24)
        return;

    bool toDs = (frameControl & 0x0100) != 0;
    bool fromDs = (frameControl & 0x0200) != 0;
    Mac bssid;

    if (!toDs && !fromDs)
        bssid = readMac(dot11 + 16); // addr3
    else if (toDs && !fromDs)
        bssid = readMac(dot11 + 4);  // addr1
    else if (!toDs && fromDs)
        bssid = readMac(dot11 + 10); // addr2
    else
        return; // WDS frame은 제외

    auto it = aps.find(bssid);
    if (it != aps.end())
        it->second.data++;
}

void printAps(const ApMap& aps) {
    std::cout << "\033[2J\033[H";
    std::cout << std::left << std::setw(18) << "BSSID"
              << std::right << std::setw(6) << "PWR"
              << std::setw(10) << "Beacons"
              << std::setw(8) << "#Data"
              << std::setw(5) << "CH"
              << "  " << std::left << std::setw(6) << "ENC"
              << "ESSID\n";

    for (const auto& item : aps) {
        const ApInfo& ap = item.second;
        std::cout << std::left << std::setw(18) << macToString(item.first)
                  << std::right << std::setw(6);
        if (ap.hasPower)
            std::cout << ap.power;
        else
            std::cout << "-";

        std::cout << std::setw(10) << ap.beacons
                  << std::setw(8) << ap.data
                  << std::setw(5) << ap.channel
                  << "  " << std::left << std::setw(6) << ap.enc
                  << ap.essid << '\n';
    }
    std::cout.flush();
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return EXIT_FAILURE;
    }

    char errbuf[PCAP_ERRBUF_SIZE]{};
    pcap_t* pcap = pcap_open_live(argv[1], 65535, 1, 1000, errbuf);
    if (pcap == nullptr) {
        std::fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    // monitor mode에서 Radiotap header가 전달되는지 확인
    if (pcap_datalink(pcap) != DLT_IEEE802_11_RADIO) {
        std::fprintf(stderr, "monitor mode interface is required\n");
        pcap_close(pcap);
        return EXIT_FAILURE;
    }

    ApMap aps;
    auto lastPrint = std::chrono::steady_clock::now();

    while (true) {
        pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);

        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            std::fprintf(stderr, "pcap_next_ex: %s\n", pcap_geterr(pcap));
            break;
        }

        if (res == 1) {
            RadiotapInfo radio;
            if (parseRadiotap(packet, header->caplen, radio) &&
                static_cast<size_t>(header->caplen) >=
                    static_cast<size_t>(radio.length) + 24) {
                const uint8_t* dot11 = packet + radio.length;
                uint16_t frameControl = readLe16(dot11);
                int type = (frameControl >> 2) & 0x3;
                int subtype = (frameControl >> 4) & 0xF;

                if (type == 0 && subtype == 8) { // Beacon
                    processBeacon(packet, header->caplen, radio.length,
                                  radio, aps);
                } else if (type == 2) { // Data
                    processData(dot11, header->caplen - radio.length,
                                frameControl, aps);
                }
            }
        }

        auto now = std::chrono::steady_clock::now();
        if (now - lastPrint >= std::chrono::milliseconds(500)) {
            printAps(aps);
            lastPrint = now;
        }
    }

    pcap_close(pcap);
    return EXIT_FAILURE;
}

