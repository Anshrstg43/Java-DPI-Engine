package com.dpi;

public class PacketParser {

    // TCP Flag constants
    public static class TCPFlags {
        public static final int FIN = 0x01;
        public static final int SYN = 0x02;
        public static final int RST = 0x04;
        public static final int PSH = 0x08;
        public static final int ACK = 0x10;
        public static final int URG = 0x20;
    }

    // Protocol numbers
    public static class Protocol {
        public static final int ICMP = 1;
        public static final int TCP = 6;
        public static final int UDP = 17;
    }

    // EtherType values
    public static class EtherType {
        public static final int IPV4 = 0x0800;
        public static final int IPV6 = 0x86DD;
        public static final int ARP = 0x0806;
    }

    // Equivalent to ParsedPacket struct
    public static class ParsedPacket {
        // Timestamps
        public long timestampSec;
        public long timestampUsec;
        
        // Ethernet layer
        public String srcMac = "";
        public String destMac = "";
        public int etherType;
        
        // IP layer
        public boolean hasIp = false;
        public int ipVersion;
        public String srcIp = "";
        public String destIp = "";
        public int protocol; 
        public int ttl;
        
        // Transport layer
        public boolean hasTcp = false;
        public boolean hasUdp = false;
        public int srcPort;
        public int destPort;
        
        // TCP-specific
        public int tcpFlags;
        public long seqNumber;
        public long ackNumber;
        
        // Payload (Java alternative to C++ pointers)
        public int payloadLength = 0;
        public byte[] payloadData = null;
        public int payloadOffset = 0; 
    }

    public static boolean parse(PcapReader.RawPacket raw, ParsedPacket parsed) {
        // Initialize parsed packet (Java naturally resets fields, but we align with C++)
        parsed.timestampSec = raw.header.tsSec;
        parsed.timestampUsec = raw.header.tsUsec;
        
        byte[] data = raw.data;
        int len = data.length;
        
        // Using an array to simulate C++ size_t& offset pass-by-reference
        int[] offset = {0}; 
        
        if (!parseEthernet(data, len, parsed, offset)) {
            return false;
        }
        
        if (parsed.etherType == EtherType.IPV4) {
            if (!parseIPv4(data, len, parsed, offset)) {
                return false;
            }
            
            if (parsed.protocol == Protocol.TCP) {
                if (!parseTCP(data, len, parsed, offset)) {
                    return false;
                }
            } else if (parsed.protocol == Protocol.UDP) {
                if (!parseUDP(data, len, parsed, offset)) {
                    return false;
                }
            }
        }
        
        // Set payload information
        if (offset[0] < len) {
            parsed.payloadLength = len - offset[0];
            parsed.payloadData = data;
            parsed.payloadOffset = offset[0];
        } else {
            parsed.payloadLength = 0;
            parsed.payloadData = null;
            parsed.payloadOffset = 0;
        }
        
        return true;
    }

    private static boolean parseEthernet(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        int ETH_HEADER_LEN = 14;
        
        if (len < ETH_HEADER_LEN) {
            return false;
        }
        
        parsed.destMac = macToString(data, 0);
        parsed.srcMac = macToString(data, 6);
        
        // Parse EtherType (bytes 12-13, big-endian) matching ntohs
        parsed.etherType = ((data[12] & 0xFF) << 8) | (data[13] & 0xFF);
        
        offset[0] = ETH_HEADER_LEN;
        return true;
    }

    private static boolean parseIPv4(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        int MIN_IP_HEADER_LEN = 20;
        int baseOffset = offset[0];
        
        if (len < baseOffset + MIN_IP_HEADER_LEN) {
            return false;
        }
        
        int versionIhl = data[baseOffset] & 0xFF;
        parsed.ipVersion = (versionIhl >> 4) & 0x0F;
        int ihl = versionIhl & 0x0F;
        
        if (parsed.ipVersion != 4) {
            return false;
        }
        
        int ipHeaderLen = ihl * 4;
        if (ipHeaderLen < MIN_IP_HEADER_LEN || len < baseOffset + ipHeaderLen) {
            return false;
        }
        
        parsed.ttl = data[baseOffset + 8] & 0xFF;
        parsed.protocol = data[baseOffset + 9] & 0xFF;
        
        // Read IPs directly from bytes to mirror C++ memcpy behavior exactly
        parsed.srcIp = ipToString(data, baseOffset + 12);
        parsed.destIp = ipToString(data, baseOffset + 16);
        
        parsed.hasIp = true;
        offset[0] += ipHeaderLen;
        
        return true;
    }

    private static boolean parseTCP(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        int MIN_TCP_HEADER_LEN = 20;
        int baseOffset = offset[0];
        
        if (len < baseOffset + MIN_TCP_HEADER_LEN) {
            return false;
        }
        
        // ntohs equivalent
        parsed.srcPort = ((data[baseOffset] & 0xFF) << 8) | (data[baseOffset + 1] & 0xFF);
        parsed.destPort = ((data[baseOffset + 2] & 0xFF) << 8) | (data[baseOffset + 3] & 0xFF);
        
        // ntohl equivalent (using long to prevent negative numbers in Java)
        parsed.seqNumber = (Integer.toUnsignedLong(((data[baseOffset + 4] & 0xFF) << 24) | 
                                                   ((data[baseOffset + 5] & 0xFF) << 16) | 
                                                   ((data[baseOffset + 6] & 0xFF) << 8) | 
                                                    (data[baseOffset + 7] & 0xFF)));
                                                    
        parsed.ackNumber = (Integer.toUnsignedLong(((data[baseOffset + 8] & 0xFF) << 24) | 
                                                   ((data[baseOffset + 9] & 0xFF) << 16) | 
                                                   ((data[baseOffset + 10] & 0xFF) << 8) | 
                                                    (data[baseOffset + 11] & 0xFF)));
        
        int dataOffset = (data[baseOffset + 12] >> 4) & 0x0F;
        int tcpHeaderLen = dataOffset * 4;
        
        parsed.tcpFlags = data[baseOffset + 13] & 0xFF;
        
        if (tcpHeaderLen < MIN_TCP_HEADER_LEN || len < baseOffset + tcpHeaderLen) {
            return false;
        }
        
        parsed.hasTcp = true;
        offset[0] += tcpHeaderLen;
        
        return true;
    }

    private static boolean parseUDP(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        int UDP_HEADER_LEN = 8;
        int baseOffset = offset[0];
        
        if (len < baseOffset + UDP_HEADER_LEN) {
            return false;
        }
        
        parsed.srcPort = ((data[baseOffset] & 0xFF) << 8) | (data[baseOffset + 1] & 0xFF);
        parsed.destPort = ((data[baseOffset + 2] & 0xFF) << 8) | (data[baseOffset + 3] & 0xFF);
        
        parsed.hasUdp = true;
        offset[0] += UDP_HEADER_LEN;
        
        return true;
    }

    public static String macToString(byte[] data, int offset) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02x", data[offset + i] & 0xFF));
        }
        return sb.toString();
    }

    public static String ipToString(byte[] data, int offset) {
        return (data[offset] & 0xFF) + "." +
               (data[offset + 1] & 0xFF) + "." +
               (data[offset + 2] & 0xFF) + "." +
               (data[offset + 3] & 0xFF);
    }

    public static String protocolToString(int protocol) {
        return switch (protocol) {
            case Protocol.ICMP -> "ICMP";
            case Protocol.TCP -> "TCP";
            case Protocol.UDP -> "UDP";
            default -> "Unknown(" + protocol + ")";
        };
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder result = new StringBuilder();
        if ((flags & TCPFlags.SYN) != 0) result.append("SYN ");
        if ((flags & TCPFlags.ACK) != 0) result.append("ACK ");
        if ((flags & TCPFlags.FIN) != 0) result.append("FIN ");
        if ((flags & TCPFlags.RST) != 0) result.append("RST ");
        if ((flags & TCPFlags.PSH) != 0) result.append("PSH ");
        if ((flags & TCPFlags.URG) != 0) result.append("URG ");
        
        String resStr = result.toString();
        if (!resStr.isEmpty()) {
            resStr = resStr.substring(0, resStr.length() - 1); // Remove trailing space
        }
        return resStr.isEmpty() ? "none" : resStr;
    }
}