package com.dpi;

import java.util.Objects;

public class Types {
    
    // 100% Exact match to C++ AppType
    public enum AppType {
        UNKNOWN, HTTP, HTTPS, DNS, TLS, QUIC, GOOGLE, FACEBOOK, 
        YOUTUBE, TWITTER, INSTAGRAM, NETFLIX, AMAZON, MICROSOFT, 
        APPLE, WHATSAPP, TELEGRAM, TIKTOK, SPOTIFY, ZOOM, 
        DISCORD, GITHUB, CLOUDFLARE
    }

    // 100% Exact match to C++ appTypeToString
    public static String appTypeToString(AppType type) {
        return switch (type) {
            case UNKNOWN -> "Unknown";
            case HTTP -> "HTTP";
            case HTTPS -> "HTTPS";
            case DNS -> "DNS";
            case TLS -> "TLS";
            case QUIC -> "QUIC";
            case GOOGLE -> "Google";
            case FACEBOOK -> "Facebook";
            case YOUTUBE -> "YouTube";
            case TWITTER -> "Twitter/X";
            case INSTAGRAM -> "Instagram";
            case NETFLIX -> "Netflix";
            case AMAZON -> "Amazon";
            case MICROSOFT -> "Microsoft";
            case APPLE -> "Apple";
            case WHATSAPP -> "WhatsApp";
            case TELEGRAM -> "Telegram";
            case TIKTOK -> "TikTok";
            case SPOTIFY -> "Spotify";
            case ZOOM -> "Zoom";
            case DISCORD -> "Discord";
            case GITHUB -> "GitHub";
            case CLOUDFLARE -> "Cloudflare";
            default -> "Unknown";
        };
    }

    public static class FiveTuple {
        public long srcIp;   
        public long destIp;
        public int srcPort;  
        public int destPort;
        public int protocol; 

        public FiveTuple() {}

        public FiveTuple(long srcIp, long dstIp, int srcPort, int dstPort, int protocol) {
            this.srcIp = srcIp;
            this.destIp = dstIp;
            this.srcPort = srcPort;
            this.destPort = dstPort;
            this.protocol = protocol;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            FiveTuple fiveTuple = (FiveTuple) o;
            return srcIp == fiveTuple.srcIp &&
                   destIp == fiveTuple.destIp &&
                   srcPort == fiveTuple.srcPort &&
                   destPort == fiveTuple.destPort &&
                   protocol == fiveTuple.protocol;
        }

        @Override
        public int hashCode() {
            return Objects.hash(srcIp, destIp, srcPort, destPort, protocol);
        }
    }
    
    public static class Flow {
        public AppType appType = AppType.UNKNOWN;
        public String sni = "";
        public boolean blocked = false;
    }
    
    public static AppType sniToAppType(String sni) {
        if (sni == null) return AppType.UNKNOWN;
        String lowerSni = sni.toLowerCase();
        
        if (lowerSni.contains("youtube")) return AppType.YOUTUBE;
        if (lowerSni.contains("facebook")) return AppType.FACEBOOK;
        if (lowerSni.contains("google")) return AppType.GOOGLE;
        if (lowerSni.contains("tiktok")) return AppType.TIKTOK;
        if (lowerSni.contains("github")) return AppType.GITHUB;
        if (lowerSni.contains("discord")) return AppType.DISCORD;
        if (lowerSni.contains("twitter") || lowerSni.contains("twimg")) return AppType.TWITTER;
        if (lowerSni.contains("spotify")) return AppType.SPOTIFY;
        if (lowerSni.contains("amazon")) return AppType.AMAZON;
        if (lowerSni.contains("zoom")) return AppType.ZOOM;
        if (lowerSni.contains("apple")) return AppType.APPLE;
        if (lowerSni.contains("microsoft")) return AppType.MICROSOFT;
        if (lowerSni.contains("whatsapp")) return AppType.WHATSAPP;
        if (lowerSni.contains("telegram")) return AppType.TELEGRAM;
        if (lowerSni.contains("instagram")) return AppType.INSTAGRAM;
        if (lowerSni.contains("netflix")) return AppType.NETFLIX;
        if (lowerSni.contains("cloudflare")) return AppType.CLOUDFLARE;
        
        return AppType.UNKNOWN;
    }
}