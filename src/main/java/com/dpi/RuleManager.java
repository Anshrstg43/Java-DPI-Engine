package com.dpi;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class RuleManager {

    // ============================================================================
    // Internal Data Structures & Locks
    // ============================================================================
    private final ReentrantReadWriteLock ipMutex = new ReentrantReadWriteLock();
    private final Set<Long> blockedIps = new HashSet<>();
    
    private final ReentrantReadWriteLock appMutex = new ReentrantReadWriteLock();
    private final Set<Types.AppType> blockedApps = new HashSet<>();
    
    private final ReentrantReadWriteLock domainMutex = new ReentrantReadWriteLock();
    private final Set<String> blockedDomains = new HashSet<>();
    private final List<String> domainPatterns = new ArrayList<>();
    
    private final ReentrantReadWriteLock portMutex = new ReentrantReadWriteLock();
    private final Set<Integer> blockedPorts = new HashSet<>();

    public static class BlockReason {
        public enum Type { IP, APP, DOMAIN, PORT }
        public Type type;
        public String detail;

        public BlockReason(Type type, String detail) {
            this.type = type;
            this.detail = detail;
        }
    }

    public static class RuleStats {
        public int blockedIps;
        public int blockedApps;
        public int blockedDomains;
        public int blockedPorts;
    }

    // ============================================================================
    // IP Blocking
    // ============================================================================
    public static long parseIP(String ip) {
        long result = 0;
        long octet = 0;
        int shift = 0;
        
        for (char c : ip.toCharArray()) {
            if (c == '.') {
                result |= (octet << shift);
                shift += 8;
                octet = 0;
            } else if (c >= '0' && c <= '9') {
                octet = octet * 10 + (c - '0');
            }
        }
        result |= (octet << shift);
        return result;
    }

    @SuppressWarnings("PointlessBitwiseExpression")
    public static String ipToString(long ip) {
        return ((ip >> 0) & 0xFF) + "." +
               ((ip >> 8) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >> 24) & 0xFF);
    }

    public void blockIP(long ip) {
        ipMutex.writeLock().lock();
        try { blockedIps.add(ip); } finally { ipMutex.writeLock().unlock(); }
        System.out.println("[RuleManager] Blocked IP: " + ipToString(ip));
    }

    public void blockIP(String ip) { blockIP(parseIP(ip)); }

    public void unblockIP(long ip) {
        ipMutex.writeLock().lock();
        try { blockedIps.remove(ip); } finally { ipMutex.writeLock().unlock(); }
        System.out.println("[RuleManager] Unblocked IP: " + ipToString(ip));
    }

    public void unblockIP(String ip) { unblockIP(parseIP(ip)); }

    public boolean isIPBlocked(long ip) {
        ipMutex.readLock().lock();
        try { return blockedIps.contains(ip); } finally { ipMutex.readLock().unlock(); }
    }

    public List<String> getBlockedIPs() {
        ipMutex.readLock().lock();
        try {
            List<String> result = new ArrayList<>();
            for (long ip : blockedIps) result.add(ipToString(ip));
            return result;
        } finally {
            ipMutex.readLock().unlock();
        }
    }

    // ============================================================================
    // Application Blocking
    // ============================================================================
    public void blockApp(Types.AppType app) {
        appMutex.writeLock().lock();
        try { blockedApps.add(app); } finally { appMutex.writeLock().unlock(); }
        System.out.println("[RuleManager] Blocked app: " + Types.appTypeToString(app));
    }

    public void unblockApp(Types.AppType app) {
        appMutex.writeLock().lock();
        try { blockedApps.remove(app); } finally { appMutex.writeLock().unlock(); }
        System.out.println("[RuleManager] Unblocked app: " + Types.appTypeToString(app));
    }

    public boolean isAppBlocked(Types.AppType app) {
        appMutex.readLock().lock();
        try { return blockedApps.contains(app); } finally { appMutex.readLock().unlock(); }
    }

    public List<Types.AppType> getBlockedApps() {
        appMutex.readLock().lock();
        try { return new ArrayList<>(blockedApps); } finally { appMutex.readLock().unlock(); }
    }

    // ============================================================================
    // Domain Blocking
    // ============================================================================
    public void blockDomain(String domain) {
        domainMutex.writeLock().lock();
        try {
            if (domain.contains("*")) domainPatterns.add(domain);
            else blockedDomains.add(domain);
        } finally {
            domainMutex.writeLock().unlock();
        }
        System.out.println("[RuleManager] Blocked domain: " + domain);
    }

    public void unblockDomain(String domain) {
        domainMutex.writeLock().lock();
        try {
            if (domain.contains("*")) domainPatterns.remove(domain);
            else blockedDomains.remove(domain);
        } finally {
            domainMutex.writeLock().unlock();
        }
        System.out.println("[RuleManager] Unblocked domain: " + domain);
    }

    private static boolean domainMatchesPattern(String domain, String pattern) {
        if (pattern.length() >= 2 && pattern.startsWith("*.")) {
            String suffix = pattern.substring(1);
            if (domain.length() >= suffix.length() && domain.endsWith(suffix)) return true;
            if (domain.equals(pattern.substring(2))) return true;
        }
        return false;
    }

    public boolean isDomainBlocked(String domain) {
        domainMutex.readLock().lock();
        try {
            if (blockedDomains.contains(domain)) return true;
            
            String lowerDomain = domain.toLowerCase();
            for (String pattern : domainPatterns) {
                if (domainMatchesPattern(lowerDomain, pattern.toLowerCase())) return true;
            }
            return false;
        } finally {
            domainMutex.readLock().unlock();
        }
    }

    public List<String> getBlockedDomains() {
        domainMutex.readLock().lock();
        try {
            List<String> result = new ArrayList<>(blockedDomains);
            result.addAll(domainPatterns);
            return result;
        } finally {
            domainMutex.readLock().unlock();
        }
    }

    // ============================================================================
    // Port Blocking
    // ============================================================================
    public void blockPort(int port) {
        portMutex.writeLock().lock();
        try { blockedPorts.add(port); } finally { portMutex.writeLock().unlock(); }
        System.out.println("[RuleManager] Blocked port: " + port);
    }

    public void unblockPort(int port) {
        portMutex.writeLock().lock();
        try { blockedPorts.remove(port); } finally { portMutex.writeLock().unlock(); }
    }

    public boolean isPortBlocked(int port) {
        portMutex.readLock().lock();
        try { return blockedPorts.contains(port); } finally { portMutex.readLock().unlock(); }
    }

    // ============================================================================
    // Combined Check
    // ============================================================================
    public BlockReason shouldBlock(long srcIp, int dstPort, Types.AppType app, String domain) {
        if (isIPBlocked(srcIp)) return new BlockReason(BlockReason.Type.IP, ipToString(srcIp));
        if (isPortBlocked(dstPort)) return new BlockReason(BlockReason.Type.PORT, String.valueOf(dstPort));
        if (isAppBlocked(app)) return new BlockReason(BlockReason.Type.APP, Types.appTypeToString(app));
        if (domain != null && !domain.isEmpty() && isDomainBlocked(domain)) {
            return new BlockReason(BlockReason.Type.DOMAIN, domain);
        }
        return null;
    }

    // ============================================================================
    // Persistence
    // ============================================================================
    public boolean saveRules(String filename) {
        try (PrintWriter out = new PrintWriter(new FileWriter(filename))) {
            out.println("[BLOCKED_IPS]");
            for (String ip : getBlockedIPs()) out.println(ip);
            
            out.println("\n[BLOCKED_APPS]");
            for (Types.AppType app : getBlockedApps()) out.println(Types.appTypeToString(app));
            
            out.println("\n[BLOCKED_DOMAINS]");
            for (String dom : getBlockedDomains()) out.println(dom);
            
            out.println("\n[BLOCKED_PORTS]");
            portMutex.readLock().lock();
            try {
                for (int port : blockedPorts) out.println(port);
            } finally {
                portMutex.readLock().unlock();
            }
            System.out.println("[RuleManager] Rules saved to: " + filename);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public boolean loadRules(String filename) {
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            String currentSection = "";
            
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                if (line.startsWith("[")) {
                    currentSection = line;
                    continue;
                }
                
                switch (currentSection) {
                    case "[BLOCKED_IPS]" -> blockIP(line);
                    case "[BLOCKED_APPS]" -> {
                        for (Types.AppType app : Types.AppType.values()) {
                            if (Types.appTypeToString(app).equals(line)) {
                                blockApp(app);
                                break;
                            }
                        }
                    }
                    case "[BLOCKED_DOMAINS]" -> blockDomain(line);
                    case "[BLOCKED_PORTS]" -> blockPort(Integer.parseInt(line));
                }
            }
            System.out.println("[RuleManager] Rules loaded from: " + filename);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public void clearAll() {
        ipMutex.writeLock().lock(); try { blockedIps.clear(); } finally { ipMutex.writeLock().unlock(); }
        appMutex.writeLock().lock(); try { blockedApps.clear(); } finally { appMutex.writeLock().unlock(); }
        domainMutex.writeLock().lock(); try { blockedDomains.clear(); domainPatterns.clear(); } finally { domainMutex.writeLock().unlock(); }
        portMutex.writeLock().lock(); try { blockedPorts.clear(); } finally { portMutex.writeLock().unlock(); }
        System.out.println("[RuleManager] All rules cleared");
    }

    public RuleStats getStats() {
        RuleStats stats = new RuleStats();
        ipMutex.readLock().lock(); try { stats.blockedIps = blockedIps.size(); } finally { ipMutex.readLock().unlock(); }
        appMutex.readLock().lock(); try { stats.blockedApps = blockedApps.size(); } finally { appMutex.readLock().unlock(); }
        domainMutex.readLock().lock(); try { stats.blockedDomains = blockedDomains.size() + domainPatterns.size(); } finally { domainMutex.readLock().unlock(); }
        portMutex.readLock().lock(); try { stats.blockedPorts = blockedPorts.size(); } finally { portMutex.readLock().unlock(); }
        return stats;
    }
}