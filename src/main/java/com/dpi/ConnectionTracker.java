package com.dpi;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Consumer;

public class ConnectionTracker {

    // ============================================================================
    // State and Data Structures
    // ============================================================================
    public enum ConnectionState {
        NEW, ESTABLISHED, CLASSIFIED, BLOCKED, CLOSED
    }

    public static class Connection {
        public Types.FiveTuple tuple;
        public ConnectionState state;
        public long firstSeen;
        public long lastSeen;
        
        public long packetsOut = 0;
        public long bytesOut = 0;
        public long packetsIn = 0;
        public long bytesIn = 0;
        
        public Types.AppType appType = Types.AppType.UNKNOWN;
        public String sni = "";
        public FastPathProcessor.PacketAction action = FastPathProcessor.PacketAction.FORWARD;
        
        // TCP state tracking
        public boolean synSeen = false;
        public boolean synAckSeen = false;
        public boolean finSeen = false;
    }

    public static class TrackerStats {
        public long activeConnections;
        public long totalConnectionsSeen;
        public long classifiedConnections;
        public long blockedConnections;
    }
    // ============================================================================
    // Connection Tracker Implementation
    // ============================================================================

    private final int maxConnections;
    
    private final Map<Types.FiveTuple, Connection> connections = new HashMap<>();
    
    private long totalSeen = 0;
    private long classifiedCount = 0;
    private long blockedCount = 0;

    public ConnectionTracker(int fpId, int maxConnections) {
        this.maxConnections = maxConnections;
    }

    public ConnectionTracker(int fpId) {
        this(fpId, 100000);
    }

    public Connection getOrCreateConnection(Types.FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) {
            return conn;
        }
        
        if (connections.size() >= maxConnections) {
            evictOldest();
        }
        
        conn = new Connection();
        conn.tuple = tuple;
        conn.state = ConnectionState.NEW;
        conn.firstSeen = System.currentTimeMillis();
        conn.lastSeen = conn.firstSeen;
        
        connections.put(tuple, conn);
        totalSeen++;
        
        return conn;
    }

    public Connection getConnection(Types.FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) {
            return conn;
        }
        
        // Try reverse tuple (for bidirectional matching)
        Types.FiveTuple rev = new Types.FiveTuple(
            tuple.destIp, tuple.srcIp, tuple.destPort, tuple.srcPort, tuple.protocol
        );
        return connections.get(rev);
    }

    public void updateConnection(Connection conn, long packetSize, boolean isOutbound) {
        if (conn == null) return;
        
        conn.lastSeen = System.currentTimeMillis();
        
        if (isOutbound) {
            conn.packetsOut++;
            conn.bytesOut += packetSize;
        } else {
            conn.packetsIn++;
            conn.bytesIn += packetSize;
        }
    }

    public void classifyConnection(Connection conn, Types.AppType app, String sni) {
        if (conn == null) return;
        
        if (conn.state != ConnectionState.CLASSIFIED) {
            conn.appType = app;
            conn.sni = sni;
            conn.state = ConnectionState.CLASSIFIED;
            classifiedCount++;
        }
    }

    public void blockConnection(Connection conn) {
        if (conn == null) return;
        
        conn.state = ConnectionState.BLOCKED;
        conn.action = FastPathProcessor.PacketAction.DROP;
        blockedCount++;
    }

    public void closeConnection(Types.FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) {
            conn.state = ConnectionState.CLOSED;
        }
    }

    public int cleanupStale(int timeoutSeconds) {
        long now = System.currentTimeMillis();
        long timeoutMillis = timeoutSeconds * 1000L;
        int removed = 0;
        
        // Using an iterator to safely remove items while looping
        var iterator = connections.entrySet().iterator();
        while (iterator.hasNext()) {
            var entry = iterator.next();
            Connection conn = entry.getValue();
            long age = now - conn.lastSeen;
            
            if (age > timeoutMillis || conn.state == ConnectionState.CLOSED) {
                iterator.remove();
                removed++;
            }
        }
        
        return removed;
    }

    public List<Connection> getAllConnections() {
        return new ArrayList<>(connections.values());
    }

    public int getActiveCount() {
        return connections.size();
    }

    public TrackerStats getStats() {
        TrackerStats stats = new TrackerStats();
        stats.activeConnections = connections.size();
        stats.totalConnectionsSeen = totalSeen;
        stats.classifiedConnections = classifiedCount;
        stats.blockedConnections = blockedCount;
        return stats;
    }

    public void clear() {
        connections.clear();
    }

    public void forEach(Consumer<Connection> callback) {
        for (Connection conn : connections.values()) {
            callback.accept(conn);
        }
    }

    private void evictOldest() {
        if (connections.isEmpty()) return;
        
        Types.FiveTuple oldestKey = null;
        long oldestTime = Long.MAX_VALUE;
        
        for (Map.Entry<Types.FiveTuple, Connection> entry : connections.entrySet()) {
            if (entry.getValue().lastSeen < oldestTime) {
                oldestTime = entry.getValue().lastSeen;
                oldestKey = entry.getKey();
            }
        }
        
        if (oldestKey != null) {
            connections.remove(oldestKey);
        }
    }

    // ============================================================================
    // Global Connection Table - Aggregates stats from all FP trackers
    // ============================================================================
    public static class GlobalConnectionTable {
        private final ConnectionTracker[] trackers;
        // Java equivalent of std::shared_mutex (allows multiple readers, single writer)
        private final ReentrantReadWriteLock mutex = new ReentrantReadWriteLock();

        public GlobalConnectionTable(int numFps) {
            trackers = new ConnectionTracker[numFps];
        }

        public void registerTracker(int fpId, ConnectionTracker tracker) {
            mutex.writeLock().lock();
            try {
                if (fpId < trackers.length) {
                    trackers[fpId] = tracker;
                }
            } finally {
                mutex.writeLock().unlock();
            }
        }

        public static class GlobalStats {
            public long totalActiveConnections = 0;
            public long totalConnectionsSeen = 0;
            public Map<Types.AppType, Long> appDistribution = new HashMap<>();
            public List<Map.Entry<String, Long>> topDomains = new ArrayList<>();
        }

        public GlobalStats getGlobalStats() {
            mutex.readLock().lock();
            try {
                GlobalStats stats = new GlobalStats();
                Map<String, Long> domainCounts = new HashMap<>();
                
                for (ConnectionTracker tracker : trackers) {
                    if (tracker == null) continue;
                    
                    TrackerStats trackerStats = tracker.getStats();
                    stats.totalActiveConnections += trackerStats.activeConnections;
                    stats.totalConnectionsSeen += trackerStats.totalConnectionsSeen;
                    
                    tracker.forEach(conn -> {
                        stats.appDistribution.put(conn.appType, 
                            stats.appDistribution.getOrDefault(conn.appType, 0L) + 1);
                            
                        if (conn.sni != null && !conn.sni.isEmpty()) {
                            domainCounts.put(conn.sni, 
                                domainCounts.getOrDefault(conn.sni, 0L) + 1);
                        }
                    });
                }
                
                // Sort top domains
                List<Map.Entry<String, Long>> domainVec = new ArrayList<>(domainCounts.entrySet());
                domainVec.sort((a, b) -> b.getValue().compareTo(a.getValue())); // Descending order
                
                int count = Math.min(domainVec.size(), 20);
                stats.topDomains = domainVec.subList(0, count);
                
                return stats;
            } finally {
                mutex.readLock().unlock();
            }
        }

        public String generateReport() {
            GlobalStats stats = getGlobalStats();
            StringBuilder ss = new StringBuilder();
            
            ss.append("\n╔══════════════════════════════════════════════════════════════╗\n");
            ss.append("║               CONNECTION STATISTICS REPORT                   ║\n");
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");
            
            ss.append(String.format("║ Active Connections:     %-36d ║\n", stats.totalActiveConnections));
            ss.append(String.format("║ Total Connections Seen: %-36d ║\n", stats.totalConnectionsSeen));
            
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");
            ss.append("║                    APPLICATION BREAKDOWN                     ║\n");
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");
            
            long total = 0;
            for (long count : stats.appDistribution.values()) {
                total += count;
            }
            
            List<Map.Entry<Types.AppType, Long>> sortedApps = new ArrayList<>(stats.appDistribution.entrySet());
            sortedApps.sort((a, b) -> b.getValue().compareTo(a.getValue()));
            
            for (Map.Entry<Types.AppType, Long> pair : sortedApps) {
                double pct = total > 0 ? (100.0 * pair.getValue() / total) : 0;
                ss.append(String.format("║ %-20s %10d (%5.1f%%)           ║\n", 
                    Types.appTypeToString(pair.getKey()), pair.getValue(), pct));
            }
            
            if (!stats.topDomains.isEmpty()) {
                ss.append("╠══════════════════════════════════════════════════════════════╣\n");
                ss.append("║                      TOP DOMAINS                             ║\n");
                ss.append("╠══════════════════════════════════════════════════════════════╣\n");
                
                for (Map.Entry<String, Long> pair : stats.topDomains) {
                    String domain = pair.getKey();
                    if (domain.length() > 35) {
                        domain = domain.substring(0, 32) + "...";
                    }
                    ss.append(String.format("║ %-40s %10d           ║\n", domain, pair.getValue()));
                }
            }
            
            ss.append("╚══════════════════════════════════════════════════════════════╝\n");
            return ss.toString();
        }
    }
}