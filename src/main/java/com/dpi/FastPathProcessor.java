package com.dpi;

import java.util.concurrent.atomic.AtomicLong;

public class FastPathProcessor {
    private final int fpId;
    private final ThreadSafeQueue<PacketJob> inputQueue;
    private final ConnectionTracker connTracker;
    private final RuleManager ruleManager;
    private final PacketOutputCallback outputCallback;
    
    private final AtomicLong packetsProcessed = new AtomicLong(0);
    private final AtomicLong packetsForwarded = new AtomicLong(0);
    private final AtomicLong packetsDropped = new AtomicLong(0);
    private final AtomicLong sniExtractions = new AtomicLong(0);
    private final AtomicLong classificationHits = new AtomicLong(0);
    
    private boolean running = false;
    private Thread thread;

    public interface PacketOutputCallback {
        void onProcessComplete(PacketJob job, PacketAction action);
    }

    public enum PacketAction {
        FORWARD, DROP
    }

    public FastPathProcessor(int fpId, RuleManager ruleManager, PacketOutputCallback outputCallback) {
        this.fpId = fpId;
        this.inputQueue = new ThreadSafeQueue<>(10000);
        this.connTracker = new ConnectionTracker(fpId);
        this.ruleManager = ruleManager;
        this.outputCallback = outputCallback;
    }

    public void start() {
        if (running) return;
        running = true;
        thread = new Thread(this::run);
        thread.start();
        System.out.println("[FP" + fpId + "] Started");
    }

    public void stop() {
        if (!running) return;
        running = false;
        inputQueue.shutdown();
        try {
            if (thread != null) thread.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        System.out.println("[FP" + fpId + "] Stopped (processed " + packetsProcessed.get() + " packets)");
    }

    private void run() {
        while (running) {
            try {
                PacketJob job = inputQueue.popWithTimeout(100);
                
                if (job == null) {
                    connTracker.cleanupStale(300); // 300 seconds timeout
                    continue;
                }
                
                packetsProcessed.incrementAndGet();
                
                PacketAction action = processPacket(job);
                
                if (outputCallback != null) {
                    outputCallback.onProcessComplete(job, action);
                }
                
                if (action == PacketAction.DROP) {
                    packetsDropped.incrementAndGet();
                } else {
                    packetsForwarded.incrementAndGet();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private PacketAction processPacket(PacketJob job) {
        ConnectionTracker.Connection conn = connTracker.getOrCreateConnection(job.tuple);
        if (conn == null) return PacketAction.FORWARD;
        
        connTracker.updateConnection(conn, job.data.length, true);
        
        if (job.tuple.protocol == 6) { 
            updateTCPState(conn, job.tcpFlags);
        }
        
        if (conn.state == ConnectionTracker.ConnectionState.BLOCKED) {
            return PacketAction.DROP;
        }
        
        if (conn.state != ConnectionTracker.ConnectionState.CLASSIFIED && job.payloadLength > 0) {
            inspectPayload(job, conn);
        }
        
        return checkRules(job, conn);
    }

    private void inspectPayload(PacketJob job, ConnectionTracker.Connection conn) {
        if (job.payloadLength == 0 || job.payloadOffset >= job.data.length) return;
        
        if (tryExtractSNI(job, conn)) return;
        if (tryExtractHTTPHost(job, conn)) return;
        
        if (job.tuple.destPort == 53 || job.tuple.srcPort == 53) {
            String domain = SniExtractor.DNS.extractQuery(job.data, job.payloadOffset, job.payloadLength);
            if (domain != null) {
                connTracker.classifyConnection(conn, Types.AppType.DNS, domain);
                return;
            }
        }
        
        if (job.tuple.destPort == 80) {
            connTracker.classifyConnection(conn, Types.AppType.HTTP, "");
        } else if (job.tuple.destPort == 443) {
            connTracker.classifyConnection(conn, Types.AppType.HTTPS, "");
        }
    }

    private boolean tryExtractSNI(PacketJob job, ConnectionTracker.Connection conn) {
        if (job.tuple.destPort != 443 && job.payloadLength < 50) return false;
        if (job.payloadOffset >= job.data.length || job.payloadLength == 0) return false;
        
        String sni = SniExtractor.TLS.extract(job.data, job.payloadOffset, job.payloadLength);
        if (sni != null) {
            sniExtractions.incrementAndGet();
            Types.AppType app = Types.sniToAppType(sni);
            connTracker.classifyConnection(conn, app, sni);
            
            if (app != Types.AppType.UNKNOWN && app != Types.AppType.HTTPS) {
                classificationHits.incrementAndGet();
            }
            return true;
        }
        return false;
    }

    private boolean tryExtractHTTPHost(PacketJob job, ConnectionTracker.Connection conn) {
        if (job.tuple.destPort != 80) return false;
        if (job.payloadOffset >= job.data.length || job.payloadLength == 0) return false;
        
        String host = SniExtractor.HTTP.extract(job.data, job.payloadOffset, job.payloadLength);
        if (host != null) {
            Types.AppType app = Types.sniToAppType(host);
            connTracker.classifyConnection(conn, app, host);
            
            if (app != Types.AppType.UNKNOWN && app != Types.AppType.HTTP) {
                classificationHits.incrementAndGet();
            }
            return true;
        }
        return false;
    }

    private PacketAction checkRules(PacketJob job, ConnectionTracker.Connection conn) {
        if (ruleManager == null) return PacketAction.FORWARD;
        
        RuleManager.BlockReason reason = ruleManager.shouldBlock(
            job.tuple.srcIp, job.tuple.destPort, conn.appType, conn.sni
        );
        
        if (reason != null) {
            System.out.println("[FP" + fpId + "] BLOCKED packet: " + reason.type + " " + reason.detail);
            connTracker.blockConnection(conn);
            return PacketAction.DROP;
        }
        
        return PacketAction.FORWARD;
    }

    private void updateTCPState(ConnectionTracker.Connection conn, int tcpFlags) {
        int SYN = 0x02, ACK = 0x10, FIN = 0x01, RST = 0x04;
        
        if ((tcpFlags & SYN) != 0) {
            if ((tcpFlags & ACK) != 0) conn.synAckSeen = true;
            else conn.synSeen = true;
        }
        
        if (conn.synSeen && conn.synAckSeen && (tcpFlags & ACK) != 0) {
            if (conn.state == ConnectionTracker.ConnectionState.NEW) {
                conn.state = ConnectionTracker.ConnectionState.ESTABLISHED;
            }
        }
        
        if ((tcpFlags & FIN) != 0) conn.finSeen = true;
        if ((tcpFlags & RST) != 0) conn.state = ConnectionTracker.ConnectionState.CLOSED;
        
        if (conn.finSeen && (tcpFlags & ACK) != 0) {
            conn.state = ConnectionTracker.ConnectionState.CLOSED;
        }
    }

    public ThreadSafeQueue<PacketJob> getInputQueue() { return inputQueue; }
    public ConnectionTracker getConnectionTracker() { return connTracker; }
}