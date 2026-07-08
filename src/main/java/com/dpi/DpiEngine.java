package com.dpi;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

public class DpiEngine {

    // ============================================================================
    // Configuration & Stats Structures
    // ============================================================================
    public static class Config {
        public int numLoadBalancers = 2;
        public int fpsPerLb = 2;
        public int queueSize = 10000;
        public String rulesFile = "";
        public boolean verbose = false;
    }

    public static class DPIStats {
        public AtomicLong totalPackets = new AtomicLong(0);
        public AtomicLong totalBytes = new AtomicLong(0);
        public AtomicLong tcpPackets = new AtomicLong(0);
        public AtomicLong udpPackets = new AtomicLong(0);
        public AtomicLong forwardedPackets = new AtomicLong(0);
        public AtomicLong droppedPackets = new AtomicLong(0);
    }

    // ============================================================================
    // Internal State
    // ============================================================================
    private final Config config;
    private RuleManager ruleManager;
    private ConnectionTracker.GlobalConnectionTable globalConnTable;
    private FPManager fpManager;
    private LoadBalancer.Manager lbManager;

    private final ThreadSafeQueue<PacketJob> outputQueue;
    private Thread outputThread;
    private FileOutputStream outputFile;
    
    private final DPIStats stats = new DPIStats();
    
    private volatile boolean running = false;
    private volatile boolean processingComplete = false;

    // ============================================================================
    // Implementation
    // ============================================================================
    public DpiEngine(Config config) {
        this.config = config;
        this.outputQueue = new ThreadSafeQueue<>(config.queueSize);
        

        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                    DPI ENGINE v1.0 (Java)                    ║");
        System.out.println("║               Deep Packet Inspection System                  ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║ Configuration:                                               ║");
        System.out.printf("║   Load Balancers:    %3d                                     ║\n", config.numLoadBalancers);
        System.out.printf("║   FPs per LB:        %3d                                     ║\n", config.fpsPerLb);
        System.out.printf("║   Total FP threads:  %3d                                     ║\n", (config.numLoadBalancers * config.fpsPerLb));
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }
    public RuleManager getRuleManager() { return ruleManager; }
    public boolean initialize() {
        ruleManager = new RuleManager();
        
        if (config.rulesFile != null && !config.rulesFile.isEmpty()) {
            ruleManager.loadRules(config.rulesFile);
        }

        int totalFps = config.numLoadBalancers * config.fpsPerLb;
        
        fpManager = new FPManager(totalFps, ruleManager, this::handleOutput);
        
        List<ThreadSafeQueue<PacketJob>> fpQueues = new ArrayList<>();
        for (int i = 0; i < totalFps; i++) {
            fpQueues.add(fpManager.getFP(i).getInputQueue());
        }

        lbManager = new LoadBalancer.Manager(config.numLoadBalancers, config.fpsPerLb, fpQueues);
        
        globalConnTable = new ConnectionTracker.GlobalConnectionTable(totalFps);
        for (int i = 0; i < totalFps; i++) {
            globalConnTable.registerTracker(i, fpManager.getFP(i).getConnectionTracker());
        }

        System.out.println("[DPIEngine] Initialized successfully");
        return true;
    }

    public void start() {
        if (running) return;
        running = true;
        processingComplete = false;

        outputThread = new Thread(this::outputThreadFunc);
        outputThread.start();

        fpManager.startAll();
        lbManager.startAll();

        System.out.println("[DPIEngine] All threads started");
    }

    public void stop() {
        if (!running) return;
        running = false;

        if (lbManager != null) lbManager.stopAll();
        if (fpManager != null) fpManager.stopAll();

        outputQueue.shutdown();
        try {
            if (outputThread != null) outputThread.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        System.out.println("[DPIEngine] All threads stopped");
    }

    public boolean processFile(String inputFile, String outputFilePath) {
        System.out.println("\n[DPIEngine] Processing: " + inputFile);
        System.out.println("[DPIEngine] Output to:  " + outputFilePath + "\n");

        if (ruleManager == null) {
            if (!initialize()) return false;
        }

        try {
            outputFile = new FileOutputStream(outputFilePath);
        } catch (IOException e) {
            System.err.println("[DPIEngine] Error: Cannot open output file");
            return false;
        }

        start();

        // Run reader in main thread for simplicity in Java (mimics reader_thread.join())
        readerThreadFunc(inputFile);

        try { Thread.sleep(500); } catch (InterruptedException e) {}
        processingComplete = true;
        try { Thread.sleep(200); } catch (InterruptedException e) {}

        stop();

        try {
            if (outputFile != null) outputFile.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println(generateReport());
        System.out.println(generateReport());
        System.out.println(globalConnTable.generateReport()); 
        return true;

    }

    private void readerThreadFunc(String inputFile) {
        try (PcapReader reader = new PcapReader()) {
            if (!reader.open(inputFile)) {
                System.err.println("[Reader] Error: Cannot open input file");
                return;
            }

            writeOutputHeader(reader.getGlobalHeader());

            PcapReader.RawPacket raw = new PcapReader.RawPacket();
            PacketParser.ParsedPacket parsed = new PacketParser.ParsedPacket();
            int packetId = 0;

            System.out.println("[Reader] Starting packet processing...");

            while (reader.readNextPacket(raw)) {
                if (!PacketParser.parse(raw, parsed)) continue;
                if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) continue;

                PacketJob job = createPacketJob(raw, parsed, packetId++);

                stats.totalPackets.incrementAndGet();
                stats.totalBytes.addAndGet(raw.data.length);

                if (parsed.hasTcp) stats.tcpPackets.incrementAndGet();
                else if (parsed.hasUdp) stats.udpPackets.incrementAndGet();

                LoadBalancer lb = lbManager.getLBForPacket(job.tuple);
                lb.getInputQueue().push(job);
            }
            System.out.println("[Reader] Finished reading " + packetId + " packets");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private PacketJob createPacketJob(PcapReader.RawPacket raw, PacketParser.ParsedPacket parsed, int packetId) {
        Types.FiveTuple tuple = new Types.FiveTuple(
            RuleManager.parseIP(parsed.srcIp),
            RuleManager.parseIP(parsed.destIp),
            parsed.srcPort,
            parsed.destPort,
            parsed.protocol
        );

        return new PacketJob(tuple, raw.data, parsed.tcpFlags, parsed.payloadLength, parsed.payloadOffset);
    }

    private void outputThreadFunc() {
        while (running || !outputQueue.empty()) {
            try {
                PacketJob job = outputQueue.popWithTimeout(100);
                if (job != null) {
                    writeOutputPacket(job);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private void handleOutput(PacketJob job, FastPathProcessor.PacketAction action) {
        if (action == FastPathProcessor.PacketAction.DROP) {
            stats.droppedPackets.incrementAndGet();
            return;
        }
        stats.forwardedPackets.incrementAndGet();
        outputQueue.tryPush(job);
    }

    private synchronized boolean writeOutputHeader(PcapReader.PcapGlobalHeader header) {
        if (outputFile == null) return false;
        try {
            ByteBuffer b = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
            b.putInt(0xa1b2c3d4).putShort((short)2).putShort((short)4)
             .putInt(0).putInt(0).putInt(65535).putInt(1);
            outputFile.write(b.array());
            return true;
        } catch (IOException e) { return false; }
    }

    private synchronized void writeOutputPacket(PacketJob job) {
        if (outputFile == null) return;
        try {
            ByteBuffer b = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
            // Assuming tsSec and tsUsec were stored in job, using 0 for simplicity if not in PacketJob yet
            b.putInt(0).putInt(0).putInt(job.data.length).putInt(job.data.length);
            outputFile.write(b.array());
            outputFile.write(job.data);
        } catch (IOException e) { e.printStackTrace(); }
    }

    public String generateReport() {
        StringBuilder ss = new StringBuilder();
        ss.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        ss.append("║                    DPI ENGINE STATISTICS                     ║\n");
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");
        ss.append("║ PACKET STATISTICS                                            ║\n");
        ss.append(String.format("║   Total Packets:      %12d                           ║\n", stats.totalPackets.get()));
        ss.append(String.format("║   Total Bytes:        %12d                           ║\n", stats.totalBytes.get()));
        ss.append(String.format("║   TCP Packets:        %12d                           ║\n", stats.tcpPackets.get()));
        ss.append(String.format("║   UDP Packets:        %12d                           ║\n", stats.udpPackets.get()));
        
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");
        ss.append("║ FILTERING STATISTICS                                         ║\n");
        ss.append(String.format("║   Forwarded:          %12d                           ║\n", stats.forwardedPackets.get()));
        ss.append(String.format("║   Dropped/Blocked:    %12d                           ║\n", stats.droppedPackets.get()));
        
        if (stats.totalPackets.get() > 0) {
            double dropRate = 100.0 * stats.droppedPackets.get() / stats.totalPackets.get();
            ss.append(String.format("║   Drop Rate:          %11.2f%%                           ║\n", dropRate));
        }
        ss.append("╚══════════════════════════════════════════════════════════════╝\n");
        return ss.toString();
    }

    // ============================================================================
    // CLI Entry Point
    // ============================================================================
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java com.dpi.DpiEngine <input.pcap> <output.pcap> [--lbs N] [--fps N]");
            return;
        }

        Config config = new Config();
        config.rulesFile = "rules.txt";
        
        // Parse dynamic command line arguments for threads
        for (int i = 2; i < args.length; i++) {
            if (args[i].equals("--lbs") && i + 1 < args.length) {
                config.numLoadBalancers = Integer.parseInt(args[++i]);
            } else if (args[i].equals("--fps") && i + 1 < args.length) {
                config.fpsPerLb = Integer.parseInt(args[++i]);
            }
        }

        DpiEngine engine = new DpiEngine(config);
        engine.processFile(args[0], args[1]);
    }
}