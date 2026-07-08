package com.dpi;

import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicLong;

public class LoadBalancer {
    private final int lbId;
    private final int fpStartId;
    private final int numFps;
    private final ThreadSafeQueue<PacketJob> inputQueue;
    private final List<ThreadSafeQueue<PacketJob>> fpQueues;
    
    private final AtomicLong[] perFpCounts;
    private final AtomicLong packetsReceived = new AtomicLong(0);
    private final AtomicLong packetsDispatched = new AtomicLong(0);
    
    private boolean running = false;
    private Thread thread;

    public LoadBalancer(int lbId, List<ThreadSafeQueue<PacketJob>> fpQueues, int fpStartId) {
        this.lbId = lbId;
        this.fpStartId = fpStartId;
        this.numFps = fpQueues.size();
        this.inputQueue = new ThreadSafeQueue<>(10000);
        this.fpQueues = fpQueues;
        
        this.perFpCounts = new AtomicLong[numFps];
        for (int i = 0; i < numFps; i++) {
            this.perFpCounts[i] = new AtomicLong(0);
        }
    }

    public void start() {
        if (running) return;
        running = true;
        thread = new Thread(this::run);
        thread.start();
        System.out.println("[LB" + lbId + "] Started (serving FP" + fpStartId + "-FP" + (fpStartId + numFps - 1) + ")");
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
        System.out.println("[LB" + lbId + "] Stopped");
    }

    private void run() {
        while (running) {
            try {
                PacketJob job = inputQueue.popWithTimeout(100);
                if (job == null) continue;
                
                packetsReceived.incrementAndGet();
                
                // Select target FP based on five-tuple hash (consistent hashing)
                int fpIndex = selectFP(job.tuple);
                
                fpQueues.get(fpIndex).push(job);
                
                packetsDispatched.incrementAndGet();
                perFpCounts[fpIndex].incrementAndGet();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private int selectFP(Types.FiveTuple tuple) {
        // Use Java's native built-in hash code
        int hash = tuple.hashCode();
        return Math.abs(hash) % numFps;
    }

    public ThreadSafeQueue<PacketJob> getInputQueue() {
        return inputQueue;
    }

    // ============================================================================
    // LBManager Implementation
    // ============================================================================
    public static class Manager {
        private final List<LoadBalancer> lbs = new ArrayList<>();
        
        public Manager(int numLbs, int fpsPerLb, List<ThreadSafeQueue<PacketJob>> fpQueues) {
            for (int lbId = 0; lbId < numLbs; lbId++) {
                List<ThreadSafeQueue<PacketJob>> lbFpQueues = new ArrayList<>();
                int fpStart = lbId * fpsPerLb;
                
                for (int i = 0; i < fpsPerLb; i++) {
                    lbFpQueues.add(fpQueues.get(fpStart + i));
                }
                lbs.add(new LoadBalancer(lbId, lbFpQueues, fpStart));
            }
            System.out.println("[LBManager] Created " + numLbs + " load balancers, " + fpsPerLb + " FPs each");
        }
        
        public void startAll() {
            for (LoadBalancer lb : lbs) lb.start();
        }
        
        public void stopAll() {
            for (LoadBalancer lb : lbs) lb.stop();
        }
        
        public LoadBalancer getLBForPacket(Types.FiveTuple tuple) {
            int hash = tuple.hashCode();
            int lbIndex = Math.abs(hash) % lbs.size();
            return lbs.get(lbIndex);
        }
    }
}