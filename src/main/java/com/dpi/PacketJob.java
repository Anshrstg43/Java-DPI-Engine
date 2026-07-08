package com.dpi;

public class PacketJob {
    public Types.FiveTuple tuple;
    public byte[] data;
    
    // Extracted TCP properties for connection tracking
    public int tcpFlags;
    
    // Pre-calculated payload offsets
    public int payloadLength;
    public int payloadOffset;
    
    public PacketJob() {}
    
    public PacketJob(Types.FiveTuple tuple, byte[] data, int tcpFlags, int payloadLength, int payloadOffset) {
        this.tuple = tuple;
        this.data = data;
        this.tcpFlags = tcpFlags;
        this.payloadLength = payloadLength;
        this.payloadOffset = payloadOffset;
    }
}