package com.dpi;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PcapReader implements AutoCloseable {

    // Magic numbers for PCAP files
    private static final long PCAP_MAGIC_NATIVE = 0xa1b2c3d4L;
    private static final long PCAP_MAGIC_SWAPPED = 0xd4c3b2a1L;

    // Equivalent to PcapGlobalHeader struct
    public static class PcapGlobalHeader {
        public long magicNumber;
        public int versionMajor;
        public int versionMinor;
        public int thiszone;
        public long sigfigs;
        public long snaplen;
        public long network;
    }

    // Equivalent to PcapPacketHeader struct
    public static class PcapPacketHeader {
        public long tsSec;
        public long tsUsec;
        public long inclLen;
        public long origLen;
    }

    // Equivalent to RawPacket struct
    public static class RawPacket {
        public PcapPacketHeader header = new PcapPacketHeader();
        public byte[] data;
    }

    private FileInputStream file;
    private PcapGlobalHeader globalHeader;
    private boolean needsByteSwap = false;
    private ByteOrder fileByteOrder = ByteOrder.BIG_ENDIAN;

    public boolean open(String filename) {
        close();

        try {
            file = new FileInputStream(filename);
            byte[] globalHeaderBytes = new byte[24];
            
            if (file.read(globalHeaderBytes) < 24) {
                System.err.println("Error: Could not read PCAP global header");
                close();
                return false;
            }

            // Java ByteBuffer defaults to BIG_ENDIAN. We read the magic number to check file endianness.
            ByteBuffer buffer = ByteBuffer.wrap(globalHeaderBytes).order(ByteOrder.BIG_ENDIAN);
            long magic = Integer.toUnsignedLong(buffer.getInt());

            int magicInt = (int) magic;
        switch (magicInt) {
            case (int) PCAP_MAGIC_NATIVE -> {
                needsByteSwap = false;
                fileByteOrder = ByteOrder.BIG_ENDIAN;
                }
            case (int) PCAP_MAGIC_SWAPPED -> {
                needsByteSwap = true;
                fileByteOrder = ByteOrder.LITTLE_ENDIAN;
                // Re-wrap the buffer with the correct byte order so Java does the swapping automatically
                buffer.order(fileByteOrder);
                }
            default -> {
                System.err.println("Error: Invalid PCAP magic number: 0x" + Long.toHexString(magic));
                close();
                return false;
                }
        }

            globalHeader = new PcapGlobalHeader();
            globalHeader.magicNumber = magic;
            globalHeader.versionMajor = Short.toUnsignedInt(buffer.getShort());
            globalHeader.versionMinor = Short.toUnsignedInt(buffer.getShort());
            globalHeader.thiszone = buffer.getInt();
            globalHeader.sigfigs = Integer.toUnsignedLong(buffer.getInt());
            globalHeader.snaplen = Integer.toUnsignedLong(buffer.getInt());
            globalHeader.network = Integer.toUnsignedLong(buffer.getInt());

            System.out.println("Opened PCAP file: " + filename);
            System.out.println("  Version: " + globalHeader.versionMajor + "." + globalHeader.versionMinor);
            System.out.println("  Snaplen: " + globalHeader.snaplen + " bytes");
            System.out.println("  Link type: " + globalHeader.network + (globalHeader.network == 1 ? " (Ethernet)" : ""));

            return true;

        } catch (IOException e) {
            System.err.println("Error: Could not open file: " + filename);
            return false;
        }
    }

    public boolean readNextPacket(RawPacket packet) {
        if (file == null) {
            return false;
        }

        try {
            byte[] headerBytes = new byte[16];
            if (file.read(headerBytes) < 16) {
                return false; // End of file or error
            }

            // Parse the 16-byte packet header using the detected byte order
            ByteBuffer buffer = ByteBuffer.wrap(headerBytes).order(fileByteOrder);
            packet.header.tsSec = Integer.toUnsignedLong(buffer.getInt());
            packet.header.tsUsec = Integer.toUnsignedLong(buffer.getInt());
            packet.header.inclLen = Integer.toUnsignedLong(buffer.getInt());
            packet.header.origLen = Integer.toUnsignedLong(buffer.getInt());

            // Sanity check on packet length
            if (packet.header.inclLen > globalHeader.snaplen || packet.header.inclLen > 65535) {
                System.err.println("Error: Invalid packet length: " + packet.header.inclLen);
                return false;
            }

            // Read the actual packet data bytes
            packet.data = new byte[(int) packet.header.inclLen];
            if (file.read(packet.data) < packet.header.inclLen) {
                System.err.println("Error: Could not read packet data");
                return false;
            }

            return true;

        } catch (IOException e) {
            return false;
        }
    }

    @Override
    public void close() {
        if (file != null) {
            try {
                file.close();
            } catch (IOException e) {
                // Ignore close errors
            }
            file = null;
        }
        needsByteSwap = false;
    }

    public PcapGlobalHeader getGlobalHeader() {
        return globalHeader;
    }

    public boolean isOpen() {
        return file != null;
    }

    public boolean needsByteSwap() {
        return needsByteSwap;
    }
}