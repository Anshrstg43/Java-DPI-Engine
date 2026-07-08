package com.dpi;

public class SniExtractor {

    // ============================================================================
    // TLS SNI Extractor Implementation
    // ============================================================================
    public static class TLS {
        private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
        private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
        private static final int EXTENSION_SNI = 0x0000;
        private static final int SNI_TYPE_HOSTNAME = 0x00;

        private static int readUint16BE(byte[] data, int offset) {
            return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
        }


        public static boolean isTLSClientHello(byte[] payload, int offset, int length) {
            if (length < 9) return false;
            
            if ((payload[offset] & 0xFF) != CONTENT_TYPE_HANDSHAKE) return false;
            
            int version = readUint16BE(payload, offset + 1);
            if (version < 0x0300 || version > 0x0304) return false;
            
            int recordLength = readUint16BE(payload, offset + 3);
            if (recordLength > length - 5) return false;
            
            return (payload[offset + 5] & 0xFF) == HANDSHAKE_CLIENT_HELLO;
        }

        public static String extract(byte[] payload, int baseOffset, int length) {
            if (!isTLSClientHello(payload, baseOffset, length)) {
                return null;
            }
            
            int offset = baseOffset + 5;            
            // Skip handshake header (Type + 3 bytes Length)
            // Skip TLS record header
            offset += 4;
            
            // Client Hello body
            // Bytes 0-1: Client version
            offset += 2;
            
            // Bytes 2-33: Random (32 bytes)
            offset += 32;
            
            // Session ID
            if (offset >= baseOffset + length) return null;
            int sessionIdLength = payload[offset] & 0xFF;
            offset += 1 + sessionIdLength;
            
            // Cipher suites
            if (offset + 2 > baseOffset + length) return null;
            int cipherSuitesLength = readUint16BE(payload, offset);
            offset += 2 + cipherSuitesLength;
            
            // Compression methods
            if (offset >= baseOffset + length) return null;
            int compressionMethodsLength = payload[offset] & 0xFF;
            offset += 1 + compressionMethodsLength;
            
            // Extensions
            if (offset + 2 > baseOffset + length) return null;
            int extensionsLength = readUint16BE(payload, offset);
            offset += 2;
            
            int extensionsEnd = offset + extensionsLength;
            if (extensionsEnd > baseOffset + length) {
                extensionsEnd = baseOffset + length;
            }
            
            while (offset + 4 <= extensionsEnd) {
                int extensionType = readUint16BE(payload, offset);
                int extensionLength = readUint16BE(payload, offset + 2);
                offset += 4;
                
                if (offset + extensionLength > extensionsEnd) break;
                
                if (extensionType == EXTENSION_SNI) {
                    if (extensionLength < 5) break;
                    
                    int sniListLength = readUint16BE(payload, offset);
                    if (sniListLength < 3) break;
                    
                    int sniType = payload[offset + 2] & 0xFF;
                    int sniLength = readUint16BE(payload, offset + 3);
                    
                    if (sniType != SNI_TYPE_HOSTNAME) break;
                    if (sniLength > extensionLength - 5) break;
                    
                    return new String(payload, offset + 5, sniLength);
                }
                
                offset += extensionLength;
            }
            
            return null;
        }
    }

    // ============================================================================
    // HTTP Host Header Extractor Implementation
    // ============================================================================
    public static class HTTP {
        public static boolean isHTTPRequest(byte[] payload, int offset, int length) {
            if (length < 4) return false;
            
            String[] methods = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};
            
            for (String method : methods) {
                boolean match = true;
                for (int i = 0; i < 4; i++) {
                    if (payload[offset + i] != (byte) method.charAt(i)) {
                        match = false;
                        break;
                    }
                }
                if (match) return true;
            }
            return false;
        }

        public static String extract(byte[] payload, int baseOffset, int length) {
            if (!isHTTPRequest(payload, baseOffset, length)) {
                return null;
            }
            
            int hostHeaderLen = 6;
            
            for (int i = baseOffset; i + hostHeaderLen < baseOffset + length; i++) {
                if ((payload[i] == 'H' || payload[i] == 'h') &&
                    (payload[i+1] == 'o' || payload[i+1] == 'O') &&
                    (payload[i+2] == 's' || payload[i+2] == 'S') &&
                    (payload[i+3] == 't' || payload[i+3] == 'T') &&
                    payload[i+4] == ':') {
                    
                    int start = i + 5;
                    while (start < baseOffset + length && (payload[start] == ' ' || payload[start] == '\t')) {
                        start++;
                    }
                    
                    int end = start;
                    while (end < baseOffset + length && payload[end] != '\r' && payload[end] != '\n') {
                        end++;
                    }
                    
                    if (end > start) {
                        String host = new String(payload, start, end - start);
                        int colonPos = host.indexOf(':');
                        if (colonPos != -1) {
                            host = host.substring(0, colonPos);
                        }
                        return host;
                    }
                }
            }
            return null;
        }
    }

    // ============================================================================
    // DNS Extractor Implementation
    // ============================================================================
    public static class DNS {
        public static boolean isDNSQuery(byte[] payload, int offset, int length) {
            if (length < 12) return false;
            
            int flags = payload[offset + 2] & 0xFF;
            if ((flags & 0x80) != 0) return false; 
            
            int qdcount = ((payload[offset + 4] & 0xFF) << 8) | (payload[offset + 5] & 0xFF);
            return qdcount != 0;
        }

        public static String extractQuery(byte[] payload, int baseOffset, int length) {
            if (!isDNSQuery(payload, baseOffset, length)) {
                return null;
            }
            
            int offset = baseOffset + 12;
            StringBuilder domain = new StringBuilder();
            
            while (offset < baseOffset + length) {
                int labelLength = payload[offset] & 0xFF;
                
                if (labelLength == 0) break;
                if (labelLength > 63) break;
                
                offset++;
                if (offset + labelLength > baseOffset + length) break;
                
                if (domain.length() > 0) {
                    domain.append('.');
                }
                domain.append(new String(payload, offset, labelLength));
                offset += labelLength;
            }
            
            return domain.length() == 0 ? null : domain.toString();
        }
    }

    // ============================================================================
    // QUIC SNI Extractor Implementation
    // ============================================================================
    public static class QUIC {
        public static boolean isQUICInitial(byte[] payload, int offset, int length) {
            if (length < 5) return false;
            int firstByte = payload[offset] & 0xFF;
            return (firstByte & 0x80) != 0;
        }

        public static String extract(byte[] payload, int baseOffset, int length) {
            if (!isQUICInitial(payload, baseOffset, length)) {
                return null;
            }
            
            for (int i = baseOffset; i + 50 < baseOffset + length; i++) {
                if (payload[i] == 0x01) {
                    if (i - baseOffset >= 5) {
                        String result = TLS.extract(payload, i - 5, (baseOffset + length) - (i - 5));
                        if (result != null) return result;
                    }
                }
            }
            return null;
        }
    }
}