Java Deep Packet Inspection (DPI) Engine :
A high-performance, multi-threaded, stateful firewall and Deep Packet Inspection (DPI) engine implemented entirely in Java. This project processes raw .pcap network traffic files, tracks connection states, extracts application-layer data (like TLS SNI hostnames), and applies dynamic firewall blocking rules.

Originally modeled after enterprise C++ DPI architectures, this Java port utilizes lock-free concepts, concurrent data structures, and raw byte manipulation (java.nio.ByteBuffer) to achieve optimal throughput.

🚀 Features: 
Multi-Threaded Architecture: Utilizes a Producer-Consumer model with dedicated Load Balancer (LB) and Fast Path (FP) threads.

Dynamic Thread Scaling: Configure the exact number of Load Balancers and Fast Path threads at runtime via CLI arguments.

Consistent Hashing: Load balancers distribute packets to processing threads using 5-tuple hashing, ensuring packets from the same connection always hit the same thread.

Stateful Connection Tracking: Maintains a high-performance flow table to track the state of TCP/UDP connections (NEW, ESTABLISHED, BLOCKED).

Application Layer Parsing: Extracts Server Name Indication (SNI) from TLS Client Hello packets to identify destination domains.

Dynamic Firewall Rules: Loads blocking rules from an external text file to block specific IPs, Ports, Applications, or Domains without recompilation.

Performance Optimizations: Drops subsequent packets of blocked connections instantly via state lookups, eliminating redundant deep inspection overhead.

🧠 Architecture Overview :
PCAP Reader: Reads raw binary data from standard .pcap files.

Load Balancers (LB): Calculates a hash based on the packet's Source IP, Destination IP, Source Port, Destination Port, and Protocol (5-Tuple).

Thread-Safe Queues: Safely passes parsed PacketJob objects from LBs to FPs.

Fast Path Processors (FP): Pops packets from the queue, updates the state in the ConnectionTracker, performs SNI extraction, and checks the RuleManager.

Output Writer: Forwards benign packets to a new output .pcap file and drops blocked packets.

📂 Project Structure :
DpiEngine.java: The main orchestrator that initializes managers, thread pools, and the parsing pipeline.

LoadBalancer.java: Distributes incoming packets to processing queues.

FPManager.java & FastPathProcessor.java: Thread managers and core packet processing logic.

ConnectionTracker.java: The stateful flow table memory.

RuleManager.java: Handles the loading and checking of firewall blocklists.

PacketParser.java & SniExtractor.java: Low-level byte array parsing for Ethernet, IP, TCP, UDP, and TLS layers.

PcapReader.java: Binary ingestion utility for .pcap formats.

ThreadSafeQueue.java: Custom synchronization queue for safe thread handoffs.

Types.java & PacketJob.java: Core data structures and enumerations.

⚙️ Prerequisites :
Java Development Kit (JDK): Version 11 or higher.

A sample .pcap file containing network traffic (e.g., test_dpi.pcap).

🛠️ Build and Run :
1. Compile the Project
Navigate to the root directory of the project and compile all Java files:

javac src/main/java/com/dpi/*.java
2. Configure Firewall Rules
Create a rules.txt file in the root directory to define what the firewall should drop.

[BLOCKED_DOMAINS]
www.youtube.com
www.facebook.com

[BLOCKED_PORTS]
23

3. Execute the Engine
Run the compiled engine. You can dynamically scale the architecture using the `--lbs` (Load Balancers) and `--fps` (Fast Paths per LB) flags:
# Default run (2 LBs, 2 FPs per LB = 4 total threads)
java -cp src/main/java com.dpi.DpiEngine test_dpi.pcap output.pcap

# High-performance run (4 LBs, 4 FPs per LB = 16 total processing threads)
java -cp src/main/java com.dpi.DpiEngine test_dpi.pcap output.pcap --lbs 4 --fps 4

📊 Sample Output :
Upon successful execution, the engine generates an ASCII statistics report detailing the packet processing and connection distributions:

╔══════════════════════════════════════════════════════════════╗
║                    DPI ENGINE STATISTICS                     ║
╠══════════════════════════════════════════════════════════════╣
║ PACKET STATISTICS                                            ║
║   Total Packets:                77                           ║
║   Total Bytes:                5738                           ║
║   TCP Packets:                  77                           ║
║   UDP Packets:                   0                           ║
╠══════════════════════════════════════════════════════════════╣
║ FILTERING STATISTICS                                         ║
║   Forwarded:                    75                           ║
║   Dropped/Blocked:               2                           ║
║   Drop Rate:                  2.60%                          ║
╚══════════════════════════════════════════════════════════════╝
👤 Author
Anshul Rastogi
Built for advanced networking and systems architecture study.