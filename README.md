# Project 3: Simplified TCP over UDP Implementation - Checkpoint 2

## Overview
This project implements a simplified version of the TCP protocol on top of UDP. For Checkpoint 2, the implementation expands upon Checkpoint 1 by adding the following core features:

1. **Connection Management**: Implements connection establishment (three-way handshake) and termination following a simplified TCP Finite State Machine (FSM).
2. **Flow Control**: Uses a sliding window mechanism to ensure the sender doesn't overwhelm the receiver.
3. **RTT Estimation**: Implements adaptive retransmission timeout using Exponential Weighted Moving Average (EWMA).
4. **Congestion Control**: Implements TCP congestion control mechanisms with slow start, congestion avoidance, and fast retransmit (similar to TCP Tahoe).


## Implementation Details

### Connection Management
The implementation follows the simplified TCP FSM as specified in the project requirements:

- **Connection Establishment (Three-Way Handshake)**:
  - Client sends SYN and transitions to SYN_SENT state
  - Server responds with SYN+ACK and transitions to SYN_RCVD state
  - Client responds with ACK and both sides transition to ESTABLISHED state

- **Connection Termination**:
  - Active close: Initiator sends FIN, transitions to FIN_SENT, waits for ACK or FIN+ACK, then transitions to TIME_WAIT
  - Passive close: Receiver of FIN sends ACK, transitions to CLOSE_WAIT, sends FIN, and transitions to LAST_ACK

The implementation includes:
- Reliable connection establishment with retransmission of SYN and SYN+ACK packets
- Timeout-based retransmission of FIN packets during connection termination
- Proper sequence number management (SYN and FIN each consume one sequence number)
- Handling of simultaneous close scenarios
- Implementation of the 2*MSL wait in TIME_WAIT state
- Proper handling of the final ACK in the three-way handshake

### Flow Control
The flow control mechanism ensures that a sender does not overwhelm a receiver by:

- Tracking the receiver's advertised window size
- Only sending data when there is available space in the receiver's buffer
- Implementing zero window handling with window update notifications
- Enforcing a limit on the total amount of buffered data based on MAX_NETWORK_BUFFER (65535 bytes)

The implementation also includes:
- Window update mechanism when buffer space becomes available (triggered when buffer space increases by 25% or more)
- Zero window probing when the receiver's window is full (approximately 10% chance per wait cycle)
- Handling of out-of-order and duplicate packets with appropriate ACK responses
- Buffer management to ensure the receive buffer doesn't exceed the MAX_NETWORK_BUFFER limit

### RTT Estimation
The RTT estimation follows the original TCP algorithm using an Exponential Weighted Moving Average (EWMA):

- EstimatedRTT = α × EstimatedRTT + (1 - α) × SampleRTT
- TimeOut = 2 × EstimatedRTT

Where α is set to 0.875 (7/8) as a reasonable value to balance stability and responsiveness. This implementation:
- Tracks sent packets and their timestamps using a "send_times" dictionary
- Updates RTT when ACKs are received, calculating sample RTT from the recorded send time
- Handles the first RTT measurement differently to initialize the SRTT value
- Adjusts the retransmission timeout dynamically based on the calculated EWMA
- Ensures the timeout doesn't exceed the DEFAULT_TIMEOUT (3 seconds)
- Skips very small RTT measurements (< 1ms) which may be due to delayed ACKs

## Congestion Control Details

### TCP Tahoe Implementation
The implementation follows TCP Tahoe's approach to congestion control:

1. **Initialization**:
   - Initial congestion window (cwnd): 1 MSS (WINDOW_INITIAL_WINDOW_SIZE)
   - Initial slow start threshold (ssthresh): 64 MSS (WINDOW_INITIAL_SSTHRESH)

2. **Slow Start Phase**:
   - cwnd increases by 1 MSS for each ACK received
   - This leads to exponential growth: cwnd doubles approximately every RTT
   - When cwnd reaches or exceeds ssthresh, transition to congestion avoidance

3. **Congestion Avoidance Phase**:
   - cwnd increases by approximately 1 MSS per RTT (implemented by counting acknowledged segments)
   - Provides a more conservative linear growth compared to slow start

4. **Loss Detection and Recovery**:
   - Timeout detection: If no ACK is received within the retransmission timeout (RTO)
   - Triple duplicate ACK detection: Fast retransmit is triggered on receiving 3 duplicate ACKs
   - For both timeout and triple duplicate ACKs:
     - ssthresh = max(cwnd/2, 2*MSS)
     - cwnd = WINDOW_INITIAL_WINDOW_SIZE (1 MSS)
     - Return to slow start state

5. **Effective Window Calculation**:
   - The sending window is the minimum of the congestion window and the receiver's advertised window
   - This ensures respect for both congestion control and flow control constraints

### Flow Control Integration
The implementation carefully integrates flow control with congestion control:
- Advertised window reflects available buffer space at the receiver
- Zero window handling prevents overwhelming the receiver
- Window updates inform the sender when more buffer space becomes available
- The effective sending window respects both congestion and flow control limits

## Assumptions and Implementation Details

1. **Fixed Header Length**: The implementation assumes a fixed header length for all packets.
2. **In-Order Delivery**: The implementation acknowledges out-of-order packets but only processes in-order segments.
3. **Maximum Buffer Size**: The implementation enforces the MAX_NETWORK_BUFFER limit (65535 bytes) for the receive buffer.
4. **Fast Retransmit**: The implementation includes triple duplicate ACK detection and fast retransmit functionality.
5. **Segment Size**: The implementation uses MSS derived from MAX_LEN minus the header size.
6. **Retransmission Handling**: Implements timeout-based retransmission for both control packets (SYN, FIN) and data segments.
7. **TIME_WAIT State**: Uses a 2*MSL (Maximum Segment Lifetime) timeout for the TIME_WAIT state.
8. **TCP Tahoe Behavior**: Implements TCP Tahoe congestion control without fast recovery.

## Running the Code

### Requirements
- Python 3.6 or higher
- Standard Python libraries (socket, struct, threading, time, random)
- No external dependencies required

### Environment Information
- Tested on Python 3.8+
- Compatible with Linux, macOS, and Windows

### Running the Server
```bash
python server.py
```

### Running the Client
```bash
python client.py
```

### Testing with Network Conditions
You can test the TCP implementation with different network conditions using Linux `tc` (traffic control) command:

```bash
# Add 100ms delay and 10% packet loss
sudo tc qdisc add dev lo root netem delay 100ms loss 10%

# Add 200ms delay and 20% packet loss (more challenging scenario)
sudo tc qdisc add dev lo root netem delay 200ms loss 20%

# Remove the network emulation
sudo tc qdisc del dev lo root netem
```

### Observing Congestion Control
The implementation logs detailed information about congestion control events:
- Current congestion state (slow start or congestion avoidance)
- Congestion window (cwnd) size
- Slow start threshold (ssthresh) value
- Transitions between states
- Window adjustments after acknowledgments or losses

Watch for these log messages to understand how the congestion control algorithm responds to network conditions.

### Using Wireshark for Analysis
The project includes a Wireshark dissector (`tcp_over_udp.lua`) that can be used to analyze the TCP over UDP packets:

1. Copy the tcp_over_udp.lua file to your Wireshark Lua plugins folder
2. In Wireshark, go to Analyze > Reload Lua Plugins
3. Start capturing on the loopback interface
4. Filter by `udp.srcport == 54321 || udp.dstport == 54321` to see only the "TCP over UDP" traffic

Using Wireshark with the custom dissector allows you to:
- Observe packet sequences and retransmissions
- Track acknowledgment patterns and duplicate ACKs
- View the advertised window sizes
- Analyze the protocol's behavior under different network conditions

## Implementation Specifics

### FSM States
The implementation uses the following state constants for the TCP Finite State Machine:
- CLOSED = 0
- LISTEN = 1
- SYN_SENT = 2
- SYN_RCVD = 3
- ESTABLISHED = 4
- FIN_SENT = 5
- CLOSE_WAIT = 6
- LAST_ACK = 7
- TIME_WAIT = 8

### Window Management
The implementation maintains a comprehensive window structure with the following key components:
- `last_ack`: The next sequence number expected from the peer
- `next_seq_expected`: The highest acknowledged sequence number received
- `recv_buf`: Buffer for received data
- `recv_len`: Number of bytes in the receive buffer
- `next_seq_to_send`: Next sequence number to use when sending
- `send_base`: Base of the sending window (oldest unacknowledged byte)
- `in_flight`: Number of bytes that have been sent but not yet acknowledged
- `packets_in_flight`: Dictionary tracking outstanding packets
- `peer_adv_window`: Peer's currently advertised window size
- `last_window_update`: When the local window was last updated
- `outstanding_segs`: Count of outstanding segments
- `dup_ack_count`: Counter for duplicate ACKs (for fast retransmit)

### Congestion Control Parameters
The implementation maintains a congestion control structure with these key components:
- `cwnd`: Congestion window size, initially set to WINDOW_INITIAL_WINDOW_SIZE (1 MSS)
- `ssthresh`: Slow start threshold, initially set to WINDOW_INITIAL_SSTHRESH (64 MSS)
- `state`: Current congestion state ("slow_start" or "congestion_avoidance")
- `segments_acked`: Counter for tracking acknowledged segments in congestion avoidance

### Sliding Window Management
The effective send window is calculated as the minimum of:
1. The congestion window (`cwnd`)
2. The receiver's advertised window (`peer_adv_window`)

This ensures that data transmission respects both congestion control and flow control constraints.

## Additional Notes

### Packet Header Format
The implementation uses a custom packet header with the following fields:
- Sequence Number (32 bits): Identifies the first byte in the payload
- Acknowledgment Number (32 bits): Next expected byte from the sender
- Flags (8 bits): Control flags with the following bit assignments:
  - SYN_FLAG = 0x8 (Synchronization flag)
  - ACK_FLAG = 0x4 (Acknowledgment flag)
  - FIN_FLAG = 0x2 (Finish flag)
  - SACK_FLAG = 0x1 (Selective Acknowledgment flag)
- Advertised Window (16 bits): Receiver's available buffer size for flow control

## Congestion Control Implementation

### Congestion Control State Machine
The implementation follows TCP Tahoe's congestion control mechanism with the following components:

1. **Slow Start**:
   - Initial congestion window (cwnd) is set to WINDOW_INITIAL_WINDOW_SIZE (1 MSS)
   - For each ACK received, cwnd increases by 1 MSS
   - When cwnd exceeds ssthresh, the algorithm transitions to congestion avoidance
   - This allows exponential growth (doubling per RTT) of the congestion window

2. **Congestion Avoidance**:
   - When in congestion avoidance, cwnd increases by approximately 1 MSS per RTT
   - This is implemented by tracking segments acknowledged and increasing cwnd by 1 MSS when enough segments have been acknowledged
   - This creates a linear growth pattern, more conservative than slow start

3. **Loss Detection and Recovery**:
   - Timeout-based loss detection: If a packet isn't acknowledged within the RTO, it's considered lost
   - Triple duplicate ACK detection: If 3 duplicate ACKs are received, fast retransmit is triggered
   - When loss is detected (either by timeout or triple duplicate ACKs):
     - ssthresh is set to half of the current cwnd (minimum 2*MSS)
     - cwnd is reset to initial window size (1 MSS)
     - Algorithm returns to slow start state