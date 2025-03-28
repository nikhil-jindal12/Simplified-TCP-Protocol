# Project 3: Simplified TCP over UDP Implementation - Checkpoint 1

## Overview
This project implements a simplified version of the TCP protocol on top of UDP. The implementation supports the following core features:

1. **Connection Management**: Implements connection establishment (three-way handshake) and termination following a simplified TCP Finite State Machine (FSM).
2. **Flow Control**: Uses a sliding window mechanism to ensure the sender doesn't overwhelm the receiver.
3. **RTT Estimation**: Implements adaptive retransmission timeout using Exponential Weighted Moving Average (EWMA).

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

# Remove the network emulation
sudo tc qdisc del dev lo root netem
```

### Using Wireshark for Analysis
The project includes a Wireshark dissector (tcp_over_udp.lua) that can be used to analyze the TCP over UDP packets:

1. Copy the tcp_over_udp.lua file to your Wireshark Lua plugins folder
2. In Wireshark, go to Analyze > Reload Lua Plugins
3. Start capturing on the loopback interface
4. Filter by `udp.srcport == 54321 || udp.dstport == 54321` to see only the TCP over UDP traffic