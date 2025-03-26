import socket
import struct
import threading
import time  
from grading import MSS, DEFAULT_TIMEOUT, MAX_NETWORK_BUFFER

# Constants for simplified TCP
SYN_FLAG = 0x8   # Synchronization flag 
ACK_FLAG = 0x4   # Acknowledgment flag
FIN_FLAG = 0x2   # Finish flag 
SACK_FLAG = 0x1  # Selective Acknowledgment flag 

# FSM state constants
CLOSED = 0
LISTEN = 1
SYN_SENT = 2
SYN_RCVD = 3
ESTABLISHED = 4
FIN_SENT = 5
CLOSE_WAIT = 6
LAST_ACK = 7
TIME_WAIT = 8

EXIT_SUCCESS = 0
EXIT_ERROR = 1

SAFE_MSS = 1024


class ReadMode:
    NO_FLAG = 0
    NO_WAIT = 1
    TIMEOUT = 2


class Packet:
    def __init__(self, seq=0, ack=0, flags=0, adv_window=MAX_NETWORK_BUFFER, payload=b""):
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.adv_window = adv_window
        self.payload = payload
        self.checksum = self.calculate_checksum()

    def calculate_checksum(self):
        """Simple checksum to verify packet integrity"""
        checksum = (self.seq + self.ack + self.flags + self.adv_window) & 0xFFFF
        for i in range(0, len(self.payload), 2):
            if i + 1 < len(self.payload):
                checksum += (self.payload[i] << 8) + self.payload[i+1]
            else:
                checksum += self.payload[i] << 8
        return checksum & 0xFFFF

    def encode(self):
        # Add checksum to the packet header
        header = struct.pack("!IIIHH", self.seq, self.ack, self.flags, self.adv_window, self.checksum)
        return header + self.payload

    @staticmethod
    def decode(data):
        # Extract and verify checksum
        header_size = struct.calcsize("!IIIHH")
        if len(data) < header_size:
            raise ValueError("Packet too small to contain header")
        
        seq, ack, flags, adv_window, received_checksum = struct.unpack("!IIIHH", data[:header_size])
        payload = data[header_size:]
        
        # Create packet without setting checksum
        packet = Packet(seq, ack, flags, adv_window, payload)
        calculated_checksum = packet.calculate_checksum()
        
        # Verify checksum
        if calculated_checksum != received_checksum:
            print(f"Warning: Checksum mismatch (received: {received_checksum}, calculated: {calculated_checksum})")
        
        return packet


class TransportSocket:
    def __init__(self):
        self.sock_fd = None

        # Locks and condition
        self.recv_lock = threading.Lock()
        self.send_lock = threading.Lock()
        self.wait_cond = threading.Condition(self.recv_lock)

        self.death_lock = threading.Lock()
        self.dying = False
        self.thread = None
        
        # FSM state
        self.state = CLOSED
        
        # Add RTT estimation
        self.rtt_stats = {
            "srtt": 0,          # Smoothed RTT
            "rttvar": 0,        # RTT variance
            "rto": DEFAULT_TIMEOUT,  # Retransmission timeout
            "alpha": 0.125,     # EWMA weight for SRTT
            "beta": 0.25,       # EWMA weight for RTTVAR
            "send_times": {},   # Track send times of packets for RTT measurement
        }

        # Enhanced window management
        self.window = {
            "last_ack": 0,            # The next seq we expect from peer
            "next_seq_expected": 0,   # The highest ack we've received
            "recv_buf": b"",          # Received data buffer
            "recv_len": 0,            # How many bytes are in recv_buf
            "next_seq_to_send": 0,    # Next sequence number to send
            "send_base": 0,           # Base of sending window (oldest unacked byte)
            "in_flight": 0,           # Bytes in flight (sent but not acked)
            "packets_in_flight": {},  # Track packets in flight {seq: (packet, send_time)}
            "peer_adv_window": MAX_NETWORK_BUFFER,  # Peer's advertised window
            "last_window_update": 0,  # When we last updated our adv_window
        }
        self.sock_type = None
        self.conn = None
        self.my_port = None

    def socket(self, sock_type, port, server_ip=None):
        """
        Create and initialize the socket, setting its type and starting the backend thread.
        """
        self.sock_fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_type = sock_type

        if sock_type == "TCP_INITIATOR":
            self.conn = (server_ip, port)
            self.sock_fd.bind(("", 0))  # Bind to any available local port
            self.state = CLOSED         # Client starts in CLOSED state
        elif sock_type == "TCP_LISTENER":
            self.sock_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock_fd.bind(("", port))
            self.state = LISTEN         # Server starts in LISTEN state
        else:
            print(str(time.time()), "Unknown socket type")
            return EXIT_ERROR

        # 1-second timeout so we can periodically check `self.dying`
        self.sock_fd.settimeout(1.0)

        self.my_port = self.sock_fd.getsockname()[1]

        # Start the backend thread
        self.thread = threading.Thread(target=self.backend, daemon=True)
        self.thread.start()
        return EXIT_SUCCESS

    def close(self):
        """
        Close the socket and stop the backend thread.
        """
        # Handle connection termination based on the current state
        if self.state == ESTABLISHED:
            self.terminate_connection()
        
        # Tell the backend threat to stop
        self.death_lock.acquire()
        try:
            self.dying = True
        finally:
            self.death_lock.release()

        if self.thread:
            self.thread.join()

        if self.sock_fd:
            self.sock_fd.close()
        else:
            print(str(time.time()), "Error: Null socket")
            return EXIT_ERROR

        return EXIT_SUCCESS

    def send(self, data):
        """
        Send data reliably to the peer (with sliding window).
        """
        if not self.conn:
            raise ValueError("Connection not established.")

        # Handle connection establishment for client
        if self.state == CLOSED and self.sock_type == "TCP_INITIATOR":
            self.establish_connection()

        # Only send data if we're in ESTABLISHED state
        if self.state != ESTABLISHED:
            raise ValueError(f"Cannot send data in state {self.state}")

        with self.send_lock:
            self.send_segment(data)

    def recv(self, buf, length, flags):
        """
        Retrieve received data from the buffer, with optional blocking behavior.

        :param buf: Buffer to store received data (list of bytes or bytearray).
        :param length: Maximum length of data to read
        :param flags: ReadMode flag to control blocking behavior
        :return: Number of bytes read
        """
        read_len = 0

        if length < 0:
            print(str(time.time()), "ERROR: Negative length")
            return EXIT_ERROR

        # If blocking read, wait until there's data in buffer
        if flags == ReadMode.NO_FLAG:
            with self.wait_cond:
                while self.window["recv_len"] == 0:
                    # If we're in CLOSE_WAIT and buffer is empty, return 0 (EOF)
                    if self.state == CLOSE_WAIT:
                        return 0
                    self.wait_cond.wait()

        self.recv_lock.acquire()
        try:
            if flags in [ReadMode.NO_WAIT, ReadMode.NO_FLAG]:
                if self.window["recv_len"] > 0:
                    read_len = min(self.window["recv_len"], length)
                    buf[0] = self.window["recv_buf"][:read_len]

                    # Remove data from the buffer
                    if read_len < self.window["recv_len"]:
                        self.window["recv_buf"] = self.window["recv_buf"][read_len:]
                        self.window["recv_len"] -= read_len
                    else:
                        self.window["recv_buf"] = b""
                        self.window["recv_len"] = 0
                    
                    # Check if we've drained enough buffer to issue a window update
                    current_time = time.time()
                    available_space = MAX_NETWORK_BUFFER - self.window["recv_len"]
                    
                    # Send window update if we've freed significant space or it's been a while
                    if (available_space > MAX_NETWORK_BUFFER / 2 and 
                        current_time - self.window["last_window_update"] > 0.1):
                        
                        if self.conn:  # Make sure we have a peer to send to
                            # Send a window update ACK
                            window_update = Packet(
                                seq=self.window["next_seq_to_send"], 
                                ack=self.window["last_ack"], 
                                flags=ACK_FLAG, 
                                adv_window=available_space
                            )
                            self.sock_fd.sendto(window_update.encode(), self.conn)
                            self.window["last_window_update"] = current_time
                            print(f"Sent window update: adv_window={available_space}")
            else:
                print(str(time.time()), "ERROR: Unknown or unimplemented flag.")
                read_len = EXIT_ERROR
        finally:
            self.recv_lock.release()

        return read_len

    def send_segment(self, data):
        """
        Send 'data' in multiple smaller segments with flow control
        """
        offset = 0
        total_len = len(data)

        # While there's data left to send
        while offset < total_len:
            with self.wait_cond:
                # Wait for window space to be available
                while self.window["in_flight"] >= self.window["peer_adv_window"]:
                    print(f"Flow control: waiting for window space (in_flight={self.window['in_flight']}, peer_window={self.window['peer_adv_window']})")
                    self.wait_cond.wait(timeout=0.1)
                    if self.dying:
                        return
                
                # Use a smaller MSS to avoid fragmentation
                available_window = self.window["peer_adv_window"] - self.window["in_flight"]
                payload_len = min(SAFE_MSS, total_len - offset, available_window)
                
                if payload_len <= 0:
                    continue
                    
                # Get sequence number for this segment
                seq_no = self.window["next_seq_to_send"]
                chunk = data[offset:offset + payload_len]
                
                # Create and send packet
                segment = Packet(
                    seq=seq_no, 
                    ack=self.window["last_ack"], 
                    flags=0, 
                    adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"],
                    payload=chunk
                )
                
                print(f"Sending segment (seq={seq_no}, len={payload_len}, window={available_window})")
                self.sock_fd.sendto(segment.encode(), self.conn)
                
                # Update window tracking
                self.window["next_seq_to_send"] += payload_len
                self.window["in_flight"] += payload_len
                self.rtt_stats["send_times"][seq_no] = time.time()
                self.window["packets_in_flight"][seq_no] = (segment, time.time())
                
                # Wait for ACK with a timeout
                start_wait = time.time()
                acked = False
                
                while not acked and seq_no in self.window["packets_in_flight"]:
                    # Check for timeout and retransmit if needed
                    current_time = time.time()
                    if current_time - self.window["packets_in_flight"][seq_no][1] > self.rtt_stats["rto"]:
                        print(f"Timeout: Retransmitting segment (seq={seq_no}, len={payload_len})")
                        self.sock_fd.sendto(segment.encode(), self.conn)
                        self.window["packets_in_flight"][seq_no] = (segment, current_time)
                    
                    # Wait for a short time to check for ACKs
                    self.wait_cond.wait(timeout=0.1)
                    
                    # Check if this packet has been acknowledged
                    if seq_no not in self.window["packets_in_flight"]:
                        acked = True
                        break
                    
                    # Give up after reasonable timeout to avoid deadlock
                    if current_time - start_wait > 10:  # 10 seconds total timeout
                        print("Giving up on waiting for ACK after 10 seconds")
                        # Remove from in-flight accounting so we can continue
                        if seq_no in self.window["packets_in_flight"]:
                            del self.window["packets_in_flight"][seq_no]
                        self.window["in_flight"] = max(0, self.window["in_flight"] - payload_len)
                        break
                
                # Move to next segment
                offset += payload_len
        
    def wait_for_all_acks(self):
        """
        Wait until all packets in flight have been acknowledged
        """
        with self.wait_cond:
            last_progress_time = time.time()
            
            while self.window["packets_in_flight"]:
                # Check for timeout and retransmit if needed
                current_time = time.time()
                with self.recv_lock:
                    # Find packets that need retransmission
                    for seq, (packet, send_time) in list(self.window["packets_in_flight"].items()):
                        if current_time - send_time > self.rtt_stats["rto"]:
                            print(f"Retransmitting segment (seq={seq}, len={len(packet.payload)})")
                            self.sock_fd.sendto(packet.encode(), self.conn)
                            # Update send time
                            self.window["packets_in_flight"][seq] = (packet, current_time)
                            last_progress_time = current_time
                
                # Give up if we've been waiting too long with no progress
                if current_time - last_progress_time > 30:  # 30 seconds timeout
                    print("Giving up waiting for ACKs after 30 seconds")
                    break
                    
                # Wait for ACKs
                self.wait_cond.wait(timeout=0.1)

    def wait_for_ack(self, ack_goal):
        """
        Wait for 'next_seq_expected' to reach or exceed 'ack_goal' within DEFAULT_TIMEOUT.
        Return True if ack arrived in time; False on timeout.
        """
        with self.recv_lock:
            start = time.time()
            timeout = self.rtt_stats["rto"]
            while self.window["next_seq_expected"] < ack_goal:
                elapsed = time.time() - start
                remaining = timeout - elapsed
                if remaining <= 0:
                    return False

                self.wait_cond.wait(timeout=remaining)
                
                # return early if socket is closing
                if self.dying:
                    return False

            return True

    def backend(self):
        """
        Backend loop to handle receiving data and sending acknowledgments.
        All incoming packets are read in this thread only, to avoid concurrency conflicts.
        """
        while not self.dying:
            try:
                data, addr = self.sock_fd.recvfrom(2048)
                
                if len(data) == 2048:
                    print(str(time.time()), "Warning: Received max packet size of 2048 bytes, data might be truncated")
                
                packet = Packet.decode(data)

                # If no peer is set, establish connection (for listener)
                if self.conn is None:
                    self.conn = addr
                    
                # Update peer advertised window for flow control
                self.window["peer_adv_window"] = packet.adv_window

                # Connection establishment handling
                if self.state == LISTEN and (packet.flags & SYN_FLAG) != 0:
                    # Received SYN in LISTEN state
                    with self.recv_lock:
                        print(f"{time.time()} Received SYN from {addr}")
                        
                        # SYN consumes one sequence number, so next expected byte is packet.seq + 1
                        self.window["last_ack"] = packet.seq + 1
                        
                        # Initialize our own sequence number for this connection
                        initial_seq = 0  # For simplicity; could be random
                        
                        # Send SYN+ACK
                        syn_ack = Packet(
                            seq=initial_seq, 
                            ack=self.window["last_ack"], 
                            flags=SYN_FLAG | ACK_FLAG, 
                            adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                        )
                        self.sock_fd.sendto(syn_ack.encode(), addr)
                        
                        # Update our sequence numbers
                        # After sending SYN, our next sequence number is initial_seq + 1
                        self.window["next_seq_to_send"] = initial_seq + 1
                        self.window["send_base"] = initial_seq + 1
                        self.window["send_next"] = initial_seq + 1
                        
                        # Transition to SYN_RCVD
                        self.state = SYN_RCVD
                        self.wait_cond.notify_all()
                    continue

                elif self.state == SYN_SENT and (packet.flags & SYN_FLAG) != 0 and (packet.flags & ACK_FLAG) != 0:
                    # Received SYN+ACK in SYN_SENT state
                    with self.recv_lock:
                        print(f"{time.time()} Received SYN+ACK from {addr}")
                        
                        # SYN consumes one sequence number, so next expected byte is packet.seq + 1
                        self.window["last_ack"] = packet.seq + 1
                        
                        # Our own SYN consumes one sequence number as well
                        # The acknowledgment (packet.ack) should be our initial seq + 1
                        initial_seq = self.window["next_seq_to_send"]
                        if packet.ack == initial_seq + 1:
                            # Update RTT estimation
                            if initial_seq in self.rtt_stats["send_times"]:
                                self.update_rtt(initial_seq)
                            
                            # Send ACK (final handshake step)
                            ack_packet = Packet(
                                seq=packet.ack,  # This is our next sequence number (initial_seq + 1)
                                ack=self.window["last_ack"], 
                                flags=ACK_FLAG, 
                                adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                            )
                            self.sock_fd.sendto(ack_packet.encode(), addr)
                            
                            # Update sequence numbers for data transmission
                            # After the SYN, our sequence numbers start at initial_seq + 1
                            self.window["next_seq_to_send"] = packet.ack
                            self.window["next_seq_expected"] = packet.ack
                            self.window["send_base"] = packet.ack
                            self.window["send_next"] = packet.ack
                            
                            # Transition to ESTABLISHED
                            self.state = ESTABLISHED
                            self.wait_cond.notify_all()
                        else:
                            print(f"Invalid ACK: expected {initial_seq + 1}, got {packet.ack}")
                    continue

                elif self.state == SYN_RCVD and (packet.flags & ACK_FLAG) != 0:
                    # Received ACK in SYN_RCVD state (completing three-way handshake)
                    with self.recv_lock:
                        print(f"{time.time()} Received ACK from {addr}, handshake complete")
                        
                        # The client is acknowledging our SYN
                        expected_ack = self.window["send_base"]
                        if packet.ack == expected_ack:
                            # Transition to ESTABLISHED
                            self.state = ESTABLISHED
                            self.wait_cond.notify_all()
                            
                            print(f"Window update: base={self.window['send_base']}, next={self.window['send_next']}, " +
                                f"in_flight={len(self.window['packets_in_flight']) if 'packets_in_flight' in self.window else 0}, adv_window={packet.adv_window}")
                        else:
                            print(f"Invalid ACK: expected {expected_ack}, got {packet.ack}")
                    continue

                # Connection termination handling
                elif self.state == ESTABLISHED and (packet.flags & FIN_FLAG) != 0:
                    # Received FIN in ESTABLISHED state (passive close)
                    with self.recv_lock:
                        print(str(time.time()), f"Received FIN from {addr}")
                        self.window["last_ack"] = packet.seq + 1
                        
                        # Send ACK
                        ack_packet = Packet(
                            seq=self.window["next_seq_to_send"], 
                            ack=self.window["last_ack"], 
                            flags=ACK_FLAG, 
                            adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                        )
                        self.sock_fd.sendto(ack_packet.encode(), addr)
                        
                        # Transition to CLOSE_WAIT
                        self.state = CLOSE_WAIT
                        self.wait_cond.notify_all()
                        
                        # Immediately send FIN and transition to LAST_ACK
                        # This is a simplification where we don't wait for application to close
                        fin_packet = Packet(
                            seq=self.window["next_seq_to_send"], 
                            ack=self.window["last_ack"], 
                            flags=FIN_FLAG, 
                            adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                        )
                        self.sock_fd.sendto(fin_packet.encode(), addr)
                        self.state = LAST_ACK
                    continue

                elif self.state == FIN_SENT and (packet.flags & ACK_FLAG) != 0:
                    # Received ACK in FIN_SENT state
                    with self.recv_lock:
                        print(str(time.time()), f"Received ACK for FIN from {addr}")
                        
                        # Only transition if this is an ACK for our FIN
                        if packet.ack > self.window["next_seq_expected"]:
                            self.window["next_seq_expected"] = packet.ack
                            self.state = TIME_WAIT
                            self.wait_cond.notify_all()
                            
                            # Schedule transition to CLOSED after 2*MSL
                            threading.Timer(2 * DEFAULT_TIMEOUT, self.time_wait_timeout).start()
                    continue

                elif self.state == FIN_SENT and (packet.flags & FIN_FLAG) != 0:
                    # Received FIN in FIN_SENT state (simultaneous close)
                    with self.recv_lock:
                        print(str(time.time()), f"Received FIN from {addr} (simultaneous close)")
                        self.window["last_ack"] = packet.seq + 1
                        
                        # Send ACK
                        ack_packet = Packet(
                            seq=self.window["next_seq_to_send"], 
                            ack=self.window["last_ack"], 
                            flags=ACK_FLAG, 
                            adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                        )
                        self.sock_fd.sendto(ack_packet.encode(), addr)
                        
                        # Transition to TIME_WAIT
                        self.state = TIME_WAIT
                        self.wait_cond.notify_all()
                        
                        # Schedule transition to CLOSED after 2*MSL
                        threading.Timer(2 * DEFAULT_TIMEOUT, self.time_wait_timeout).start()
                    continue

                elif self.state == LAST_ACK and (packet.flags & ACK_FLAG) != 0:
                    # Received ACK in LAST_ACK state (completing passive close)
                    with self.recv_lock:
                        print(str(time.time()), f"Received final ACK from {addr}")
                        self.state = CLOSED
                        self.wait_cond.notify_all()
                    continue

                # Data packet handling (ACK packets with or without data)
                if (packet.flags & ACK_FLAG) != 0:
                    with self.recv_lock:
                        # Check if this ACK advances our window
                        if packet.ack > self.window["next_seq_expected"]:
                            # Calculate how many bytes were acknowledged
                            acked_bytes = packet.ack - self.window["next_seq_expected"]
                            self.window["next_seq_expected"] = packet.ack
                            
                            # Update peer's advertised window
                            self.window["peer_adv_window"] = packet.adv_window
                            
                            # Update in-flight data count
                            self.window["in_flight"] = max(0, self.window["in_flight"] - acked_bytes)
                            
                            # Remove acknowledged packets from in-flight list
                            for seq in list(self.window["packets_in_flight"].keys()):
                                pkt, _ = self.window["packets_in_flight"][seq]
                                if seq + len(pkt.payload) <= packet.ack:
                                    # Update RTT estimation
                                    if seq in self.rtt_stats["send_times"]:
                                        self.update_rtt(seq)
                                    # Remove from in-flight list
                                    del self.window["packets_in_flight"][seq]
                            
                            print(f"Window update: base={self.window['next_seq_expected']}, " +
                                f"in_flight={self.window['in_flight']}, adv_window={packet.adv_window}")
                            
                            # Notify any waiting sender
                            self.wait_cond.notify_all()

                # Data packet processing (if in ESTABLISHED state)
                if self.state in [ESTABLISHED, CLOSE_WAIT] and len(packet.payload) > 0:
                    with self.recv_lock:
                        # Check if this packet is within our receive window
                        if packet.seq == self.window["last_ack"]:
                            # Check if we have space in the receive buffer
                            available_space = MAX_NETWORK_BUFFER - self.window["recv_len"]
                            
                            if available_space >= len(packet.payload):
                                # Append payload to our receive buffer
                                self.window["recv_buf"] += packet.payload
                                self.window["recv_len"] += len(packet.payload)
                                
                                print(f"Received data segment {packet.seq} with {len(packet.payload)} bytes.")
                                
                                # Update last_ack
                                self.window["last_ack"] = packet.seq + len(packet.payload)
                                
                                # Calculate new advertised window
                                adv_window = MAX_NETWORK_BUFFER - self.window["recv_len"]
                                
                                # Send ACK with current window advertisement
                                ack_packet = Packet(
                                    seq=self.window["next_seq_to_send"], 
                                    ack=self.window["last_ack"], 
                                    flags=ACK_FLAG, 
                                    adv_window=adv_window
                                )
                                self.sock_fd.sendto(ack_packet.encode(), addr)
                                
                                self.wait_cond.notify_all()
                            else:
                                # Buffer full, send ACK with reduced window
                                print(f"Receive buffer limited: {available_space} bytes available")
                                ack_packet = Packet(
                                    seq=self.window["next_seq_to_send"], 
                                    ack=self.window["last_ack"], 
                                    flags=ACK_FLAG, 
                                    adv_window=available_space
                                )
                                self.sock_fd.sendto(ack_packet.encode(), addr)
                        elif packet.seq > self.window["last_ack"]:
                            # Out-of-order packet, send duplicate ACK
                            print(f"Out-of-order packet: received seq={packet.seq}, expected={self.window['last_ack']}")
                            ack_packet = Packet(
                                seq=self.window["next_seq_to_send"], 
                                ack=self.window["last_ack"], 
                                flags=ACK_FLAG, 
                                adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                            )
                            self.sock_fd.sendto(ack_packet.encode(), addr)
                        else:
                            # Duplicate packet, send ACK
                            print(f"Duplicate packet: received seq={packet.seq}, already received up to={self.window['last_ack']}")
                            ack_packet = Packet(
                                seq=self.window["next_seq_to_send"], 
                                ack=self.window["last_ack"], 
                                flags=ACK_FLAG, 
                                adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                            )
                            self.sock_fd.sendto(ack_packet.encode(), addr)
                elif len(packet.payload) > 0:
                    # Out-of-order or duplicate packet
                    print(str(time.time()), f"Out-of-order packet: seq={packet.seq}, expected={self.window['last_ack']}")
                    
                    # Send duplicate ACK
                    ack_packet = Packet(
                        seq=self.window["next_seq_to_send"], 
                        ack=self.window["last_ack"], 
                        flags=ACK_FLAG, 
                        adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                    )
                    self.sock_fd.sendto(ack_packet.encode(), addr)

            except socket.timeout:
                continue
            
            except Exception as e:
                if not self.dying:
                    print(str(time.time()), f"Error in backend: {e}")

    # In the establish_connection method in TransportSocket class:
    def establish_connection(self):
        """
        Establish connection using three-way handshake (client side)
        """
        print(f"{time.time()} Initiating connection establishment...")
        
        # Initialize sequence number (can be random, but we'll use 0 for simplicity)
        initial_seq = 0
        self.window["next_seq_to_send"] = initial_seq
        
        # Send SYN packet
        syn_packet = Packet(
            seq=initial_seq, 
            ack=0, 
            flags=SYN_FLAG, 
            adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
        )
        
        # Record send time for RTT estimation
        self.rtt_stats["send_times"][initial_seq] = time.time()
        
        # Send SYN and transition to SYN_SENT
        self.sock_fd.sendto(syn_packet.encode(), self.conn)
        self.state = SYN_SENT
        
        # Wait for connection to be established (handled by backend)
        with self.wait_cond:
            timeout_time = time.time() + self.rtt_stats["rto"]
            
            while self.state != ESTABLISHED:
                remaining = max(0, timeout_time - time.time())
                if remaining <= 0:
                    # Timeout, retransmit SYN
                    print("SYN timeout, retransmitting...")
                    self.sock_fd.sendto(syn_packet.encode(), self.conn)
                    timeout_time = time.time() + self.rtt_stats["rto"]
                
                # Wait for state change or timeout
                self.wait_cond.wait(timeout=min(remaining, 1.0))
                
                # Check if we're dying
                if self.dying:
                    raise ValueError("Socket is closing")
        
        print(f"{time.time()} Connection established successfully")
        
    def accept_connection(self):
        """
        Accept a connection request (server side)
        """
        print(str(time.time()), "Waiting for connection...")
        
        # Wait for SYN to arrive (handled by backend)
        with self.wait_cond:
            while self.state != SYN_RCVD:
                self.wait_cond.wait()
        
        print(str(time.time()), "Connection accepted")

    def terminate_connection(self):
        """
        Terminate the connection (active close)
        """
        print(str(time.time()), "Initiating connection termination...")
        
        # Send FIN packet
        fin_packet = Packet(
            seq=self.window["next_seq_to_send"], 
            ack=self.window["last_ack"], 
            flags=FIN_FLAG, 
            adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
        )
        
        self.sock_fd.sendto(fin_packet.encode(), self.conn)
        self.state = FIN_SENT
        
        # Wait for ACK or FIN+ACK
        with self.wait_cond:
            timeout_time = time.time() + self.rtt_stats["rto"]
            
            while self.state != TIME_WAIT and self.state != CLOSED:
                remaining = max(0, timeout_time - time.time())
                if remaining <= 0:
                    # Timeout, retransmit FIN
                    print(str(time.time()), "FIN timeout, retransmitting...")
                    self.sock_fd.sendto(fin_packet.encode(), self.conn)
                    timeout_time = time.time() + self.rtt_stats["rto"]
                
                # Wait for state change or timeout
                self.wait_cond.wait(timeout=min(remaining, 1.0))
                
                # Check if we're dying
                if self.dying:
                    break
        
        # If in TIME_WAIT, wait for 2*MSL before fully closing
        if self.state == TIME_WAIT:
            print(str(time.time()), "In TIME_WAIT, waiting for 2*MSL...")
            time.sleep(2 * DEFAULT_TIMEOUT)
            self.state = CLOSED
            
        print(str(time.time()), "Connection terminated")
        
    def time_wait_timeout(self):
        """
        Called after TIME_WAIT timeout to transition to CLOSED state.
        """
        with self.recv_lock:
            if self.state == TIME_WAIT:
                self.state = CLOSED
                self.wait_cond.notify_all()
                
    def update_rtt(self, seq_no):
        """
        Update RTT estimation when an ACK is received.
        """
        if seq_no in self.rtt_stats["send_times"]:
            # Calculate sample RTT
            sample_rtt = time.time() - self.rtt_stats["send_times"][seq_no]
            del self.rtt_stats["send_times"][seq_no]
            
            # Update SRTT and RTTVAR using EWMA
            if self.rtt_stats["srtt"] == 0:
                # First measurement
                self.rtt_stats["srtt"] = sample_rtt
                self.rtt_stats["rttvar"] = sample_rtt / 2
            else:
                # EWMA updates
                self.rtt_stats["rttvar"] = (1 - self.rtt_stats["beta"]) * self.rtt_stats["rttvar"] + \
                                        self.rtt_stats["beta"] * abs(sample_rtt - self.rtt_stats["srtt"])
                self.rtt_stats["srtt"] = (1 - self.rtt_stats["alpha"]) * self.rtt_stats["srtt"] + \
                                        self.rtt_stats["alpha"] * sample_rtt
            
            # Update RTO = SRTT + 4*RTTVAR (clamped)
            self.rtt_stats["rto"] = min(DEFAULT_TIMEOUT, max(0.2, self.rtt_stats["srtt"] + 4 * self.rtt_stats["rttvar"]))
            
            print(f"{time.time()} RTT sample: {sample_rtt:.4f}s, SRTT: {self.rtt_stats['srtt']:.4f}s, RTO: {self.rtt_stats['rto']:.4f}s")