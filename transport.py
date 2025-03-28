import socket
import struct
import threading
import time
import random
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

# Use MSS from grading instead of a hardcoded value for better compatibility
SAFE_MSS = 1024

# Debug mode - set to False to disable verbose output
DEBUG = False

def debug_print(*args, **kwargs):
    """Print only if DEBUG is enabled"""
    if DEBUG:
        print(*args, **kwargs)


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

    def encode(self):
        """
        Encode the packet header and payload into bytes
        Format: seq (32 bits), ack (32 bits), flags (32 bits), adv_window (16 bits)
        """
        try:
            # Pack header components with strict format
            header = struct.pack("!IIIH", self.seq, self.ack, self.flags, self.adv_window)
            
            # Combine header with payload
            packet = header + self.payload
            return packet
        except Exception as e:
            print(f"ERROR encoding packet: {e}")
            return b""  # Return empty bytes on error

    @staticmethod
    def decode(data):
        """
        Decode bytes into a Packet object
        """
        try:
            # Get header size and unpack
            header_size = struct.calcsize("!IIIH")
            
            if len(data) < header_size:
                print(f"WARNING: Received data too small for header: {len(data)} bytes")
                return Packet()  # Return an empty packet
                
            header = data[:header_size]
            
            seq, ack, flags, adv_window = struct.unpack("!IIIH", header)
            payload = data[header_size:]
            
            return Packet(seq, ack, flags, adv_window, payload)
        except Exception as e:
            print(f"ERROR decoding packet: {e}")
            return Packet()  # Return an empty packet on error


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
        
        self.last_syn_ack_time = None
        self.syn_ack_retries = 0
        
        self.final_handshake_ack = None  # Store the final ACK packet of the handshake
        self.final_ack_time = None       # When the final ACK was sent
        self.final_ack_retries = 0       # Number of retransmissions
        self.connection_establishing = False  # Flag to track if we're establishing a connection
        
        # FSM state
        self.state = CLOSED
        
        # Add RTT estimation
        self.rtt_stats = {
            "srtt": 0,          # Smoothed RTT (EstimatedRTT)
            "rttvar": 0,        # RTT variance
            "rto": DEFAULT_TIMEOUT,  # Retransmission timeout
            "alpha": 0.125,     # EWMA weight factor for SRTT (RFC recommends 0.125)
            "beta": 0.25,       # EWMA weight factor for RTTVAR (RFC recommends 0.25)
            "send_times": {},   # Track send times of packets for RTT measurement
            "first_measurement": True, # Flag for first measurement
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
            "last_window_update": MAX_NETWORK_BUFFER,  # When we last updated our adv_window
            "outstanding_segs": 0,     # Count of outstanding segments
            "dup_ack_count": 0,       # Count of duplicate ACKs for fast retransmit
        }
        self.sock_type = None
        self.conn = None
        self.my_port = None

    def socket(self, sock_type, port, server_ip=None):
        """
        Create and initialize the socket, setting its type and starting the backend thread.
        """
        try:
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
                print(f"{time.time()} Unknown socket type")
                return EXIT_ERROR

            # 1-second timeout so we can periodically check `self.dying`
            self.sock_fd.settimeout(1.0)

            self.my_port = self.sock_fd.getsockname()[1]
            print(f"Socket initialized with local port {self.my_port}")

            # Start the backend thread
            self.thread = threading.Thread(target=self.backend, daemon=True)
            self.thread.start()
            return EXIT_SUCCESS
        except Exception as e:
            print(f"Error initializing socket: {e}")
            return EXIT_ERROR

    def close(self):
        """
        Close the socket and stop the backend thread.
        """
        # Handle connection termination based on the current state
        if self.state == ESTABLISHED:
            self.terminate_connection()
        
        # Tell the backend thread to stop
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
            print(f"{time.time()} Error: Null socket")
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
            print(f"{time.time()} ERROR: Negative length")
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
                    
                    # Calculate new available window
                    new_available = MAX_NETWORK_BUFFER - self.window["recv_len"]
                    old_available = self.window["last_window_update"]
                    
                    # If we've freed up significant buffer space, send a window update
                    # This helps if we previously advertised a small or zero window
                    if (new_available > old_available + MAX_NETWORK_BUFFER/4 or 
                        (old_available == 0 and new_available > 0)):
                        
                        if self.conn:  # Make sure we have a peer to send to
                            debug_print(f"Sent window update: adv_window={new_available}")
                            window_update = Packet(
                                seq=self.window["next_seq_to_send"], 
                                ack=self.window["last_ack"], 
                                flags=ACK_FLAG, 
                                adv_window=new_available
                            )
                            self.sock_fd.sendto(window_update.encode(), self.conn)
                            self.window["last_window_update"] = new_available
            else:
                print(f"{time.time()} ERROR: Unknown or unimplemented flag.")
                read_len = EXIT_ERROR
        finally:
            self.recv_lock.release()

        return read_len

    def send_segment(self, data):
        """
        Send 'data' in multiple smaller segments with flow control
        """
        # Check if we're in ESTABLISHED state
        if self.state != ESTABLISHED:
            print(f"Cannot send data in state {self.state}")
            return
            
        offset = 0
        total_len = len(data)
        
        print(f"Sending {total_len} bytes of data")

        # While there's data left to send
        while offset < total_len and not self.dying:
            with self.wait_cond:  # Use wait_cond to properly wait for window updates
                # Wait for window space to be available
                while self.window["peer_adv_window"] <= 0 and not self.dying:
                    print(f"Flow control: zero window, waiting for update from peer")
                    # Send zero window probe periodically
                    if random.random() < 0.1:  # ~10% chance to send probe
                        probe = Packet(
                            seq=self.window["next_seq_to_send"],
                            ack=self.window["last_ack"],
                            flags=0,
                            adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"],
                            payload=b""  # Zero-byte probe
                        )
                        self.sock_fd.sendto(probe.encode(), self.conn)
                    
                    # Wait for window update
                    self.wait_cond.wait(timeout=0.5)  # Use condition variable instead of busy waiting
                
                if self.dying:
                    break
                    
                # Calculate how much we can send in this segment
                available_window = min(
                    self.window["peer_adv_window"],  # Respect peer's advertised window
                    SAFE_MSS  # Don't exceed our segment size
                )
                
                payload_len = min(available_window, total_len - offset)
                
                if payload_len <= 0:
                    continue
                    
                # Create and send packet
                seq_no = self.window["next_seq_to_send"]
                chunk = data[offset:offset + payload_len]
                
                segment = Packet(
                    seq=seq_no, 
                    ack=self.window["last_ack"], 
                    flags=0, 
                    adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"],
                    payload=chunk
                )
                
                # Record send time for RTT estimation
                self.rtt_stats["send_times"][seq_no] = time.time()
                
                print(f"Sending segment (seq={seq_no}, len={payload_len}, window={self.window['peer_adv_window']})")
                self.sock_fd.sendto(segment.encode(), self.conn)
                
                # Update window tracking
                self.window["next_seq_to_send"] += payload_len
                self.window["in_flight"] += payload_len
                self.window["packets_in_flight"][seq_no] = (segment, time.time())
                self.window["outstanding_segs"] += 1
                
                # Update peer window to account for sent data
                self.window["peer_adv_window"] -= payload_len
                
                # Move to next segment
                offset += payload_len
        
        if offset > 0:  # Only wait for ACKs if we sent something
            # Wait for all segments to be ACKed
            self.wait_for_all_acks()
    
    def wait_for_all_acks(self):
        """
        Wait until all packets in flight have been acknowledged
        """
        start_time = time.time()
        max_wait_time = 30  # Maximum time to wait in seconds
        
        # Wait while we have packets in flight and haven't hit the timeout
        while self.window["packets_in_flight"] and time.time() - start_time < max_wait_time:
            # Check for packets that need retransmission
            current_time = time.time()
            packets_to_retransmit = []
            
            with self.recv_lock:
                for seq, (packet, send_time) in list(self.window["packets_in_flight"].items()):
                    if current_time - send_time > self.rtt_stats["rto"]:
                        packets_to_retransmit.append((seq, packet))
            
            # Retransmit packets outside the lock to avoid deadlock
            for seq, packet in packets_to_retransmit:
                print(f"Retransmitting segment (seq={seq}, len={len(packet.payload)})")
                self.sock_fd.sendto(packet.encode(), self.conn)
                with self.recv_lock:
                    self.window["packets_in_flight"][seq] = (packet, current_time)
            
            # Sleep briefly to avoid busy waiting
            time.sleep(0.01)
        
        # If we still have packets in flight after the timeout, log a warning
        if self.window["packets_in_flight"]:
            print(f"Warning: Giving up waiting for ACKs after {max_wait_time} seconds")

    def wait_for_ack(self, ack_goal):
        """
        Wait for 'next_seq_expected' to reach or exceed 'ack_goal' within RTO.
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
                if self.state == SYN_RCVD and self.last_syn_ack_time is not None:
                    current_time = time.time()
                    if (current_time - self.last_syn_ack_time > self.rtt_stats["rto"] and 
                        self.syn_ack_retries < 5):
                        
                        # Retransmit the SYN-ACK
                        initial_seq = self.window["next_seq_to_send"] - 1
                        syn_ack = Packet(
                            seq=initial_seq,
                            ack=self.window["last_ack"],
                            flags=SYN_FLAG | ACK_FLAG,
                            adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                        )
                        self.sock_fd.sendto(syn_ack.encode(), self.conn)
                        self.last_syn_ack_time = current_time
                        self.syn_ack_retries += 1
                        print(f"Retransmitted SYN+ACK packet to {self.conn} (attempt {self.syn_ack_retries}/5)")
                
                # Add retransmission of final ACK (client side)
                if (self.state == ESTABLISHED and self.connection_establishing and
                    self.final_handshake_ack is not None and self.final_ack_time is not None):
                    
                    current_time = time.time()
                    # Use a shorter timeout for the final ACK retransmission
                    timeout = min(1.0, self.rtt_stats["rto"])
                    
                    if (current_time - self.final_ack_time > timeout and
                        self.final_ack_retries < 5):
                        
                        # Retransmit final ACK
                        self.sock_fd.sendto(self.final_handshake_ack, self.conn)
                        self.final_ack_time = current_time
                        self.final_ack_retries += 1
                        print(f"Retransmitting final handshake ACK (attempt {self.final_ack_retries}/5)")
                    
                    # After 5 successful retransmissions or 10 seconds, assume connection is established
                    elif (self.final_ack_retries >= 5 or 
                        current_time - self.final_ack_time > 10.0):
                        print("Completed connection establishment phase")
                        self.final_handshake_ack = None
                        self.final_ack_time = None
                        self.connection_establishing = False
                
                data, addr = self.sock_fd.recvfrom(2048)
                
                if len(data) == 2048:
                    print(f"{time.time()} Warning: Received max packet size of 2048 bytes, data might be truncated")
                
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
                        
                        # Store client connection information
                        self.conn = addr
                        
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
                        
                        # Send the SYN+ACK
                        encoded_packet = syn_ack.encode()
                        self.sock_fd.sendto(encoded_packet, addr)
                        print(f"Sent SYN+ACK packet to {addr}")
                        
                        # Update our sequence numbers
                        # After sending SYN, our next sequence number is initial_seq + 1
                        self.window["next_seq_to_send"] = initial_seq + 1
                        self.window["send_base"] = initial_seq + 1
                        
                        # Add RTT tracking for SYN packet
                        self.rtt_stats["send_times"][initial_seq] = time.time()
                        
                        self.last_syn_ack_time = time.time()
                        self.syn_ack_retries = 0
                        
                        # Transition to SYN_RCVD
                        self.state = SYN_RCVD
                        print(f"Transitioned to SYN_RCVD state")
                        self.wait_cond.notify_all()
                    continue

                elif self.state == SYN_SENT and (packet.flags & SYN_FLAG) != 0 and (packet.flags & ACK_FLAG) != 0:
                    # Received SYN+ACK in SYN_SENT state
                    with self.recv_lock:
                        print(f"{time.time()} Received SYN+ACK from {addr}")
                        
                        # SYN consumes one sequence number, so next expected byte is packet.seq + 1
                        self.window["last_ack"] = packet.seq + 1
                        
                        # Our own SYN consumes one sequence number as well
                        initial_seq = self.window["next_seq_to_send"] - 1  # Subtract 1 to get the initial SYN seq
                        
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

                            # With these lines:
                            encoded_ack = ack_packet.encode()
                            self.sock_fd.sendto(encoded_ack, addr)
                            print(f"Sent ACK to complete handshake")

                            # Store the final ACK for potential retransmission
                            self.final_handshake_ack = encoded_ack
                            self.final_ack_time = time.time()
                            self.final_ack_retries = 0
                            self.connection_establishing = True

                            # Update sequence numbers for data transmission
                            self.window["next_seq_to_send"] = packet.ack
                            self.window["next_seq_expected"] = packet.ack
                            self.window["send_base"] = packet.ack
                            
                            # Transition to ESTABLISHED
                            self.state = ESTABLISHED
                            print(f"Connection established, transitioned to ESTABLISHED state")
                            self.wait_cond.notify_all()
                        else:
                            print(f"Invalid ACK: expected {initial_seq + 1}, got {packet.ack}")
                    continue

                elif self.state == SYN_RCVD and (packet.flags & ACK_FLAG) != 0:
                    # Received ACK in SYN_RCVD state (completing three-way handshake)
                    with self.recv_lock:
                        print(f"{time.time()} Received ACK from {addr}, handshake complete")
                        
                        # The client is acknowledging our SYN
                        expected_ack = self.window["next_seq_to_send"] 
                        if packet.ack == expected_ack:
                            # Transition to ESTABLISHED
                            self.state = ESTABLISHED
                            self.last_syn_ack_time = None
                            self.syn_ack_retries = 0
                            self.window["next_seq_expected"] = packet.ack
                            self.wait_cond.notify_all()
                            
                            print(f"Connection established, now in ESTABLISHED state")
                        else:
                            print(f"Invalid ACK: expected {expected_ack}, got {packet.ack}")
                    continue

                # Connection termination handling
                elif self.state == ESTABLISHED and (packet.flags & FIN_FLAG) != 0:
                    # Received FIN in ESTABLISHED state (passive close)
                    with self.recv_lock:
                        print(f"{time.time()} Received FIN from {addr}")
                        # FIN consumes one sequence number, so next expected byte is packet.seq + 1
                        self.window["last_ack"] = packet.seq + 1
                        
                        # Send ACK for the FIN
                        ack_packet = Packet(
                            seq=self.window["next_seq_to_send"], 
                            ack=self.window["last_ack"], 
                            flags=ACK_FLAG, 
                            adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                        )
                        self.sock_fd.sendto(ack_packet.encode(), addr)
                        print(f"Sent ACK for FIN, transitioning to CLOSE_WAIT")
                        
                        # Transition to CLOSE_WAIT
                        self.state = CLOSE_WAIT
                        self.wait_cond.notify_all()
                        
                        # In a real application, the app would close the socket when ready
                        # For this simplified implementation, we'll send FIN immediately
                        next_seq = self.window["next_seq_to_send"]
                        fin_packet = Packet(
                            seq=next_seq, 
                            ack=self.window["last_ack"], 
                            flags=FIN_FLAG, 
                            adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                        )
                        self.sock_fd.sendto(fin_packet.encode(), addr)
                        print(f"Sent FIN (seq={next_seq}), transitioning to LAST_ACK")
                        
                        # Update sequence number and transition to LAST_ACK
                        self.window["next_seq_to_send"] = next_seq + 1
                        self.state = LAST_ACK
                    continue

                elif self.state == FIN_SENT and (packet.flags & ACK_FLAG) != 0:
                    # Received ACK in FIN_SENT state
                    with self.recv_lock:
                        print(f"{time.time()} Received ACK for FIN from {addr}")
                        
                        # Update next expected sequence if this ACK acknowledges our FIN
                        if packet.ack >= self.window["next_seq_to_send"]:
                            self.window["next_seq_expected"] = packet.ack
                            
                            # ACK for our FIN, transition to TIME_WAIT
                            print(f"Valid ACK for our FIN, transitioning to TIME_WAIT")
                            self.state = TIME_WAIT
                            self.wait_cond.notify_all()
                            
                            # Schedule transition to CLOSED after 2*MSL
                            threading.Timer(2 * DEFAULT_TIMEOUT, self.time_wait_timeout).start()
                        else:
                            print(f"Received ACK {packet.ack} but expected at least {self.window['next_seq_to_send']}")
                    continue

                elif self.state == FIN_SENT and (packet.flags & FIN_FLAG) != 0:
                    # Received FIN in FIN_SENT state (simultaneous close)
                    with self.recv_lock:
                        print(f"{time.time()} Received FIN from {addr} (simultaneous close)")
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
                        print(f"{time.time()} Received final ACK from {addr}")
                        
                        # Check if this ACK acknowledges our FIN
                        if packet.ack >= self.window["next_seq_to_send"]:
                            print(f"Valid ACK for our FIN in LAST_ACK, transitioning to CLOSED")
                            # Transition to CLOSED state
                            self.state = CLOSED
                            self.wait_cond.notify_all()
                        else:
                            print(f"Received ACK {packet.ack} in LAST_ACK but expected at least {self.window['next_seq_to_send']}")
                    continue
                    
                elif self.state == TIME_WAIT:
                    # If we receive a data packet in TIME_WAIT, still send an ACK
                    # This helps the other side complete its transmission
                    if len(packet.payload) > 0:
                        print(f"Received data in TIME_WAIT state, sending ACK")
                        ack_packet = Packet(
                            seq=self.window["next_seq_to_send"], 
                            ack=packet.seq + len(packet.payload), 
                            flags=ACK_FLAG, 
                            adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                        )
                        self.sock_fd.sendto(ack_packet.encode(), addr)
                    # For retransmitted FINs, send an ACK again
                    elif (packet.flags & FIN_FLAG) != 0:
                        print("Received duplicate FIN in TIME_WAIT, acknowledging again")
                        ack_packet = Packet(
                            seq=self.window["next_seq_to_send"], 
                            ack=packet.seq + 1, 
                            flags=ACK_FLAG, 
                            adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                        )
                        self.sock_fd.sendto(ack_packet.encode(), addr)
                    continue

                # Data packet handling (ACK packets with or without data)
                if (packet.flags & ACK_FLAG) != 0:
                    with self.recv_lock:
                        # Process acknowledged data
                        if packet.ack > self.window["next_seq_expected"]:
                            # New ACK, reset duplicate ACK counter
                            self.window["dup_ack_count"] = 0
                            
                            # Calculate how many bytes were acknowledged
                            acked_bytes = packet.ack - self.window["next_seq_expected"]
                            
                            # Update in-flight packets and RTT estimation
                            removed_packets = 0
                            for seq in list(self.window["packets_in_flight"].keys()):
                                pkt, _ = self.window["packets_in_flight"][seq]
                                if seq + len(pkt.payload) <= packet.ack:
                                    # Update RTT estimation if this packet is being acknowledged
                                    if seq in self.rtt_stats["send_times"]:
                                        self.update_rtt(seq)
                                    # Remove from in-flight list
                                    del self.window["packets_in_flight"][seq]
                                    removed_packets += 1
                            
                            # Update next expected sequence and in-flight data
                            self.window["next_seq_expected"] = packet.ack
                            self.window["in_flight"] = max(0, self.window["in_flight"] - acked_bytes)
                            self.window["outstanding_segs"] = max(0, self.window["outstanding_segs"] - removed_packets)
                            
                            # Update peer's advertised window
                            self.window["peer_adv_window"] = packet.adv_window
                            
                            # If we're still in connection establishment and received an ACK for data,
                            # consider the connection fully established
                            if self.connection_establishing:
                                self.final_handshake_ack = None
                                self.final_ack_time = None 
                                self.connection_establishing = False
                                print("Connection fully established (data acknowledged)")
                            
                            debug_print(f"ACK received: base={self.window['next_seq_expected']}, " +
                                f"in_flight={self.window['in_flight']}, adv_window={packet.adv_window}")
                            
                            # Notify any waiting sender
                            self.wait_cond.notify_all()
                        elif packet.ack == self.window["next_seq_expected"]:
                            # Duplicate ACK received
                            self.window["dup_ack_count"] += 1
                            print(f"Duplicate ACK received: {packet.ack}, count: {self.window['dup_ack_count']}")
                            
                            if self.window["dup_ack_count"] == 3:
                                # Triple duplicate ACK detected, trigger fast retransmit
                                print(f"Triple duplicate ACK detected, triggering fast retransmit for ACK {packet.ack}")
                                
                                # The segment to retransmit is the one with sequence number equal to the ACK number
                                # of the duplicate ACKs
                                missing_seq = packet.ack
                                
                                # Find the segment to retransmit
                                if missing_seq in self.window["packets_in_flight"]:
                                    # Found the packet to retransmit
                                    pkt, _ = self.window["packets_in_flight"][missing_seq]
                                    print(f"Fast retransmitting packet with seq {missing_seq}")
                                    self.sock_fd.sendto(pkt.encode(), self.conn)
                                    # Update send time
                                    self.window["packets_in_flight"][missing_seq] = (pkt, time.time())
                                else:
                                    print(f"No packet found to retransmit for ACK {packet.ack}")
                                
                                # Reset the duplicate ACK counter after fast retransmit
                                self.window["dup_ack_count"] = 0

                # Data packet processing (if in ESTABLISHED state)
                if self.state in [ESTABLISHED, CLOSE_WAIT] and len(packet.payload) > 0:
                    with self.recv_lock:
                        # Check if this packet is within our receive window
                        if packet.seq == self.window["last_ack"]:
                            
                            if self.window["recv_len"] + len(packet.payload) <= MAX_NETWORK_BUFFER:
                                
                                # Append payload to our receive buffer
                                self.window["recv_buf"] += packet.payload
                                self.window["recv_len"] += len(packet.payload)
                                
                                debug_print(f"Received data segment {packet.seq} with {len(packet.payload)} bytes.")
                                
                                # Update last_ack
                                self.window["last_ack"] = packet.seq + len(packet.payload)
                                
                                # Calculate new advertised window
                                available_window = MAX_NETWORK_BUFFER - self.window["recv_len"]
                                
                                # Send ACK with current window advertisement
                                ack_packet = Packet(
                                    seq=self.window["next_seq_to_send"], 
                                    ack=self.window["last_ack"], 
                                    flags=ACK_FLAG, 
                                    adv_window=available_window
                                )
                                self.sock_fd.sendto(ack_packet.encode(), addr)
                                
                                self.wait_cond.notify_all()
                            else:
                                # Buffer would overflow - reject data by not advancing last_ack
                                print(f"WARNING: Receive buffer would exceed MAX_NETWORK_BUFFER ({MAX_NETWORK_BUFFER} bytes)")
                                print(f"Current buffer size: {self.window['recv_len']}, incoming payload: {len(packet.payload)} bytes")
                                
                                # Send ACK with zero window to stop sender
                                ack_packet = Packet(
                                    seq=self.window["next_seq_to_send"], 
                                    ack=self.window["last_ack"], 
                                    flags=ACK_FLAG, 
                                    adv_window=0  # Zero window to indicate buffer full
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
                            debug_print(f"Duplicate packet: received seq={packet.seq}, already received up to={self.window['last_ack']}")
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
                    print(f"{time.time()} Error in backend: {e}")

    def establish_connection(self):
        """
        Establish connection using three-way handshake (client side)
        """
        print(f"{time.time()} Initiating connection establishment...")
        
        # Initialize sequence number (can be random, but we'll use 0 for simplicity)
        initial_seq = 0
        self.window["next_seq_to_send"] = initial_seq + 1  # SYN consumes one sequence number
        
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
        encoded_syn = syn_packet.encode()
        print(f"Sending SYN packet")
        self.sock_fd.sendto(encoded_syn, self.conn)
        self.state = SYN_SENT
        
        # Wait for connection to be established
        max_retries = 5
        retries = 0
        
        with self.wait_cond:
            while self.state != ESTABLISHED and retries < max_retries:
                timeout = min(3.0, self.rtt_stats["rto"])  # Cap timeout at 3 seconds
                
                # Wait for response
                self.wait_cond.wait(timeout=timeout)
                
                # Check if state changed
                if self.state == ESTABLISHED:
                    print(f"Connection established successfully")
                    return
                    
                # Timeout occurred - retry or give up
                retries += 1
                print(f"SYN timeout, retransmitting... (attempt {retries}/{max_retries})")
                
                # Retransmit SYN
                self.sock_fd.sendto(encoded_syn, self.conn)
        
        # If we exit the loop without establishing connection
        if self.state != ESTABLISHED:
            raise ConnectionError("Failed to establish connection after multiple retries")
        
    def accept_connection(self):
        """
        Accept a connection request (server side)
        """
        print(f"{time.time()} Waiting for connection...")
        
        # Wait for SYN to arrive (handled by backend)
        with self.wait_cond:
            while self.state != SYN_RCVD:
                self.wait_cond.wait()
        
        print(f"{time.time()} Connection accepted")

    def terminate_connection(self):
        """
        Terminate the connection (active close)
        """
        print(f"{time.time()} Initiating connection termination...")
        
        # Only proceed with termination if we're in ESTABLISHED state
        if self.state != ESTABLISHED:
            print(f"Cannot terminate from state {self.state}")
            return
            
        # Wait for all data to be sent
        self.wait_for_all_acks()
        
        # Increment seq number for FIN
        next_seq = self.window["next_seq_to_send"]
        
        # Send FIN packet
        fin_packet = Packet(
            seq=next_seq, 
            ack=self.window["last_ack"], 
            flags=FIN_FLAG, 
            adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
        )
        
        print(f"Sending FIN packet (seq={next_seq})")
        self.sock_fd.sendto(fin_packet.encode(), self.conn)
        
        # Update sequence number for FIN
        self.window["next_seq_to_send"] = next_seq + 1
        
        # Transition to FIN_SENT state
        self.state = FIN_SENT
        
        # Wait for ACK or FIN+ACK
        retries = 0
        max_retries = 5
        
        with self.wait_cond:
            while self.state != TIME_WAIT and self.state != CLOSED and retries < max_retries:
                # Wait for response with timeout
                self.wait_cond.wait(timeout=self.rtt_stats["rto"])
                
                # Check if state changed
                if self.state == TIME_WAIT or self.state == CLOSED:
                    break
                    
                # Timeout occurred - retransmit FIN
                retries += 1
                print(f"FIN timeout, retransmitting... (attempt {retries}/{max_retries})")
                self.sock_fd.sendto(fin_packet.encode(), self.conn)
                
                # Check if we're dying
                if self.dying:
                    break
        
        # If in TIME_WAIT, wait for 2*MSL before fully closing
        if self.state == TIME_WAIT:
            print(f"{time.time()} In TIME_WAIT, waiting for 2*MSL...")
            # Schedule transition to CLOSED after 2*MSL
            threading.Timer(2 * DEFAULT_TIMEOUT, self.time_wait_timeout).start()
            
        print(f"{time.time()} Connection termination initiated")
        
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
        Update RTT estimation when an ACK is received using EWMA.
        Implements the algorithm specified in RFC 6298.
        """
        if seq_no in self.rtt_stats["send_times"]:
            # Calculate sample RTT
            sample_rtt = time.time() - self.rtt_stats["send_times"][seq_no]
            del self.rtt_stats["send_times"][seq_no]  # Clean up after using
            
            # Skip very small measurements (likely delayed ACKs)
            if sample_rtt < 0.001:
                return
                
            alpha = self.rtt_stats["alpha"]
            beta = self.rtt_stats["beta"]
            
            if self.rtt_stats["first_measurement"]:
                # First measurement: initialize values (RFC 6298 recommendation)
                self.rtt_stats["srtt"] = sample_rtt
                self.rtt_stats["rttvar"] = sample_rtt / 2
                self.rtt_stats["first_measurement"] = False
            else:
                # RFC 6298 algorithm:
                # RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R'|
                # SRTT = (1 - alpha) * SRTT + alpha * R'
                
                # First update RTTVAR (using old SRTT)
                self.rtt_stats["rttvar"] = (1 - beta) * self.rtt_stats["rttvar"] + \
                                          beta * abs(self.rtt_stats["srtt"] - sample_rtt)
                
                # Then update SRTT
                self.rtt_stats["srtt"] = (1 - alpha) * self.rtt_stats["srtt"] + alpha * sample_rtt
            
            # Set RTO = SRTT + 4 * RTTVAR (RFC 6298 recommendation)
            self.rtt_stats["rto"] = self.rtt_stats["srtt"] + 4 * self.rtt_stats["rttvar"]
            
            # Limit RTO to reasonable bounds (RFC 6298 suggests min of 1s)
            self.rtt_stats["rto"] = max(1.0, min(DEFAULT_TIMEOUT, self.rtt_stats["rto"]))
            
            print(f"RTT update: sample={sample_rtt:.4f}s, SRTT={self.rtt_stats['srtt']:.4f}s, RTO={self.rtt_stats['rto']:.4f}s")