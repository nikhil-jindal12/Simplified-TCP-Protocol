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
        # Encode the packet header and payload into bytes
        # Format: seq (32 bits), ack (32 bits), flags (32 bits), adv_window (16 bits)
        header = struct.pack("!IIIH", self.seq, self.ack, self.flags, self.adv_window)
        return header + self.payload

    @staticmethod
    def decode(data):
        # Decode bytes into a Packet object
        header_size = struct.calcsize("!IIIH")
        seq, ack, flags, adv_window = struct.unpack("!IIIH", data[:header_size])
        payload = data[header_size:]
        return Packet(seq, ack, flags, adv_window, payload)


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

        self.window = {
            "last_ack": 0,            # The next seq we expect from peer (used for receiving data)
            "next_seq_expected": 0,   # The highest ack we've received for *our* transmitted data
            "recv_buf": b"",          # Received data buffer
            "recv_len": 0,            # How many bytes are in recv_buf
            "next_seq_to_send": 0,    # The sequence number for the next packet we send
            "in_flight": 0,           # Number of bytes in flight (sent but not acked)
            "peer_adv_window": MAX_NETWORK_BUFFER,  # Peer's advertised window
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
            else:
                print(str(time.time()), "ERROR: Unknown or unimplemented flag.")
                read_len = EXIT_ERROR
        finally:
            self.recv_lock.release()

        return read_len

    def send_segment(self, data):
        """
        Send 'data' in multiple MSS-sized segments and reliably wait for each ACK
        """
        offset = 0
        total_len = len(data)

        # While there's data left to send
        while offset < total_len:
                    # Wait for flow control window to have space
            with self.wait_cond:
                while self.window["in_flight"] >= self.window["peer_adv_window"]:
                    print(str(time.time()), f"Flow control: waiting for window space (in_flight={self.window['in_flight']}, peer_window={self.window['peer_adv_window']})")
                    self.wait_cond.wait(timeout=self.rtt_stats["rto"])
                    
                    # If socket is closing, stop sending
                    if self.dying:
                        return
            
            # Calculate payload size based on MSS and flow control
            available_window = self.window["peer_adv_window"] - self.window["in_flight"]
            payload_len = min(MSS, total_len - offset, available_window)

            # Current sequence number
            seq_no = self.window["next_seq_to_send"]
            chunk = data[offset : offset + payload_len]

            # Create a packet
            segment = Packet(seq=seq_no, ack=self.window["last_ack"], flags=0, adv_window=MAX_NETWORK_BUFFER, payload=chunk)

            # We expect an ACK for seq_no + payload_len
            ack_goal = seq_no + payload_len
            
            # Update in-flight data
            with self.recv_lock:
                self.window["in_flight"] += payload_len

            # Track send time for RTT measurement
            self.rtt_stats["send_times"][seq_no] = time.time()

            while True:
                print(str(time.time()), f"Sending segment (seq={seq_no}, len={payload_len})")
                self.sock_fd.sendto(segment.encode(), self.conn)

                if self.wait_for_ack(ack_goal):
                    print(str(time.time()), f"Segment {seq_no} acknowledged.")
                    # Advance our next_seq_to_send
                    self.window["next_seq_to_send"] += payload_len
                    break
                else:
                    print(str(time.time()), "Timeout: Retransmitting segment.")

            offset += payload_len


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
                        print(str(time.time()), f"Received SYN from {addr}")
                        self.window["last_ack"] = packet.seq + 1
                        
                        # Send SYN+ACK
                        syn_ack = Packet(
                            seq=self.window["next_seq_to_send"], 
                            ack=self.window["last_ack"], 
                            flags=SYN_FLAG | ACK_FLAG, 
                            adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                        )
                        self.sock_fd.sendto(syn_ack.encode(), addr)
                        
                        # Transition to SYN_RCVD
                        self.state = SYN_RCVD
                        self.wait_cond.notify_all()
                    continue

                elif self.state == SYN_SENT and (packet.flags & SYN_FLAG) != 0 and (packet.flags & ACK_FLAG) != 0:
                    # Received SYN+ACK in SYN_SENT state
                    with self.recv_lock:
                        print(str(time.time()), f"Received SYN+ACK from {addr}")
                        self.window["last_ack"] = packet.seq + 1
                        
                        # Update RTT estimation if we have send time
                        if packet.ack - 1 in self.rtt_stats["send_times"]:
                            self.update_rtt(packet.ack - 1)
                        
                        # Send ACK
                        ack_packet = Packet(
                            seq=packet.ack, 
                            ack=self.window["last_ack"], 
                            flags=ACK_FLAG, 
                            adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                        )
                        self.sock_fd.sendto(ack_packet.encode(), addr)
                        
                        # Transition to ESTABLISHED
                        self.window["next_seq_to_send"] = packet.ack
                        self.window["next_seq_expected"] = packet.ack
                        self.state = ESTABLISHED
                        self.wait_cond.notify_all()
                    continue

                elif self.state == SYN_RCVD and (packet.flags & ACK_FLAG) != 0:
                    # Received ACK in SYN_RCVD state (completing three-way handshake)
                    with self.recv_lock:
                        print(str(time.time()), f"Received ACK from {addr}, handshake complete")
                        
                        # Update RTT estimation if we have send time
                        if packet.ack - 1 in self.rtt_stats["send_times"]:
                            self.update_rtt(packet.ack - 1)
                        
                        # Transition to ESTABLISHED
                        self.window["next_seq_to_send"] = packet.ack
                        self.window["next_seq_expected"] = packet.ack  
                        self.state = ESTABLISHED
                        self.wait_cond.notify_all()
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
                        # Update next_seq_expected (for flow control)
                        if packet.ack > self.window["next_seq_expected"]:
                            # Calculate how many bytes were acknowledged
                            acked_bytes = packet.ack - self.window["next_seq_expected"]
                            
                            # Update in-flight bytes
                            self.window["in_flight"] = max(0, self.window["in_flight"] - acked_bytes)
                            self.window["next_seq_expected"] = packet.ack
                            
                            # Update RTT estimation
                            if packet.ack - acked_bytes in self.rtt_stats["send_times"]:
                                self.update_rtt(packet.ack - acked_bytes)
                        
                        self.wait_cond.notify_all()

                # Data packet processing (if in ESTABLISHED state)
                if self.state in [ESTABLISHED, CLOSE_WAIT] and len(packet.payload) > 0 and packet.seq == self.window["last_ack"]:
                    with self.recv_lock:
                        # Check if we have space in the receive buffer
                        if self.window["recv_len"] + len(packet.payload) <= MAX_NETWORK_BUFFER:
                            # Append payload to our receive buffer
                            self.window["recv_buf"] += packet.payload
                            self.window["recv_len"] += len(packet.payload)
                            
                            print(str(time.time()), f"Received data segment {packet.seq} with {len(packet.payload)} bytes.")
                            
                            # Update last_ack
                            self.window["last_ack"] = packet.seq + len(packet.payload)
                            
                            # Send ACK
                            ack_packet = Packet(
                                seq=self.window["next_seq_to_send"], 
                                ack=self.window["last_ack"], 
                                flags=ACK_FLAG, 
                                adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                            )
                            self.sock_fd.sendto(ack_packet.encode(), addr)
                            
                            self.wait_cond.notify_all()
                        else:
                            # Buffer full, send ACK with zero window
                            print(str(time.time()), "Receive buffer full, advertising zero window")
                            ack_packet = Packet(
                                seq=self.window["next_seq_to_send"], 
                                ack=self.window["last_ack"], 
                                flags=ACK_FLAG, 
                                adv_window=0
                            )
                            self.sock_fd.sendto(ack_packet.encode(), addr)
                    continue
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

    def establish_connection(self):
        """
        Establish connection using three-way handshake (client side)
        """
        print(str(time.time()), "Initiating connection establishment...")
        
        # Send SYN packet
        syn_packet = Packet(
            seq=self.window["next_seq_to_send"], 
            ack=0, 
            flags=SYN_FLAG, 
            adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
        )
        
        # Record send time for RTT estimation
        self.rtt_stats["send_times"][self.window["next_seq_to_send"]] = time.time()
        
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
                    print(str(time.time()), "SYN timeout, retransmitting...")
                    self.sock_fd.sendto(syn_packet.encode(), self.conn)
                    timeout_time = time.time() + self.rtt_stats["rto"]
                
                # Wait for state change or timeout
                self.wait_cond.wait(timeout=min(remaining, 1.0))
                
                # Check if we're dying
                if self.dying:
                    raise ValueError("Socket is closing")
        
        print(str(time.time()), "Connection established successfully")
        
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
            
            print(str(time.time()), f"RTT sample: {sample_rtt:.4f}s, SRTT: {self.rtt_stats['srtt']:.4f}s, RTO: {self.rtt_stats['rto']:.4f}s")