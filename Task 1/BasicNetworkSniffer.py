import customtkinter as ctk
import threading
import tkinter as tk
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw

# Attempting to import HTTP layer from Scapy if available
try:
    from scapy.layers.http import HTTP  # Import HTTP only if available
except ImportError:
    HTTP = None  # If HTTP layer is unavailable, set HTTP to None

# Initialize CustomTkinter settings
ctk.set_appearance_mode("dark")  # Set dark mode for the GUI
ctk.set_default_color_theme("blue")  # Set default theme to blue

# Main application class for the Network Sniffer app
class NetworkSnifferApp(ctk.CTk):
    def __init__(self):
        # Initialize parent class (CTk) and set up initial attributes
        super().__init__()
        self.scrollbar = None
        self.text_display = None
        self.button_stop = None
        self.button_start = None
        self.label_title = None
        self.title("Network Sniffer")  # Window title
        self.geometry("875x550")  # Window size
        self.packet_capture = False  # Variable to control packet capture state
        self.sniffer_thread = None  # Store reference to sniffer thread
        self.create_widgets()  # Call to create the GUI elements

    def create_widgets(self):
        # Create and pack the title label
        self.label_title = ctk.CTkLabel(self, text="Basic Network Sniffer", font=("Arial", 30, "bold"), text_color="white", bg_color="transparent")
        self.label_title.pack(pady=20)

        # Frame to organize buttons
        button_frame = ctk.CTkFrame(self, fg_color="transparent", bg_color="transparent")
        button_frame.pack(pady=10)

        # Start button
        self.button_start = ctk.CTkButton(button_frame, text="Start Sniffing", width=200, height=40, font=("Arial", 14), command=self.start_capture, corner_radius=10, hover_color="#444")
        self.button_start.grid(row=0, column=0, padx=10)

        # Stop button
        self.button_stop = ctk.CTkButton(button_frame, text="Stop Sniffing", width=200, height=40, font=("Arial", 14), command=self.stop_capture, corner_radius=10, hover_color="#444")
        self.button_stop.grid(row=0, column=1, padx=10)

        # Frame to hold the packet display area
        display_frame = ctk.CTkFrame(self, fg_color="transparent", bg_color="transparent")
        display_frame.pack(padx=20, pady=10, fill="both", expand=True)

        # Text widget to display captured packet data
        self.text_display = tk.Text(display_frame, width=760, height=400, font=("Courier", 12), wrap="word", bg="#2d2d2d", fg="white", insertbackground="white")
        self.text_display.pack(pady=10, fill="both", expand=True)

        # Configuring text tags for different types of packets with identifying colors
        self.text_display.tag_configure("ethernet", foreground="#56B4D3")
        self.text_display.tag_configure("ip", foreground="#E69F00")
        self.text_display.tag_configure("tcp", foreground="#009E73")
        self.text_display.tag_configure("udp", foreground="#D55E00")
        self.text_display.tag_configure("icmp", foreground="#F0E442")
        self.text_display.tag_configure("dns", foreground="#CC79A7")
        self.text_display.tag_configure("http", foreground="#0072B2")

        # scrollbar
        self.scrollbar = tk.Scrollbar(display_frame, command=self.text_display.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.text_display.config(yscrollcommand=self.scrollbar.set)

    def start_capture(self):
        # Start packet capturing in a separate thread if not already capturing
        if not self.packet_capture:
            self.packet_capture = True
            self.sniffer_thread = threading.Thread(target=self.sniff_packets)
            self.sniffer_thread.start()  # Start sniffing in background thread
            self.text_display.insert("end", "Packet capture started...\n")

    def stop_capture(self):
        # Stop packet capture
        self.packet_capture = False
        self.text_display.insert("end", "Stopping packet capture...\n")

    def sniff_packets(self):
        # Sniff packets in a loop, call packet_handler for each captured packet
        sniff(prn=self.packet_handler, stop_filter=self.should_stop_sniffing, store=False)

    def should_stop_sniffing(self, packet):
        # Stop sniffing if packet_capture is set to False
        return not self.packet_capture

    def packet_handler(self, packet):
        # Handle each captured packet, display relevant details
        if not self.packet_capture:
            return

        # Ethernet Layer (MAC addresses)
        if packet.haslayer(Ether):
            eth_layer = packet.getlayer(Ether)
            self.insert_with_tag(f"\nEthernet Frame: Source MAC: {eth_layer.src}, Destination MAC: {eth_layer.dst}\n", "ethernet")

        # IP Layer (Source and Destination IP addresses)
        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            self.insert_with_tag(f"IP Packet: Source IP: {ip_layer.src}, Destination IP: {ip_layer.dst}\n", "ip")

            # ICMP (for ping-like packets)
            if packet.haslayer(ICMP):
                icmp_layer = packet.getlayer(ICMP)
                self.insert_with_tag(f"ICMP Packet: Type: {icmp_layer.type}, Code: {icmp_layer.code}\n", "icmp")

            # TCP (Transmission Control Protocol)
            elif packet.haslayer(TCP):
                tcp_layer = packet.getlayer(TCP)
                self.insert_with_tag(f"TCP Segment: Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}\n", "tcp")
                self.insert_with_tag(f"Flags: {tcp_layer.flags}\n", "tcp")

                # Check if there's HTTP data inside TCP packet
                if packet.haslayer(Raw) and b"HTTP" in packet[Raw].load:
                    http_data = packet[Raw].load.decode(errors="ignore")
                    self.extract_http_url(http_data)

            # UDP (User Datagram Protocol)
            elif packet.haslayer(UDP):
                udp_layer = packet.getlayer(UDP)
                self.insert_with_tag(f"UDP Segment: Source Port: {udp_layer.sport}, Destination Port: {udp_layer.dport}\n", "udp")

                # DNS (Domain Name System - can reveal hostnames)
                if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                    dns_query = packet.getlayer(DNSQR)
                    self.insert_with_tag(f"DNS Query: {dns_query.qname.decode()}\n", "dns")

        # Scroll the display to the bottom after inserting new data
        self.text_display.see("end")

    def insert_with_tag(self, text, tag):
        """Helper function to insert text with a specific tag for formatting"""
        self.text_display.insert("end", text, tag)

    def extract_http_url(self, http_data):
        """Extract HTTP URLs from HTTP GET or POST requests"""
        lines = http_data.split("\r\n")
        for line in lines:
            if "GET" in line or "POST" in line:
                try:
                    url = line.split(" ")[1]  # Get the URL part of the GET/POST request
                    self.insert_with_tag(f"HTTP URL: {url}\n", "http")
                except IndexError:
                    continue  # Skip malformed lines

# Run the application
if __name__ == "__main__":
    app = NetworkSnifferApp()  # Instantiate the app
    app.mainloop()  # Start the Tkinter main loop to display the GUI
