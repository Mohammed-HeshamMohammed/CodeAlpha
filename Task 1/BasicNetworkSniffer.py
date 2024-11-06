import customtkinter as ctk
import threading
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Initialize CustomTkinter
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class NetworkSnifferApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Network Sniffer")
        self.geometry("800x600")
        self.packet_capture = False
        self.sniffer_thread = None
        self.create_widgets()

    def create_widgets(self):
        # Title Label
        self.label_title = ctk.CTkLabel(self, text="Network Sniffer", font=("Arial", 24))
        self.label_title.pack(pady=10)

        # Start and Stop buttons
        self.button_start = ctk.CTkButton(self, text="Start Capture", command=self.start_capture)
        self.button_start.pack(pady=5)
        self.button_stop = ctk.CTkButton(self, text="Stop Capture", command=self.stop_capture)
        self.button_stop.pack(pady=5)

        # Display Area for Packets
        self.text_display = ctk.CTkTextbox(self, width=760, height=400, font=("Courier", 12))
        self.text_display.pack(pady=10)

    def start_capture(self):
        if not self.packet_capture:
            self.packet_capture = True
            self.sniffer_thread = threading.Thread(target=self.sniff_packets)
            self.sniffer_thread.start()
            self.text_display.insert("end", "Packet capture started...\n")

    def stop_capture(self):
        self.packet_capture = False
        self.text_display.insert("end", "Stopping packet capture...\n")

    def sniff_packets(self):
        # Sniff packets and call the packet_handler function for each captured packet
        sniff(prn=self.packet_handler, stop_filter=self.should_stop_sniffing, store=False)

    def should_stop_sniffing(self, packet):
        # Stop sniffing if packet_capture is set to False
        return not self.packet_capture

    def packet_handler(self, packet):
        if not self.packet_capture:
            return

        packet_info = ""
        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            packet_info += f"IP Packet: Source: {ip_layer.src}, Destination: {ip_layer.dst}\n"

            # Check for ICMP
            if packet.haslayer(ICMP):
                icmp_layer = packet.getlayer(ICMP)
                packet_info += f"ICMP Type: {icmp_layer.type}, Code: {icmp_layer.code}\n"

            # Check for TCP
            elif packet.haslayer(TCP):
                tcp_layer = packet.getlayer(TCP)
                packet_info += f"TCP Segment: Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}\n"
                packet_info += f"Flags: {tcp_layer.flags}\n"

            # Check for UDP
            elif packet.haslayer(UDP):
                udp_layer = packet.getlayer(UDP)
                packet_info += f"UDP Segment: Source Port: {udp_layer.sport}, Destination Port: {udp_layer.dport}\n"

        self.text_display.insert("end", packet_info + "\n")
        self.text_display.see("end")


# Run the application
if __name__ == "__main__":
    app = NetworkSnifferApp()
    app.mainloop()
