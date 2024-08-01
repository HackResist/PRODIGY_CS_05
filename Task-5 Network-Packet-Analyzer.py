# This Code Written By Lokesh (HackResist)
import tkinter as tk
from tkinter import messagebox, scrolledtext
from scapy.all import sniff, IP, TCP


class PacketSnifferGUI:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("Packet Sniffer Tool")
        self.root.geometry("600x400")
        self.root.config(bg="#2b3d3d")

        self.terms_accepted = False

        self.show_disclaimer()

    def show_disclaimer(self):
        # Create disclaimer text
        disclaimer_text = (
            "#----------------------- Packet Sniffer Tool Disclaimer --------------------------#\n\n"
            "This tool is for educational and ethical use only.\n"
            " Unauthorized use is prohibited. By using this tool, you agree to:\n\n"
            "1. Use it only on networks you have permission to access.\n"
            "2. Abide by all laws and terms of service.               \n"
            "3. Avoid harming or exploiting any networks.             \n"
            "4. Not intercept or store sensitive information.         \n"
            "5. Refrain from redistributing or selling it without permission.\n"
            "6. Accept that the author is not liable for any damages.  \n"
            "7. Respect the privacy and security of all networks you monitor."
        )

        # Create and place the disclaimer label
        self.disclaimer_label = tk.Label(self.root, text=disclaimer_text, wraplength=580, justify="center", bg="#ECFFE6", padx=10, pady=10)
        self.disclaimer_label.pack(fill=tk.NONE, expand=True)

        # Create and place the button frame for Accept and Reject
        button_frame = tk.Frame(self.root, bg="#2b3d3d")
        button_frame.pack(pady=10)

        tk.Button(button_frame, text="Accept", command=self.accept_terms, bg="#4caf50", fg="white").pack(side=tk.LEFT, padx=10, pady=10)
        tk.Button(button_frame, text="Reject", command=self.reject_terms, bg="#f44336", fg="white").pack(side=tk.RIGHT, padx=10, pady=10)

    def accept_terms(self):
        self.terms_accepted = True
        self.disclaimer_label.pack_forget()  # Remove disclaimer label
        self.setup_main_window()

    def reject_terms(self):
        response = messagebox.askyesno("Confirm Exit", "Are you sure you want to exit? You must accept the terms to use the application.")
        if response:
            self.root.quit()

    def setup_main_window(self):
        # Remove disclaimer-related elements
        for widget in self.root.winfo_children():
            widget.pack_forget()

        # Create and place the result text area
        self.result_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, bg="#1e1e1e", fg="white")
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create and place the button frame for Start Sniffing, Stop Sniffing, and Clear Results
        button_frame = tk.Frame(self.root, bg="#2b3d3d")
        button_frame.pack(pady=10)

        tk.Button(button_frame, text="Start Sniffing", command=self.start_sniffing, bg="#4caf50", fg="white").pack(pady=5)
        tk.Button(button_frame, text="Stop Sniffing", command=self.stop_sniffing, bg="#f44336", fg="white").pack(pady=5)
        tk.Button(button_frame, text="Clear Results", command=self.clear_results, bg="#ff9800", fg="white").pack(pady=5)

    def start_sniffing(self):
        if not self.terms_accepted:
            messagebox.showerror("Error", "You must accept the terms before starting.")
            return

        self.result_text.delete(1.0, tk.END)  # Clear previous results
        self.sniffing = True
        self.sniff_packets()

    def stop_sniffing(self):
        self.sniffing = False

    def sniff_packets(self):
        def packet_sniff(packet):
            if packet.haslayer(TCP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                protocol = packet[IP].proto
                payload = str(packet[TCP].payload)

                output_string = (f"Source IP: {src_ip}\n"
                                 f"Destination IP: {dst_ip}\n"
                                 f"Source Port: {src_port}\n"
                                 f"Destination Port: {dst_port}\n"
                                 f"Protocol: {protocol}\n"
                                 f"Payload: {payload[:50]}...\n\n")

                self.result_text.insert(tk.END, output_string)
                self.result_text.see(tk.END)

                with open('packet_sniffer_results.txt', 'a') as f:
                    f.write(output_string)

        sniff(filter="tcp", prn=packet_sniff, store=0, count=10)
        if self.sniffing:
            self.root.after(100, self.sniff_packets)

    def clear_results(self):
        self.result_text.delete(1.0, tk.END)

    def run(self):
        self.root.mainloop()

if __name__ == '__main__':
    app = PacketSnifferGUI()
    app.run()
