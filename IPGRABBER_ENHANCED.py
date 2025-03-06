import socket
import dns.resolver
import dns.reversename
import json
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from tkinter.font import Font

class DNSLookupApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced DNS Lookup Tool")
        self.root.geometry("900x700")
        self.root.minsize(600, 500)
        
        # Set app icon if needed
        # self.root.iconbitmap("dns_icon.ico")
        
        # Configure styles
        self.style = ttk.Style()
        self.style.configure("TButton", font=("Helvetica", 10))
        self.style.configure("TCheckbutton", font=("Helvetica", 10))
        self.style.configure("TLabel", font=("Helvetica", 10))
        
        # Create main frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create title
        title_label = ttk.Label(main_frame, text="Advanced DNS Lookup Tool", 
                               font=("Helvetica", 16, "bold"))
        title_label.pack(pady=(0, 10))
        
        # Create input frame
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=5)
        
        # Domain input
        ttk.Label(input_frame, text="Domain:").pack(side=tk.LEFT, padx=(0, 5))
        self.domain_entry = ttk.Entry(input_frame, width=40, font=("Helvetica", 11))
        self.domain_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.domain_entry.bind("<Return>", lambda e: self.lookup_dns())
        
        # Lookup button
        lookup_button = ttk.Button(input_frame, text="Lookup DNS", command=self.lookup_dns)
        lookup_button.pack(side=tk.LEFT)
        
        # Record types frame
        records_frame = ttk.LabelFrame(main_frame, text="DNS Record Types", padding=5)
        records_frame.pack(fill=tk.X, pady=10)
        
        # Record type checkboxes
        self.record_vars = {}
        record_types = [
            ("A (IPv4)", "A"), 
            ("AAAA (IPv6)", "AAAA"),
            ("MX (Mail)", "MX"),
            ("NS (Nameservers)", "NS"),
            ("TXT", "TXT"),
            ("SOA", "SOA"),
            ("CNAME", "CNAME"),
            ("PTR (Reverse DNS)", "PTR")
        ]
        
        # Create 2 rows of checkboxes
        checkbox_frame1 = ttk.Frame(records_frame)
        checkbox_frame1.pack(fill=tk.X)
        checkbox_frame2 = ttk.Frame(records_frame)
        checkbox_frame2.pack(fill=tk.X)
        
        for i, (label, value) in enumerate(record_types):
            var = tk.BooleanVar(value=True)
            self.record_vars[value] = var
            
            if i < 4:  # First row
                parent = checkbox_frame1
            else:      # Second row
                parent = checkbox_frame2
                
            ttk.Checkbutton(parent, text=label, variable=var).pack(side=tk.LEFT, padx=10, pady=5)
        
        # Select/Deselect All buttons
        select_frame = ttk.Frame(records_frame)
        select_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(select_frame, text="Select All", 
                  command=lambda: self.toggle_all(True)).pack(side=tk.LEFT, padx=5)
        ttk.Button(select_frame, text="Deselect All", 
                  command=lambda: self.toggle_all(False)).pack(side=tk.LEFT, padx=5)
        
        # Progress indicator
        self.progress_frame = ttk.Frame(main_frame)
        self.progress_frame.pack(fill=tk.X, pady=5)
        self.progress_label = ttk.Label(self.progress_frame, text="Looking up DNS records...")
        self.progress_bar = ttk.Progressbar(self.progress_frame, mode="indeterminate")
        
        # Results area
        result_frame = ttk.LabelFrame(main_frame, text="DNS Records", padding=5)
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Create a notebook (tabs) for displaying the results
        self.notebook = ttk.Notebook(result_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # General tab
        self.general_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.general_tab, text="Overview")
        
        # Output text widget with scrollbars
        self.output_text = scrolledtext.ScrolledText(self.general_tab, wrap=tk.WORD,
                                                    font=("Courier New", 10))
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.config(state=tk.DISABLED)
        
        # Create tags for colored text
        self.output_text.tag_configure("header", font=("Courier New", 11, "bold"))
        self.output_text.tag_configure("section", font=("Courier New", 10, "bold"), foreground="blue")
        self.output_text.tag_configure("data", font=("Courier New", 10))
        
        # Copy to clipboard button
        copy_button = ttk.Button(result_frame, text="Copy Results", command=self.copy_to_clipboard)
        copy_button.pack(side=tk.RIGHT, pady=5)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Store tabs to keep track of them
        self.additional_tabs = []
        
        # Set focus to domain entry
        self.domain_entry.focus()
    
    def toggle_all(self, state):
        """Select or deselect all record type checkboxes"""
        for var in self.record_vars.values():
            var.set(state)
    
    def show_loading(self):
        """Show loading progress bar"""
        self.progress_label.pack(side=tk.LEFT, padx=5)
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.progress_bar.start(10)
        self.status_var.set("Looking up DNS records...")
        self.root.update()
    
    def hide_loading(self):
        """Hide loading progress bar"""
        self.progress_bar.stop()
        self.progress_bar.pack_forget()
        self.progress_label.pack_forget()
        self.status_var.set("Ready")
        self.root.update()
    
    def copy_to_clipboard(self):
        """Copy results to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(self.output_text.get(1.0, tk.END))
        self.status_var.set("Results copied to clipboard")
    
    def clear_output(self):
        """Clear the output area"""
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state=tk.DISABLED)
        
        # Remove any additional tabs (except the Overview tab)
        for tab in self.additional_tabs:
            self.notebook.forget(tab)
        
        self.additional_tabs = []
    
    def get_dns_records(self, domain):
        """Get DNS records for the specified domain"""
        selected_types = [record_type for record_type, var in self.record_vars.items() if var.get()]
        
        if not selected_types:
            return {"domain": domain, "records": {}, "error": "No record types selected"}
        
        results = {
            "domain": domain,
            "records": {}
        }
        
        for record_type in selected_types:
            try:
                if record_type == 'PTR':
                    # For PTR, we need to first get the IP(s)
                    if 'A' in results['records']:
                        ptrs = []
                        for ip in results['records']['A']:
                            try:
                                ptr = str(dns.reversename.from_address(ip))
                                answers = dns.resolver.resolve(ptr, 'PTR')
                                for rdata in answers:
                                    ptrs.append(str(rdata.target).rstrip('.'))
                            except Exception:
                                continue
                        results['records']['PTR'] = ptrs
                else:
                    answers = dns.resolver.resolve(domain, record_type)
                    if record_type == 'A':
                        results['records'][record_type] = [rdata.address for rdata in answers]
                    elif record_type == 'AAAA':
                        results['records'][record_type] = [rdata.address for rdata in answers]
                    elif record_type == 'MX':
                        results['records'][record_type] = [f"{rdata.preference} {rdata.exchange}" for rdata in answers]
                    elif record_type == 'NS':
                        results['records'][record_type] = [str(rdata.target).rstrip('.') for rdata in answers]
                    elif record_type == 'TXT':
                        results['records'][record_type] = [str(rdata).strip('"') for rdata in answers]
                    elif record_type == 'SOA':
                        for rdata in answers:
                            results['records'][record_type] = {
                                'mname': str(rdata.mname).rstrip('.'),
                                'rname': str(rdata.rname).rstrip('.'),
                                'serial': rdata.serial,
                                'refresh': rdata.refresh,
                                'retry': rdata.retry,
                                'expire': rdata.expire,
                                'minimum': rdata.minimum
                            }
                    elif record_type == 'CNAME':
                        results['records'][record_type] = [str(rdata.target).rstrip('.') for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
                # Record type not found for this domain
                results['records'][record_type] = []
            except Exception as e:
                results['records'][record_type] = []
                self.update_status(f"Error getting {record_type} records: {e}")
        
        return results
    
    def update_status(self, message):
        """Update status bar with a message"""
        self.status_var.set(message)
        self.root.update()
    
    def display_results(self, results):
        """Display DNS lookup results in the UI"""
        self.clear_output()
        
        domain = results.get('domain', 'Unknown')
        records = results.get('records', {})
        
        # Get output text widget ready
        self.output_text.config(state=tk.NORMAL)
        
        # Display domain in header
        self.output_text.insert(tk.END, f"DNS Records for {domain}\n", "header")
        self.output_text.insert(tk.END, "="*50 + "\n\n")
        
        # Display error if there is one
        if 'error' in results:
            self.output_text.insert(tk.END, f"Error: {results['error']}\n")
            self.output_text.config(state=tk.DISABLED)
            return
        
        # Create tabs for each record type that has records
        record_labels = {
            'A': 'IPv4 Addresses',
            'AAAA': 'IPv6 Addresses',
            'MX': 'Mail Servers',
            'NS': 'Name Servers',
            'TXT': 'TXT Records',
            'SOA': 'Start of Authority',
            'CNAME': 'CNAME Records',
            'PTR': 'PTR Records'
        }
        
        # Display A records (IPv4)
        if 'A' in records:
            self.output_text.insert(tk.END, "IPv4 Addresses (A):\n", "section")
            if records['A']:
                for ip in records['A']:
                    self.output_text.insert(tk.END, f"  {ip}\n", "data")
            else:
                self.output_text.insert(tk.END, "  No A records found\n", "data")
            self.output_text.insert(tk.END, "\n")
            
            # Create a tab for A records if there are any
            if records['A']:
                a_tab = ttk.Frame(self.notebook)
                self.notebook.add(a_tab, text="A Records")
                self.additional_tabs.append(a_tab)
                
                a_text = scrolledtext.ScrolledText(a_tab, wrap=tk.WORD, font=("Courier New", 10))
                a_text.pack(fill=tk.BOTH, expand=True)
                a_text.insert(tk.END, f"IPv4 Addresses for {domain}:\n\n")
                for ip in records['A']:
                    a_text.insert(tk.END, f"{ip}\n")
                a_text.config(state=tk.DISABLED)
        
        # Display AAAA records (IPv6)
        if 'AAAA' in records:
            self.output_text.insert(tk.END, "IPv6 Addresses (AAAA):\n", "section")
            if records['AAAA']:
                for ip in records['AAAA']:
                    self.output_text.insert(tk.END, f"  {ip}\n", "data")
            else:
                self.output_text.insert(tk.END, "  No AAAA records found\n", "data")
            self.output_text.insert(tk.END, "\n")
            
            # Create a tab for AAAA records if there are any
            if records['AAAA']:
                aaaa_tab = ttk.Frame(self.notebook)
                self.notebook.add(aaaa_tab, text="AAAA Records")
                self.additional_tabs.append(aaaa_tab)
                
                aaaa_text = scrolledtext.ScrolledText(aaaa_tab, wrap=tk.WORD, font=("Courier New", 10))
                aaaa_text.pack(fill=tk.BOTH, expand=True)
                aaaa_text.insert(tk.END, f"IPv6 Addresses for {domain}:\n\n")
                for ip in records['AAAA']:
                    aaaa_text.insert(tk.END, f"{ip}\n")
                aaaa_text.config(state=tk.DISABLED)
        
        # Display MX records
        if 'MX' in records:
            self.output_text.insert(tk.END, "Mail Servers (MX):\n", "section")
            if records['MX']:
                for mx in records['MX']:
                    self.output_text.insert(tk.END, f"  {mx}\n", "data")
            else:
                self.output_text.insert(tk.END, "  No MX records found\n", "data")
            self.output_text.insert(tk.END, "\n")
            
            # Create a tab for MX records if there are any
            if records['MX']:
                mx_tab = ttk.Frame(self.notebook)
                self.notebook.add(mx_tab, text="MX Records")
                self.additional_tabs.append(mx_tab)
                
                mx_text = scrolledtext.ScrolledText(mx_tab, wrap=tk.WORD, font=("Courier New", 10))
                mx_text.pack(fill=tk.BOTH, expand=True)
                mx_text.insert(tk.END, f"Mail Servers for {domain}:\n\n")
                mx_text.insert(tk.END, "Priority  Mail Server\n")
                mx_text.insert(tk.END, "-" * 50 + "\n")
                for mx in records['MX']:
                    parts = mx.split(' ', 1)
                    if len(parts) == 2:
                        mx_text.insert(tk.END, f"{parts[0].ljust(10)} {parts[1]}\n")
                    else:
                        mx_text.insert(tk.END, f"{mx}\n")
                mx_text.config(state=tk.DISABLED)
        
        # Display NS records
        if 'NS' in records:
            self.output_text.insert(tk.END, "Name Servers (NS):\n", "section")
            if records['NS']:
                for ns in records['NS']:
                    self.output_text.insert(tk.END, f"  {ns}\n", "data")
            else:
                self.output_text.insert(tk.END, "  No NS records found\n", "data")
            self.output_text.insert(tk.END, "\n")
            
            # Create a tab for NS records if there are any
            if records['NS']:
                ns_tab = ttk.Frame(self.notebook)
                self.notebook.add(ns_tab, text="NS Records")
                self.additional_tabs.append(ns_tab)
                
                ns_text = scrolledtext.ScrolledText(ns_tab, wrap=tk.WORD, font=("Courier New", 10))
                ns_text.pack(fill=tk.BOTH, expand=True)
                ns_text.insert(tk.END, f"Name Servers for {domain}:\n\n")
                for ns in records['NS']:
                    ns_text.insert(tk.END, f"{ns}\n")
                ns_text.config(state=tk.DISABLED)
        
        # Display TXT records
        if 'TXT' in records:
            self.output_text.insert(tk.END, "TXT Records:\n", "section")
            if records['TXT']:
                for txt in records['TXT']:
                    self.output_text.insert(tk.END, f"  {txt}\n", "data")
            else:
                self.output_text.insert(tk.END, "  No TXT records found\n", "data")
            self.output_text.insert(tk.END, "\n")
            
            # Create a tab for TXT records if there are any
            if records['TXT']:
                txt_tab = ttk.Frame(self.notebook)
                self.notebook.add(txt_tab, text="TXT Records")
                self.additional_tabs.append(txt_tab)
                
                txt_text = scrolledtext.ScrolledText(txt_tab, wrap=tk.WORD, font=("Courier New", 10))
                txt_text.pack(fill=tk.BOTH, expand=True)
                txt_text.insert(tk.END, f"TXT Records for {domain}:\n\n")
                for i, txt in enumerate(records['TXT'], 1):
                    txt_text.insert(tk.END, f"Record {i}:\n{txt}\n\n")
                txt_text.config(state=tk.DISABLED)
        
        # Display SOA record
        if 'SOA' in records and records['SOA']:
            self.output_text.insert(tk.END, "Start of Authority (SOA):\n", "section")
            soa = records['SOA']
            self.output_text.insert(tk.END, f"  Primary Nameserver: {soa.get('mname', 'N/A')}\n", "data")
            self.output_text.insert(tk.END, f"  Responsible Email: {soa.get('rname', 'N/A')}\n", "data")
            self.output_text.insert(tk.END, f"  Serial Number: {soa.get('serial', 'N/A')}\n", "data")
            self.output_text.insert(tk.END, f"  Refresh: {soa.get('refresh', 'N/A')} seconds\n", "data")
            self.output_text.insert(tk.END, f"  Retry: {soa.get('retry', 'N/A')} seconds\n", "data")
            self.output_text.insert(tk.END, f"  Expire: {soa.get('expire', 'N/A')} seconds\n", "data")
            self.output_text.insert(tk.END, f"  Minimum TTL: {soa.get('minimum', 'N/A')} seconds\n", "data")
            self.output_text.insert(tk.END, "\n")
            
            # Create a tab for SOA record
            soa_tab = ttk.Frame(self.notebook)
            self.notebook.add(soa_tab, text="SOA Record")
            self.additional_tabs.append(soa_tab)
            
            soa_text = scrolledtext.ScrolledText(soa_tab, wrap=tk.WORD, font=("Courier New", 10))
            soa_text.pack(fill=tk.BOTH, expand=True)
            soa_text.insert(tk.END, f"Start of Authority for {domain}:\n\n")
            soa_text.insert(tk.END, f"Primary Nameserver: {soa.get('mname', 'N/A')}\n")
            soa_text.insert(tk.END, f"Responsible Email: {soa.get('rname', 'N/A')}\n")
            soa_text.insert(tk.END, f"Serial Number: {soa.get('serial', 'N/A')}\n")
            soa_text.insert(tk.END, f"Refresh: {soa.get('refresh', 'N/A')} seconds\n")
            soa_text.insert(tk.END, f"Retry: {soa.get('retry', 'N/A')} seconds\n")
            soa_text.insert(tk.END, f"Expire: {soa.get('expire', 'N/A')} seconds\n")
            soa_text.insert(tk.END, f"Minimum TTL: {soa.get('minimum', 'N/A')} seconds\n")
            soa_text.config(state=tk.DISABLED)
        
        # Display CNAME records
        if 'CNAME' in records:
            self.output_text.insert(tk.END, "CNAME Records:\n", "section")
            if records['CNAME']:
                for cname in records['CNAME']:
                    self.output_text.insert(tk.END, f"  {cname}\n", "data")
            else:
                self.output_text.insert(tk.END, "  No CNAME records found\n", "data")
            self.output_text.insert(tk.END, "\n")
            
            # Create a tab for CNAME records if there are any
            if records['CNAME']:
                cname_tab = ttk.Frame(self.notebook)
                self.notebook.add(cname_tab, text="CNAME Records")
                self.additional_tabs.append(cname_tab)
                
                cname_text = scrolledtext.ScrolledText(cname_tab, wrap=tk.WORD, font=("Courier New", 10))
                cname_text.pack(fill=tk.BOTH, expand=True)
                cname_text.insert(tk.END, f"CNAME Records for {domain}:\n\n")
                for cname in records['CNAME']:
                    cname_text.insert(tk.END, f"{cname}\n")
                cname_text.config(state=tk.DISABLED)
        
        # Display PTR records
        if 'PTR' in records:
            self.output_text.insert(tk.END, "PTR Records (Reverse DNS):\n", "section")
            if records['PTR']:
                for ptr in records['PTR']:
                    self.output_text.insert(tk.END, f"  {ptr}\n", "data")
            else:
                self.output_text.insert(tk.END, "  No PTR records found\n", "data")
            self.output_text.insert(tk.END, "\n")
            
            # Create a tab for PTR records if there are any
            if records['PTR']:
                ptr_tab = ttk.Frame(self.notebook)
                self.notebook.add(ptr_tab, text="PTR Records")
                self.additional_tabs.append(ptr_tab)
                
                ptr_text = scrolledtext.ScrolledText(ptr_tab, wrap=tk.WORD, font=("Courier New", 10))
                ptr_text.pack(fill=tk.BOTH, expand=True)
                ptr_text.insert(tk.END, f"PTR Records for IPs of {domain}:\n\n")
                for ptr in records['PTR']:
                    ptr_text.insert(tk.END, f"{ptr}\n")
                ptr_text.config(state=tk.DISABLED)
        
        # Read-only mode
        self.output_text.config(state=tk.DISABLED)
    
    def lookup_dns(self):
        """Perform DNS lookup in a separate thread to keep UI responsive"""
        domain = self.domain_entry.get().strip()
        
        if not domain:
            messagebox.showerror("Error", "Please enter a domain name")
            return
        
        # Show loading indicator
        self.show_loading()
        
        # Start lookup in a separate thread
        lookup_thread = threading.Thread(target=self._thread_lookup_dns, args=(domain,))
        lookup_thread.daemon = True
        lookup_thread.start()
    
    def _thread_lookup_dns(self, domain):
        """Thread function for DNS lookup"""
        try:
            results = self.get_dns_records(domain)
            
            # Update UI in the main thread
            self.root.after(0, lambda: self.display_results(results))
            self.root.after(0, lambda: self.update_status(f"Completed DNS lookup for {domain}"))
        except Exception as e:
            # Show error in main thread
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
            self.root.after(0, lambda: self.update_status(f"Error: {e}"))
        finally:
            # Hide loading indicator
            self.root.after(0, self.hide_loading)

def main():
    # Create the main window
    root = tk.Tk()
    app = DNSLookupApp(root)
    
    # Start the main loop
    root.mainloop()

if __name__ == "__main__":
    main()