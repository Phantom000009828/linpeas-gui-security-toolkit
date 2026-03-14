import customtkinter as ctk
import subprocess
import threading
import time

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


class LinPEAS_GUI(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.title("LinPEAS GUI Security Scanner")
        self.geometry("1300x750")

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self.high_risk = 0
        self.medium_risk = 0
        self.low_risk = 0

        self.create_sidebar()
        self.create_header()
        self.create_dashboard()

    # ---------------- SIDEBAR ---------------- #

    def create_sidebar(self):

        sidebar = ctk.CTkFrame(self, width=230)
        sidebar.grid(row=0, column=0, rowspan=2, sticky="ns")

        title = ctk.CTkLabel(
            sidebar,
            text="LINPEAS GUI",
            font=("Arial", 22, "bold")
        )
        title.pack(pady=25)

        buttons = [
            ("Full Scan", self.start_scan),
            ("System Info", self.system_info),
            ("SUID Scan", self.suid_scan),
            ("Permission Scan", self.permission_scan),
            ("Cron Jobs", self.cron_scan),
            ("Kernel Check", self.kernel_scan),
        ]

        for text, cmd in buttons:
            btn = ctk.CTkButton(
                sidebar,
                text=text,
                command=cmd,
                width=180
            )
            btn.pack(pady=7)

        export = ctk.CTkButton(
            sidebar,
            text="Export Report",
            fg_color="green",
            command=self.export_report
        )
        export.pack(pady=25)

    # ---------------- HEADER ---------------- #

    def create_header(self):

        header = ctk.CTkFrame(self, height=70)
        header.grid(row=0, column=1, sticky="ew")

        title = ctk.CTkLabel(
            header,
            text="Linux Privilege Escalation Dashboard",
            font=("Arial", 28, "bold")
        )
        title.pack(pady=20)

    # ---------------- DASHBOARD ---------------- #

    def create_dashboard(self):

        main = ctk.CTkFrame(self)
        main.grid(row=1, column=1, sticky="nsew")

        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(3, weight=1)

        self.progress = ctk.CTkProgressBar(main, height=18)
        self.progress.grid(row=0, column=0, padx=30, pady=20, sticky="ew")
        self.progress.set(0)

        stats = ctk.CTkFrame(main)
        stats.grid(row=1, column=0, padx=30, pady=10, sticky="ew")

        stats.grid_columnconfigure((0, 1, 2), weight=1)

        self.high_label = self.stat_card(stats, "HIGH", "red", 0)
        self.medium_label = self.stat_card(stats, "MEDIUM", "orange", 1)
        self.low_label = self.stat_card(stats, "LOW", "cyan", 2)

        console_label = ctk.CTkLabel(
            main,
            text="Scan Console",
            font=("Consolas", 16)
        )
        console_label.grid(row=2, column=0, pady=(15, 5))

        self.console = ctk.CTkTextbox(
            main,
            font=("Consolas", 13)
        )

        self.console.grid(
            row=3,
            column=0,
            padx=30,
            pady=10,
            sticky="nsew"
        )

    def stat_card(self, parent, title, color, column):

        frame = ctk.CTkFrame(parent)
        frame.grid(row=0, column=column, padx=10, pady=10, sticky="ew")

        label = ctk.CTkLabel(frame, text=title)
        label.pack(pady=5)

        value = ctk.CTkLabel(
            frame,
            text="0",
            font=("Arial", 22, "bold"),
            text_color=color
        )
        value.pack()

        return value

    # ---------------- UTILITIES ---------------- #

    def log(self, text):

        self.console.insert("end", text + "\n")
        self.console.see("end")

    def run(self, command):

        try:
            output = subprocess.check_output(
                command,
                shell=True,
                text=True
            )
            return output
        except:
            return "Command failed"

    # ---------------- SCANS ---------------- #

    def system_info(self):

        self.log("=== SYSTEM INFO ===")

        self.log(self.run("whoami"))
        self.log(self.run("uname -a"))

    def suid_scan(self):

        self.log("\n=== SUID BINARIES ===")

        result = self.run(
            "find / -perm -4000 -type f 2>/dev/null | head"
        )

        self.log(result)

        self.medium_risk += 1
        self.update_stats()

    def permission_scan(self):

        self.log("\n=== WRITABLE FILES ===")

        result = self.run(
            "find / -writable -type f 2>/dev/null | head"
        )

        self.log(result)

        self.high_risk += 1
        self.update_stats()

    def cron_scan(self):

        self.log("\n=== CRON JOBS ===")

        result = self.run("crontab -l")

        self.log(result)

        self.low_risk += 1
        self.update_stats()

    def kernel_scan(self):

        self.log("\n=== KERNEL VERSION ===")

        result = self.run("uname -r")

        self.log(result)

    # ---------------- FULL SCAN ---------------- #

    def start_scan(self):

        thread = threading.Thread(target=self.full_scan)
        thread.start()

    def full_scan(self):

        self.console.delete("1.0", "end")

        self.log("Starting LinPEAS scan...\n")

        for i in range(100):

            self.progress.set(i / 100)

            time.sleep(0.01)

        self.system_info()
        self.suid_scan()
        self.permission_scan()
        self.cron_scan()
        self.kernel_scan()

        self.log("\nScan Completed")

    # ---------------- STATS ---------------- #

    def update_stats(self):

        self.high_label.configure(text=str(self.high_risk))
        self.medium_label.configure(text=str(self.medium_risk))
        self.low_label.configure(text=str(self.low_risk))

    # ---------------- REPORT ---------------- #

    def export_report(self):

        data = self.console.get("1.0", "end")

        with open("linpeas_report.txt", "w") as f:
            f.write(data)

        self.log("\nReport saved -> linpeas_report.txt")


app = LinPEAS_GUI()
app.mainloop()
