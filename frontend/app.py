import tkinter as tk
from tkinter import ttk, messagebox
import urllib.request
import urllib.parse
import json


class VulnerabilityTrackerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Vulnerability Tracker")
        self.root.geometry("1000x650")

        self.api_url = ""
        self.api_key = ""

        self.show_connection_dialog()


    def show_connection_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Connect to API")
        dialog.geometry("420x220")
        dialog.grab_set()

        ttk.Label(dialog, text="API URL").pack(pady=(20, 5))

        url_entry = ttk.Entry(dialog, width=45)
        url_entry.insert(0, "http://localhost:8000")
        url_entry.pack()

        ttk.Label(dialog, text="X-API-Key").pack(pady=(15, 5))

        key_entry = ttk.Entry(dialog, width=45, show="*")
        key_entry.pack()

        def connect():
            self.api_url = url_entry.get().rstrip("/")
            self.api_key = key_entry.get()

            if not self.api_url:
                messagebox.showerror(
                    "Error",
                    "Please enter the API URL"
                )
                return

            try:
                self.api_get("/")
            except Exception as exc:
                messagebox.showerror(
                    "Connection failed",
                    str(exc)
                )
                return

            dialog.destroy()
            self.build_main_window()
            self.refresh_all()

        ttk.Button(
            dialog,
            text="Connect",
            command=connect
        ).pack(pady=20)


    def api_get(self, endpoint):
        request = urllib.request.Request(
            self.api_url + endpoint
        )

        with urllib.request.urlopen(request) as response:
            return json.loads(response.read().decode())


    def api_write(self, endpoint, method, data):
        body = json.dumps(data).encode()

        request = urllib.request.Request(
            self.api_url + endpoint,
            data=body,
            method=method,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": self.api_key
            }
        )

        with urllib.request.urlopen(request) as response:
            return json.loads(response.read().decode())


    def build_main_window(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill="x")

        ttk.Label(
            top,
            text="Vulnerability Tracker",
            font=("Arial", 18, "bold")
        ).pack(side="left")

        ttk.Button(
            top,
            text="Refresh",
            command=self.refresh_all
        ).pack(side="right")

        summary_frame = ttk.LabelFrame(
            self.root,
            text="Summary",
            padding=10
        )
        summary_frame.pack(fill="x", padx=10, pady=5)

        self.summary_label = ttk.Label(
            summary_frame,
            text="Loading..."
        )
        self.summary_label.pack(anchor="w")

        filter_frame = ttk.LabelFrame(
            self.root,
            text="Filters",
            padding=10
        )
        filter_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(
            filter_frame,
            text="Status:"
        ).pack(side="left")

        self.status_filter = ttk.Combobox(
            filter_frame,
            values=[
                "",
                "Open",
                "In Progress",
                "Resolved"
            ],
            state="readonly",
            width=15
        )
        self.status_filter.pack(side="left", padx=5)

        ttk.Label(
            filter_frame,
            text="Severity:"
        ).pack(side="left", padx=(20, 0))

        self.severity_filter = ttk.Combobox(
            filter_frame,
            values=[
                "",
                "Critical",
                "High",
                "Medium",
                "Low"
            ],
            state="readonly",
            width=15
        )
        self.severity_filter.pack(side="left", padx=5)

        ttk.Button(
            filter_frame,
            text="Apply",
            command=self.load_findings
        ).pack(side="left", padx=10)

        table_frame = ttk.Frame(
            self.root,
            padding=10
        )
        table_frame.pack(fill="both", expand=True)

        columns = (
            "id",
            "asset",
            "team",
            "cve",
            "severity",
            "status",
            "discovered",
            "due",
            "resolved"
        )

        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings"
        )

        headings = {
            "id": "ID",
            "asset": "Asset",
            "team": "Team",
            "cve": "CVE",
            "severity": "Severity",
            "status": "Status",
            "discovered": "Discovered",
            "due": "Due",
            "resolved": "Resolved"
        }

        for column in columns:
            self.tree.heading(
                column,
                text=headings[column]
            )
            self.tree.column(
                column,
                width=100
            )

        self.tree.pack(
            fill="both",
            expand=True
        )

        actions = ttk.Frame(
            self.root,
            padding=10
        )
        actions.pack(fill="x")

        ttk.Button(
            actions,
            text="Create Finding",
            command=self.create_finding_dialog
        ).pack(side="left")

        ttk.Button(
            actions,
            text="Update Selected Status",
            command=self.update_status_dialog
        ).pack(side="left", padx=10)


    def refresh_all(self):
        self.load_findings()
        self.load_summary()


    def load_summary(self):
        try:
            data = self.api_get("/summary")
            summary = data["summary"]

            text = (
                f"Critical: {summary['Critical']}    "
                f"High: {summary['High']}    "
                f"Medium: {summary['Medium']}    "
                f"Low: {summary['Low']}"
            )

            self.summary_label.config(text=text)

        except Exception as exc:
            messagebox.showerror(
                "Summary error",
                str(exc)
            )


    def load_findings(self):
        status = self.status_filter.get()
        severity = self.severity_filter.get()

        params = {}

        if status:
            params["status"] = status

        if severity:
            params["severity"] = severity

        endpoint = "/findings"

        if params:
            endpoint += "?" + urllib.parse.urlencode(params)

        try:
            data = self.api_get(endpoint)

            for item in self.tree.get_children():
                self.tree.delete(item)

            for finding in data["findings"]:
                self.tree.insert(
                    "",
                    "end",
                    values=(
                        finding["id"],
                        finding["asset"],
                        finding["team"],
                        finding["cve_id"],
                        finding["severity"],
                        finding["status"],
                        finding["discovered_on"],
                        finding["due_date"],
                        finding["resolved_on"] or ""
                    )
                )

        except Exception as exc:
            messagebox.showerror(
                "Findings error",
                str(exc)
            )


    def create_finding_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Create Finding")
        dialog.geometry("400x420")

        fields = {}

        labels = [
            ("asset_id", "Asset ID"),
            ("vulnerability_id", "Vulnerability ID"),
            ("discovered_on", "Discovered date"),
            ("due_date", "Due date")
        ]

        for key, label in labels:
            ttk.Label(
                dialog,
                text=label
            ).pack(pady=(10, 2))

            entry = ttk.Entry(
                dialog,
                width=30
            )
            entry.pack()

            fields[key] = entry

        ttk.Label(
            dialog,
            text="Status"
        ).pack(pady=(10, 2))

        status_box = ttk.Combobox(
            dialog,
            values=[
                "Open",
                "In Progress",
                "Resolved"
            ],
            state="readonly",
            width=27
        )
        status_box.set("Open")
        status_box.pack()

        def submit():
            try:
                data = {
                    "asset_id": int(
                        fields["asset_id"].get()
                    ),
                    "vulnerability_id": int(
                        fields["vulnerability_id"].get()
                    ),
                    "status": status_box.get(),
                    "discovered_on":
                        fields["discovered_on"].get(),
                    "due_date":
                        fields["due_date"].get()
                }

                result = self.api_write(
                    "/findings",
                    "POST",
                    data
                )

                messagebox.showinfo(
                    "Success",
                    f"Finding created with ID "
                    f"{result['id']}"
                )

                dialog.destroy()
                self.refresh_all()

            except Exception as exc:
                messagebox.showerror(
                    "Create error",
                    str(exc)
                )

        ttk.Button(
            dialog,
            text="Create",
            command=submit
        ).pack(pady=20)


    def update_status_dialog(self):
        selected = self.tree.selection()

        if not selected:
            messagebox.showwarning(
                "No selection",
                "Select a finding first"
            )
            return

        values = self.tree.item(
            selected[0]
        )["values"]

        finding_id = values[0]

        dialog = tk.Toplevel(self.root)
        dialog.title("Update Finding")
        dialog.geometry("350x250")

        ttk.Label(
            dialog,
            text=f"Finding ID: {finding_id}"
        ).pack(pady=15)

        status_box = ttk.Combobox(
            dialog,
            values=[
                "Open",
                "In Progress",
                "Resolved"
            ],
            state="readonly",
            width=25
        )

        status_box.set(values[5])
        status_box.pack(pady=5)

        ttk.Label(
            dialog,
            text="Resolved date (YYYY-MM-DD)"
        ).pack(pady=(15, 5))

        resolved_entry = ttk.Entry(
            dialog,
            width=28
        )
        resolved_entry.pack()

        def submit():
            try:
                data = {
                    "status": status_box.get()
                }

                if status_box.get() == "Resolved":
                    data["resolved_on"] = (
                        resolved_entry.get()
                    )

                result = self.api_write(
                    f"/findings/{finding_id}",
                    "PATCH",
                    data
                )

                messagebox.showinfo(
                    "Success",
                    result["message"]
                )

                dialog.destroy()
                self.refresh_all()

            except Exception as exc:
                messagebox.showerror(
                    "Update error",
                    str(exc)
                )

        ttk.Button(
            dialog,
            text="Update",
            command=submit
        ).pack(pady=20)


if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityTrackerApp(root)
    root.mainloop()
