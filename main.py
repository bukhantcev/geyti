

import requests
from bs4 import BeautifulSoup
import socket
import ipaddress
import threading
import tkinter as tk
from tkinter import messagebox
import subprocess
from concurrent.futures import ThreadPoolExecutor

def is_http_open(ip, port=80, timeout=0.5):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except:
        return False

def scan_network(subnet, callback):
    def worker():
        found_ips = []
        network = ipaddress.ip_network(subnet, strict=False)
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(is_http_open, str(ip)): str(ip) for ip in network.hosts()}
            for future in futures:
                ip = futures[future]
                if future.result():
                    found_ips.append(ip)
        callback(found_ips)
    threading.Thread(target=worker, daemon=True).start()

def open_web(ip):
    url = f"http://{ip}"
    subprocess.run(["open", "-a", "Safari", url])

def fetch_port_details(ip, port_index):
    try:
        url = f"http://{ip}"
        r = requests.get(url, timeout=3)
        soup = BeautifulSoup(r.text, "html.parser")
        div = soup.find("div", id=f"id-dmx-port-{port_index}-info")
        if not div:
            return ["Нет данных"]
        lines = []
        for li in div.find_all("li"):
            text = li.get_text(strip=True)
            lines.append(text)
        return lines if lines else ["Нет данных"]
    except Exception as e:
        return [f"Ошибка: {e}"]

def show_ui():
    def on_scan():
        btn_scan.config(state="disabled")
        listbox.delete(0, tk.END)
        scan_network(entry_subnet.get(), update_list)

    def update_list(ip_list):
        for ip in ip_list:
            listbox.insert(tk.END, ip)
        btn_scan.config(state="normal")
        if not ip_list:
            messagebox.showinfo("Сканирование завершено", "Устройства не найдены.")

    def on_select(event):
        if not listbox.curselection():
            return
        selected_index = listbox.curselection()[0]
        item_text = listbox.get(selected_index)

        if item_text.startswith("   "):  # инфа о порте, ничего не делаем
            return
        elif item_text.startswith("Порт"):
            if listbox.itemcget(selected_index, "fg") == "blue":
                while listbox.size() > selected_index + 1 and listbox.get(selected_index + 1).startswith("   "):
                    listbox.delete(selected_index + 1)
                listbox.itemconfig(selected_index, {"fg": "black"})
            else:
                parent_index = selected_index - 1
                while parent_index >= 0 and (listbox.get(parent_index).startswith("   ") or listbox.get(parent_index).startswith("Порт")):
                    parent_index -= 1
                ip = listbox.get(parent_index)
                port_number = int(item_text.split(" ")[-1])
                details = fetch_port_details(ip, port_number)
                for i, line in enumerate(details):
                    listbox.insert(selected_index + 1 + i, f"   {line}")
                listbox.itemconfig(selected_index, {"fg": "blue"})
        else:  # это IP
            if listbox.itemcget(selected_index, "fg") == "blue":
                while listbox.size() > selected_index + 1 and (listbox.get(selected_index + 1).startswith("Порт") or listbox.get(selected_index + 1).startswith("   ")):
                    listbox.delete(selected_index + 1)
                listbox.itemconfig(selected_index, {"fg": "black"})
            else:
                for i in range(1, 9):
                    listbox.insert(selected_index + i, f"Порт {i}")
                listbox.itemconfig(selected_index, {"fg": "blue"})

    root = tk.Tk()
    root.title("Сканер гейтов с веб-интерфейсом")

    tk.Label(root, text="Подсеть (например, 192.168.1.0/24):").pack()
    entry_subnet = tk.Entry(root, width=30)
    entry_subnet.insert(0, "192.168.1.0/24")
    entry_subnet.pack()

    btn_scan = tk.Button(root, text="Сканировать", command=on_scan)
    btn_scan.pack(pady=5)

    listbox = tk.Listbox(root, width=50, height=20)
    listbox.pack()
    listbox.bind("<Double-Button-1>", lambda e: open_web(listbox.get(listbox.curselection()[0])))
    listbox.bind("<<ListboxSelect>>", on_select)

    root.mainloop()

if __name__ == "__main__":
    show_ui()