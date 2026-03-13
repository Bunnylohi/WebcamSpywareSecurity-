import tkinter as tk
from tkinter import messagebox, simpledialog
from PIL import Image, ImageTk
import os
import random
import string
import datetime
import cv2
import threading
import smtplib
import ssl
from email.message import EmailMessage
import json
import ctypes
import ctypes.wintypes
import sys

# ---------------- Globals ---------------- #
camera_enabled = False
cap = None
current_password = "admin123"
EMAIL_CONFIG_FILE = "email_config.sec"
ATTACH_DIR = "snapshots"
os.makedirs(ATTACH_DIR, exist_ok=True)

# ---------------- Helper Functions ---------------- #
def resource_path(filename):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, filename)

def log_action(action):
    with open("activity_log.txt", "a") as log_file:
        log_file.write(f"{datetime.datetime.now()}: {action}\n")

# ========== Windows DPAPI helpers ========== #
class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

crypt32 = ctypes.windll.crypt32
kernel32 = ctypes.windll.kernel32

def _bytes_to_blob(data: bytes) -> DATA_BLOB:
    blob = DATA_BLOB()
    blob.cbData = len(data)
    blob.pbData = ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte))
    return blob

def _blob_to_bytes(blob: DATA_BLOB) -> bytes:
    size = int(blob.cbData)
    if size == 0:
        return b""
    data = ctypes.string_at(blob.pbData, size)
    kernel32.LocalFree(blob.pbData)
    return data

def dpapi_encrypt(plaintext: bytes) -> bytes:
    in_blob = _bytes_to_blob(plaintext)
    out_blob = DATA_BLOB()
    if not crypt32.CryptProtectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
        raise RuntimeError("DPAPI encryption failed")
    return _blob_to_bytes(out_blob)

def dpapi_decrypt(ciphertext: bytes) -> bytes:
    in_blob = _bytes_to_blob(ciphertext)
    out_blob = DATA_BLOB()
    if not crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
        raise RuntimeError("DPAPI decryption failed")
    return _blob_to_bytes(out_blob)

# ---------------- Email Config ---------------- #
def save_email_config(cfg: dict):
    try:
        raw = json.dumps(cfg).encode("utf-8")
        enc = dpapi_encrypt(raw)
        with open(EMAIL_CONFIG_FILE, "wb") as f:
            f.write(enc)
        log_action("Email config saved.")
    except Exception as e:
        log_action(f"Email config save failed: {e}")
        messagebox.showerror("Error", f"Failed to save email settings.\n{e}")

def load_email_config() -> dict | None:
    try:
        if not os.path.exists(EMAIL_CONFIG_FILE):
            return None
        with open(EMAIL_CONFIG_FILE, "rb") as f:
            enc = f.read()
        raw = dpapi_decrypt(enc)
        cfg = json.loads(raw.decode("utf-8"))
        required = {"server", "port", "sender", "password", "recipient", "attach_snapshot"}
        if not required.issubset(set(cfg.keys())):
            return None
        return cfg
    except Exception as e:
        log_action(f"Email config load failed: {e}")
        return None

# ---------------- Email Alerts ---------------- #
def capture_snapshot() -> str | None:
    try:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = os.path.join(ATTACH_DIR, f"snapshot_{timestamp}.jpg")
        global cap, camera_enabled
        grabbed = False
        frame = None
        if camera_enabled and cap and cap.isOpened():
            ret, f = cap.read()
            if ret:
                grabbed = True
                frame = f
        else:
            temp_cap = cv2.VideoCapture(0)
            if temp_cap.isOpened():
                ret, f = temp_cap.read()
                temp_cap.release()
                if ret:
                    grabbed = True
                    frame = f
        if grabbed and frame is not None:
            cv2.imwrite(file_path, frame)
            return file_path
    except Exception as e:
        log_action(f"Snapshot failed: {e}")
    return None

def _send_email_smtp(cfg: dict, subject: str, body: str, attach: bool):
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = cfg["sender"]
        msg["To"] = cfg["recipient"]
        msg.set_content(body)
        attachment_path = None
        attached_flag = False
        if attach and cfg.get("attach_snapshot", True):
            attachment_path = capture_snapshot()
            if attachment_path and os.path.exists(attachment_path):
                with open(attachment_path, "rb") as f:
                    data = f.read()
                    msg.add_attachment(data, maintype="image", subtype="jpeg",
                                       filename=os.path.basename(attachment_path))
                attached_flag = True
        context = ssl.create_default_context()
        if int(cfg["port"]) == 465:
            with smtplib.SMTP_SSL(cfg["server"], int(cfg["port"]), context=context) as server:
                server.login(cfg["sender"], cfg["password"])
                server.send_message(msg)
        else:
            with smtplib.SMTP(cfg["server"], int(cfg["port"])) as server:
                server.starttls(context=context)
                server.login(cfg["sender"], cfg["password"])
                server.send_message(msg)
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_action(f"Email sent to {cfg['recipient']}; Subject: {subject}; Snapshot: {attached_flag}")
    except Exception as e:
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_action(f"Email send failed to {cfg.get('recipient','<unknown>')}; Subject: {subject}; Error: {e}")

def send_email_alert(event_type: str):
    cfg = load_email_config()
    if not cfg:
        log_action("Email alert skipped (not configured).")
        return
    subject = f"[WebCam Spyware Security] {event_type}"
    body = f"Event: {event_type}\nDate/Time: {datetime.datetime.now()}\n\nAutomated alert."
    t = threading.Thread(target=_send_email_smtp, args=(cfg, subject, body, True), daemon=True)
    t.start()

# ---------------- Camera Control ---------------- #
def disable_camera():
    global cap, camera_enabled
    if cap:
        cap.release()
    camera_enabled = False
    cam_feed_label.config(image='')
    log_action("Camera Disabled")
    success_label.config(text="Camera Disabled Successfully!", fg="green")
    send_email_alert("Camera Disabled")

def enable_camera():
    global cap, camera_enabled
    if not camera_enabled:
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            messagebox.showerror("Error", "Cannot access webcam.")
            return
        camera_enabled = True
        log_action("Camera Enabled")
        success_label.config(text="Camera Enabled Successfully!", fg="green")
        update_camera_feed()
        send_email_alert("Camera Enabled")
    else:
        messagebox.showinfo("Info", "Camera already enabled")

def update_camera_feed():
    global cap
    if camera_enabled and cap and cap.isOpened():
        ret, frame = cap.read()
        if ret:
            frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            img = Image.fromarray(frame)
            imgtk = ImageTk.PhotoImage(image=img)
            cam_feed_label.imgtk = imgtk
            cam_feed_label.config(image=imgtk)
        cam_feed_label.after(20, update_camera_feed)

# ---------------- Password Prompt ---------------- #
def password_prompt(action):
    def verify():
        entered_password = entry.get()
        if entered_password == current_password:
            pw_win.destroy()
            if remember_var.get():
                log_action("User opted to remember password")
            if action == "disable":
                disable_camera()
            elif action == "enable":
                enable_camera()
        else:
            error_label.config(text="Incorrect Password", fg="red")
            entry.delete(0, tk.END)
            log_action("Failed password attempt")
            send_email_alert("Failed Password Attempt")

    def toggle_password():
        entry.config(show="" if show_var.get() else "*")

    pw_win = tk.Toplevel(root)
    pw_win.title("Enter Password")
    pw_win.geometry("300x200")
    pw_win.configure(bg="black")

    tk.Label(pw_win, text="Enter Password:", fg="white", bg="black").pack(pady=5)
    entry = tk.Entry(pw_win, show="*", font=("Arial", 12))
    entry.pack(pady=5)

    show_var = tk.BooleanVar()
    remember_var = tk.BooleanVar()
    tk.Checkbutton(pw_win, text="Show Password", variable=show_var, command=toggle_password, bg="black", fg="white", selectcolor="black").pack(pady=2)
    tk.Checkbutton(pw_win, text="Remember Me", variable=remember_var, bg="black", fg="white", selectcolor="black").pack(pady=2)
    tk.Button(pw_win, text="OK", command=verify, bg="red", fg="white").pack(pady=5)
    error_label = tk.Label(pw_win, text="", fg="red", bg="black")
    error_label.pack()

# ---------------- Change Camera Password ---------------- #
def open_password_tool():
    def save_password(pwd):
        global current_password
        if pwd:
            current_password = pwd
            current_pwd_label.config(text=current_password)
            success_label.config(text="Password Saved Successfully!", fg="green")
        else:
            success_label.config(text="Password cannot be empty.", fg="red")

    def generate_password():
        try:
            length = int(length_entry.get())
            if length < 4:
                raise ValueError
            chars = string.ascii_letters
            if include_numbers.get():
                chars += string.digits
            if include_special.get():
                chars += string.punctuation
            new_pwd = ''.join(random.choices(chars, k=length))
            generated_pwd_var.set(new_pwd)
        except:
            messagebox.showerror("Error", "Enter valid length (>=4)")

    pwd_win = tk.Toplevel(root)
    pwd_win.title("Camera Password Tool")
    pwd_win.geometry("400x300")
    pwd_win.configure(bg="black")

    tk.Label(pwd_win, text="New Password:", fg="white", bg="black").pack(pady=5)
    pwd_entry = tk.Entry(pwd_win, show="*", font=("Arial",12))
    pwd_entry.pack(pady=5)

    tk.Button(pwd_win, text="Save Password", bg="green", fg="white", command=lambda: save_password(pwd_entry.get())).pack(pady=5)

    # Random password generator
    tk.Label(pwd_win, text="Generate Random Password:", fg="white", bg="black").pack(pady=5)
    tk.Label(pwd_win, text="Length:", fg="white", bg="black").pack()
    length_entry = tk.Entry(pwd_win, font=("Arial",12))
    length_entry.insert(0, "8")
    length_entry.pack(pady=5)

    include_numbers = tk.BooleanVar(value=True)
    include_special = tk.BooleanVar(value=False)
    tk.Checkbutton(pwd_win, text="Include Numbers", variable=include_numbers, bg="black", fg="white", selectcolor="black").pack()
    tk.Checkbutton(pwd_win, text="Include Special Characters", variable=include_special, bg="black", fg="white", selectcolor="black").pack()

    generated_pwd_var = tk.StringVar()
    tk.Entry(pwd_win, textvariable=generated_pwd_var, font=("Arial",12)).pack(pady=5)
    tk.Button(pwd_win, text="Generate", bg="orange", fg="white", command=generate_password).pack(pady=5)

# ---------------- Email Settings Window ---------------- #
def open_email_settings():
    def save_cfg():
        cfg = {
            "server": server_entry.get(),
            "port": int(port_entry.get()),
            "sender": sender_entry.get(),
            "password": pwd_entry.get(),
            "recipient": recipient_entry.get(),
            "attach_snapshot": attach_var.get()
        }
        save_email_config(cfg)

    def send_test_email():
        cfg = load_email_config()
        if not cfg:
            messagebox.showerror("Error", "Email not configured yet")
            return
        _send_email_smtp(cfg, "Test Email from WebCam Spyware", "This is a test alert.", False)
        messagebox.showinfo("Success", "Test email sent (check logs if any error)")

    email_win = tk.Toplevel(root)
    email_win.title("Email Alert Settings")
    email_win.geometry("400x400")
    email_win.configure(bg="black")

    cfg = load_email_config() or {}

    tk.Label(email_win, text="SMTP Server:", fg="white", bg="black").pack(pady=2)
    server_entry = tk.Entry(email_win, font=("Arial",12))
    server_entry.insert(0, cfg.get("server","smtp.gmail.com"))
    server_entry.pack()

    tk.Label(email_win, text="Port:", fg="white", bg="black").pack(pady=2)
    port_entry = tk.Entry(email_win, font=("Arial",12))
    port_entry.insert(0, cfg.get("port",587))
    port_entry.pack()

    tk.Label(email_win, text="Sender Email:", fg="white", bg="black").pack(pady=2)
    sender_entry = tk.Entry(email_win, font=("Arial",12))
    sender_entry.insert(0, cfg.get("sender",""))
    sender_entry.pack()

    tk.Label(email_win, text="App Password:", fg="white", bg="black").pack(pady=2)
    pwd_entry = tk.Entry(email_win, font=("Arial",12), show="*")
    pwd_entry.insert(0, cfg.get("password",""))
    pwd_entry.pack()

    tk.Label(email_win, text="Recipient Email:", fg="white", bg="black").pack(pady=2)
    recipient_entry = tk.Entry(email_win, font=("Arial",12))
    recipient_entry.insert(0, cfg.get("recipient",""))
    recipient_entry.pack()

    attach_var = tk.BooleanVar(value=cfg.get("attach_snapshot", True))
    tk.Checkbutton(email_win, text="Attach Snapshot", variable=attach_var, bg="black", fg="white", selectcolor="black").pack(pady=5)

    tk.Button(email_win, text="Save Settings", bg="green", fg="white", command=save_cfg).pack(pady=5)
    tk.Button(email_win, text="Send Test Email", bg="blue", fg="white", command=send_test_email).pack(pady=5)

# ---------------- View Logs ---------------- #
def view_logs():
    if os.path.exists("activity_log.txt"):
        os.startfile("activity_log.txt")
    else:
        messagebox.showinfo("Logs", "No logs found.")

# ---------------- GUI ---------------- #
root = tk.Tk()
root.title("WebCam Spyware Security")
root.geometry("500x700")
root.configure(bg="black")

# Camera image
image_path = resource_path("camera.png")
if os.path.exists(image_path):
    img = Image.open(image_path)
    img = img.resize((150,150))
    cam_img = ImageTk.PhotoImage(img)
    cam_label = tk.Label(root, image=cam_img, bg="black")
    cam_label.image = cam_img
    cam_label.pack(pady=10)

tk.Label(root, text="WebCam Spyware Security", fg="white", bg="black", font=("Arial",16,"bold")).pack()

# Buttons
project_pdf = resource_path("Project_Information_2.pdf")
tk.Button(root, text="Project Info", bg="red", fg="white", command=lambda: os.startfile(project_pdf)).pack(pady=5)
tk.Button(root, text="View Logs", bg="red", fg="white", command=view_logs).pack(pady=5)
tk.Button(root, text="Change Camera Password", bg="red", fg="white", command=open_password_tool).pack(pady=5)
tk.Button(root, text="Email Alert Settings", bg="red", fg="white", command=open_email_settings).pack(pady=5)

# Camera control frame
frame = tk.Frame(root, bg="gray")
frame.pack(pady=10)
tk.Button(frame, text="Enable Camera", bg="green", fg="white", width=20, command=lambda: password_prompt("enable")).pack(pady=5)
tk.Button(frame, text="Disable Camera", bg="red", fg="white", width=20, command=lambda: password_prompt("disable")).pack(pady=5)

# Status labels
success_label = tk.Label(root, text="", fg="green", bg="black", font=("Arial",12))
success_label.pack(pady=5)
tk.Label(root, text="Current Password:", fg="white", bg="black", font=("Arial",10)).pack()
current_pwd_label = tk.Label(root, text=current_password, fg="cyan", bg="black", font=("Arial",10))
current_pwd_label.pack()
cam_feed_label = tk.Label(root, bg="black")
cam_feed_label.pack(pady=10)

root.mainloop()







