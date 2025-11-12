import base64
import json
import os
import threading
import time
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

import requests
from nacl import signing

API_BASE = os.environ.get('API_BASE', 'http://localhost:8080')
STATE_FILE = os.path.join(os.path.dirname(__file__), 'state.json')
POLL_INTERVAL = 4


def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def save_state(state):
    with open(STATE_FILE, 'w', encoding='utf-8') as f:
        json.dump(state, f, indent=2)


class DeviceApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Lyra Lane Device Approver')
        self.geometry('520x500')
        self.resizable(False, False)

        self.state_data = load_state()
        self.signing_key = None
        self.polling = False
        self.pending_login = None

        self.create_widgets()
        self.protocol('WM_DELETE_WINDOW', self.on_close)

        if self.is_linked():
            self.log('Device linked as %s' % self.state_data.get('device_name'))
            self.bootstrap_signing_key()
            self.start_polling()
        else:
            self.log('Link your device to begin.')

    def create_widgets(self):
        self.columnconfigure(0, weight=1)

        brand_frame = ttk.Frame(self, padding=20)
        brand_frame.grid(row=0, column=0, sticky='ew')
        title = ttk.Label(brand_frame, text='Lyra Lane Device', font=('Poppins', 18, 'bold'))
        title.pack(anchor='center')
        subtitle = ttk.Label(brand_frame, text='Approve web logins with your trusted device')
        subtitle.pack(anchor='center', pady=(4, 0))

        separator = ttk.Separator(self)
        separator.grid(row=1, column=0, sticky='ew')

        self.content = ttk.Frame(self, padding=20)
        self.content.grid(row=2, column=0, sticky='nsew')
        self.content.columnconfigure(0, weight=1)

        self.log_area = scrolledtext.ScrolledText(self, height=10, state='disabled', wrap='word')
        self.log_area.grid(row=3, column=0, sticky='nsew', padx=20, pady=10)

        if self.is_linked():
            self.render_linked()
        else:
            self.render_link_form()

    def is_linked(self):
        return all(key in self.state_data for key in ('email', 'private_key', 'public_key', 'device_name'))

    def render_link_form(self):
        for widget in self.content.winfo_children():
            widget.destroy()

        ttk.Label(self.content, text='Link this device', font=('Poppins', 14, 'bold')).grid(row=0, column=0, pady=(0, 10))

        self.email_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.device_var = tk.StringVar(value='My Device')

        ttk.Label(self.content, text='Email').grid(row=1, column=0, sticky='w')
        ttk.Entry(self.content, textvariable=self.email_var, width=40).grid(row=2, column=0, pady=4)

        ttk.Label(self.content, text='Password').grid(row=3, column=0, sticky='w')
        ttk.Entry(self.content, textvariable=self.password_var, width=40, show='*').grid(row=4, column=0, pady=4)

        ttk.Label(self.content, text='Device name').grid(row=5, column=0, sticky='w')
        ttk.Entry(self.content, textvariable=self.device_var, width=40).grid(row=6, column=0, pady=4)

        ttk.Button(self.content, text='Link device', command=self.link_device).grid(row=7, column=0, pady=(12, 0))

    def render_linked(self):
        for widget in self.content.winfo_children():
            widget.destroy()

        ttk.Label(self.content, text='Linked device', font=('Poppins', 14, 'bold')).grid(row=0, column=0, sticky='w')
        ttk.Label(self.content, text=f"Email: {self.state_data.get('email')}").grid(row=1, column=0, sticky='w', pady=(8, 0))
        ttk.Label(self.content, text=f"Device: {self.state_data.get('device_name')}").grid(row=2, column=0, sticky='w')
        ttk.Button(self.content, text='Relink', command=self.relink).grid(row=3, column=0, pady=(12, 0), sticky='w')

    def bootstrap_signing_key(self):
        try:
            key_bytes = base64.b64decode(self.state_data['private_key'])
            self.signing_key = signing.SigningKey(key_bytes)
        except Exception:
            messagebox.showerror('Error', 'Failed to load device key. Please relink.')
            self.state_data = {}
            save_state(self.state_data)
            self.render_link_form()

    def link_device(self):
        email = self.email_var.get().strip()
        password = self.password_var.get().strip()
        device_name = self.device_var.get().strip() or 'My Device'

        if not email or not password:
            messagebox.showwarning('Missing info', 'Email and password are required.')
            return

        if '@' not in email:
            messagebox.showwarning('Invalid email', 'Enter a valid email address.')
            return

        self.log('Linking device…')

        signing_key = signing.SigningKey.generate()
        verify_key = signing_key.verify_key

        payload = {
            'email': email,
            'password': password,
            'device_name': device_name,
            'public_key': base64.b64encode(verify_key.encode()).decode()
        }

        try:
            response = requests.post(f'{API_BASE}/api/device/link', json=payload, timeout=10)
            response.raise_for_status()
        except requests.RequestException as exc:
            messagebox.showerror('Link failed', f'Could not link device: {exc}')
            return

        self.state_data = {
            'email': email,
            'device_name': device_name,
            'private_key': base64.b64encode(signing_key.encode()).decode(),
            'public_key': payload['public_key']
        }
        save_state(self.state_data)
        self.signing_key = signing_key
        self.render_linked()
        self.log('Device linked successfully.')
        self.start_polling()

    def relink(self):
        if self.polling:
            self.polling = False
        self.state_data = {}
        save_state(self.state_data)
        self.pending_login = None
        self.log('Device cleared. Link again to continue.')
        self.render_link_form()

    def start_polling(self):
        if self.polling:
            return
        if not self.is_linked():
            return
        if not self.signing_key:
            self.bootstrap_signing_key()
        self.polling = True
        threading.Thread(target=self.poll_loop, daemon=True).start()

    def poll_loop(self):
        while self.polling and self.is_linked():
            try:
                resp = requests.get(
                    f'{API_BASE}/api/device/pending',
                    params={'email': self.state_data['email']},
                    timeout=10
                )
                resp.raise_for_status()
                data = resp.json()
                logins = data.get('logins', [])
                if logins:
                    login = logins[0]
                    if not self.pending_login or self.pending_login['login_id'] != login['login_id']:
                        self.pending_login = login
                        self.show_approval(login)
                else:
                    self.pending_login = None
            except requests.RequestException as exc:
                self.log(f'Polling failed: {exc}')
            time.sleep(POLL_INTERVAL)

    def show_approval(self, login):
        self.log(f"Login request received at {login['created_at']}")
        top = tk.Toplevel(self)
        top.title('Approve login?')
        top.geometry('360x220')
        ttk.Label(top, text='Passwordless sign-in', font=('Poppins', 14, 'bold')).pack(pady=(20, 10))
        ttk.Label(top, text=f"Email: {self.state_data.get('email')}").pack()
        ttk.Label(top, text=f"Requested: {login['created_at']}").pack(pady=(0, 10))

        button_frame = ttk.Frame(top)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text='Approve', command=lambda: self.approve_login(top, login)).grid(row=0, column=0, padx=10)
        ttk.Button(button_frame, text='Ignore', command=lambda: self.ignore_login(top)).grid(row=0, column=1, padx=10)

    def approve_login(self, window, login):
        window.destroy()
        if not self.signing_key:
            self.bootstrap_signing_key()
        try:
            message_bytes = base64.b64decode(login['challenge'])
            signature = self.signing_key.sign(message_bytes).signature
            signature_b64 = base64.b64encode(signature).decode()
            payload = {'login_id': login['login_id'], 'signature': signature_b64}
            resp = requests.post(f'{API_BASE}/api/device/approve', json=payload, timeout=10)
            resp.raise_for_status()
            self.log('Login approved and signature sent.')
        except Exception as exc:
            self.log(f'Approval failed: {exc}')
            messagebox.showerror('Error', f'Could not approve login: {exc}')

    def ignore_login(self, window):
        window.destroy()
        self.log('Login ignored. It will expire shortly if not approved.')

    def log(self, message):
        self.log_area.configure(state='normal')
        self.log_area.insert('end', f'[{time.strftime("%H:%M:%S")}] {message}\n')
        self.log_area.configure(state='disabled')
        self.log_area.see('end')

    def on_close(self):
        self.polling = False
        self.destroy()


if __name__ == '__main__':
    app = DeviceApp()
    app.mainloop()
