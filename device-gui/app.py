import argparse
import base64
import getpass
import json
import os
import queue
import threading
import time

import requests
from nacl import signing


try:
    import tkinter as tk
    from tkinter import messagebox, scrolledtext, ttk
    TclError = tk.TclError
except Exception:  # Tk is optional for CLI mode
    tk = None
    messagebox = scrolledtext = ttk = None

    class TclError(Exception):
        pass

API_BASE = os.environ.get('API_BASE', 'http://localhost:8080').rstrip('/')
STATE_FILE = os.path.join(os.path.dirname(__file__), 'state.json')
POLL_INTERVAL = 4


class DeviceError(Exception):
    """Raised for recoverable device errors."""


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


class DeviceClient:
    """Holds the link state, signing key, and polling logic used by both UIs."""

    def __init__(self, api_base=API_BASE, poll_interval=POLL_INTERVAL, logger=None):
        self.api_base = api_base
        self.poll_interval = poll_interval
        self.logger = logger or (lambda msg: None)

        self.state_data = load_state()
        self.signing_key = None
        self.pending_login = None
        self.polling = False
        self._poll_callback = None

        if self.is_linked():
            try:
                self.bootstrap_signing_key()
            except DeviceError as exc:
                self.log(f'{exc}; clearing stored device state.')
                self.relink()

    def log(self, message):
        self.logger(message)

    def is_linked(self):
        required = ('email', 'private_key', 'public_key', 'device_name')
        return all(key in self.state_data for key in required)

    def bootstrap_signing_key(self):
        if not self.is_linked():
            raise DeviceError('Device not linked')
        try:
            key_bytes = base64.b64decode(self.state_data['private_key'])
            self.signing_key = signing.SigningKey(key_bytes)
        except Exception as exc:
            self.signing_key = None
            self.state_data = {}
            save_state(self.state_data)
            raise DeviceError('Failed to load device key. Please relink.') from exc

    def link_device(self, email, password, device_name):
        signing_key = signing.SigningKey.generate()
        verify_key = signing_key.verify_key
        payload = {
            'email': email,
            'password': password,
            'device_name': device_name,
            'public_key': base64.b64encode(verify_key.encode()).decode()
        }
        try:
            response = requests.post(f'{self.api_base}/api/device/link', json=payload, timeout=10)
            response.raise_for_status()
        except requests.RequestException as exc:
            raise DeviceError(f'Could not link device: {exc}') from exc

        self.state_data = {
            'email': email,
            'device_name': device_name,
            'private_key': base64.b64encode(signing_key.encode()).decode(),
            'public_key': payload['public_key']
        }
        save_state(self.state_data)
        self.signing_key = signing_key
        self.log('Device linked successfully.')

    def relink(self):
        self.stop_polling()
        self.state_data = {}
        self.signing_key = None
        self.pending_login = None
        save_state(self.state_data)

    def start_polling(self, on_login):
        if self.polling or not self.is_linked():
            return
        if not self.signing_key:
            self.bootstrap_signing_key()
        self.polling = True
        self._poll_callback = on_login
        threading.Thread(target=self._poll_loop, daemon=True).start()

    def stop_polling(self):
        self.polling = False

    def _poll_loop(self):
        while self.polling and self.is_linked():
            try:
                resp = requests.get(
                    f'{self.api_base}/api/device/pending',
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
                        self._emit_login(login)
                else:
                    self.pending_login = None
            except requests.RequestException as exc:
                self.log(f'Polling failed: {exc}')
            time.sleep(self.poll_interval)

    def _emit_login(self, login):
        if not self._poll_callback:
            return
        try:
            self._poll_callback(login)
        except Exception as exc:
            self.log(f'Login handler failed: {exc}')

    def approve_login(self, login):
        if not self.signing_key:
            self.bootstrap_signing_key()
        try:
            message_bytes = base64.b64decode(login['challenge'])
            signature = self.signing_key.sign(message_bytes).signature
            signature_b64 = base64.b64encode(signature).decode()
            payload = {'login_id': login['login_id'], 'signature': signature_b64}
            resp = requests.post(f'{self.api_base}/api/device/approve', json=payload, timeout=10)
            resp.raise_for_status()
            self.pending_login = None
        except Exception as exc:
            raise DeviceError(f'Could not approve login: {exc}') from exc

    def clear_pending_login(self):
        self.pending_login = None


if tk is not None:
    class DeviceApp(tk.Tk):
        def __init__(self, poll_interval=POLL_INTERVAL):
            super().__init__()
            self.title('Lyra Lane Device Approver')
            self.geometry('520x500')
            self.resizable(False, False)

            self.client = DeviceClient(logger=self.log, poll_interval=poll_interval)

            self.create_widgets()
            self.protocol('WM_DELETE_WINDOW', self.on_close)

            if self.client.is_linked():
                self.log(f"Device linked as {self.client.state_data.get('device_name')}")
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

            if self.client.is_linked():
                self.render_linked()
            else:
                self.render_link_form()

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

            state = self.client.state_data
            ttk.Label(self.content, text='Linked device', font=('Poppins', 14, 'bold')).grid(row=0, column=0, sticky='w')
            ttk.Label(self.content, text=f"Email: {state.get('email')}").grid(row=1, column=0, sticky='w', pady=(8, 0))
            ttk.Label(self.content, text=f"Device: {state.get('device_name')}").grid(row=2, column=0, sticky='w')
            ttk.Button(self.content, text='Relink', command=self.relink).grid(row=3, column=0, pady=(12, 0), sticky='w')

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
            try:
                self.client.link_device(email, password, device_name)
            except DeviceError as exc:
                messagebox.showerror('Link failed', str(exc))
                return

            self.render_linked()
            self.start_polling()

        def relink(self):
            self.client.relink()
            self.log('Device cleared. Link again to continue.')
            self.render_link_form()

        def start_polling(self):
            try:
                self.client.start_polling(self.handle_login_event)
            except DeviceError as exc:
                messagebox.showerror('Error', str(exc))

        def handle_login_event(self, login):
            self.after(0, lambda: self.show_approval(login))

        def show_approval(self, login):
            self.log(f"Login request received at {login['created_at']}")
            top = tk.Toplevel(self)
            top.title('Approve login?')
            top.geometry('360x220')
            ttk.Label(top, text='Passwordless sign-in', font=('Poppins', 14, 'bold')).pack(pady=(20, 10))
            ttk.Label(top, text=f"Email: {self.client.state_data.get('email')}").pack()
            ttk.Label(top, text=f"Requested: {login['created_at']}").pack(pady=(0, 10))

            button_frame = ttk.Frame(top)
            button_frame.pack(pady=10)
            ttk.Button(button_frame, text='Approve', command=lambda: self.approve_login(top, login)).grid(row=0, column=0, padx=10)
            ttk.Button(button_frame, text='Ignore', command=lambda: self.ignore_login(top)).grid(row=0, column=1, padx=10)

        def approve_login(self, window, login):
            window.destroy()
            try:
                self.client.approve_login(login)
                self.log('Login approved and signature sent.')
            except DeviceError as exc:
                self.log(f'Approval failed: {exc}')
                messagebox.showerror('Error', str(exc))

        def ignore_login(self, window):
            window.destroy()
            self.client.clear_pending_login()
            self.log('Login ignored. It will expire shortly if not approved.')

        def log(self, message):
            entry = f'[{time.strftime("%H:%M:%S")}] {message}\n'
            if not hasattr(self, 'log_area'):
                print(entry.rstrip())
                return
            self.log_area.configure(state='normal')
            self.log_area.insert('end', entry)
            self.log_area.configure(state='disabled')
            self.log_area.see('end')

        def on_close(self):
            self.client.stop_polling()
            self.destroy()


class DeviceCLI:
    def __init__(self, poll_interval=POLL_INTERVAL):
        self.login_queue = queue.Queue()
        self.client = DeviceClient(logger=self.log, poll_interval=poll_interval)

    def log(self, message):
        print(f'[{time.strftime("%H:%M:%S")}] {message}')

    def run(self):
        self.log('Lyra Lane Device CLI')
        if not self.client.is_linked():
            self.log('No linked device found. Follow the prompts to link this terminal.')
            self.prompt_link()
        else:
            self.log(f"Device linked as {self.client.state_data.get('device_name')}")

        try:
            self.client.start_polling(self.enqueue_login)
        except DeviceError as exc:
            self.log(f'Cannot start polling: {exc}')
            return

        self.log('Polling for pending logins. Press Ctrl+C to exit.')
        try:
            while True:
                try:
                    login = self.login_queue.get(timeout=0.5)
                except queue.Empty:
                    continue
                self.prompt_login_decision(login)
        except KeyboardInterrupt:
            self.log('Stopping…')
        finally:
            self.client.stop_polling()

    def prompt_link(self):
        while True:
            email = input('Email: ').strip()
            password = getpass.getpass('Password: ').strip()
            device_name = input('Device name [My Device]: ').strip() or 'My Device'

            if not email or not password:
                self.log('Email and password are required.')
                continue
            if '@' not in email:
                self.log('Enter a valid email.')
                continue

            self.log('Linking device…')
            try:
                self.client.link_device(email, password, device_name)
                break
            except DeviceError as exc:
                self.log(str(exc))
                retry = input('Try again? [y/N]: ').strip().lower()
                if retry not in ('y', 'yes'):
                    raise SystemExit(1)

        self.log(f"Device linked as {self.client.state_data.get('device_name')}")

    def enqueue_login(self, login):
        self.login_queue.put(login)

    def prompt_login_decision(self, login):
        email = self.client.state_data.get('email')
        created_at = login.get('created_at', 'unknown time')
        self.log(f'Login request for {email} @ {created_at}')
        while True:
            choice = input('Approve login? [y/N]: ').strip().lower()
            if choice in ('y', 'yes'):
                try:
                    self.client.approve_login(login)
                    self.log('Login approved and signature sent.')
                except DeviceError as exc:
                    self.log(str(exc))
                break
            if choice in ('n', 'no', ''):
                self.client.clear_pending_login()
                self.log('Login ignored. It will expire shortly if not approved.')
                break
            print('Please respond with y or n.')


def main():
    parser = argparse.ArgumentParser(description='Lyra Lane device app')
    parser.add_argument('--cli', action='store_true', help='Run in terminal mode instead of the Tk GUI.')
    parser.add_argument('--poll-interval', type=int, default=POLL_INTERVAL, help='Seconds between poll requests.')
    args = parser.parse_args()

    if args.cli:
        DeviceCLI(poll_interval=args.poll_interval).run()
        return

    if tk is None:
        print('Tkinter is not available. Run with --cli to use the terminal interface.')
        return

    try:
        app = DeviceApp(poll_interval=args.poll_interval)
    except TclError as exc:
        print(f'Unable to start Tkinter GUI: {exc}')
        print('Run with --cli to use the terminal interface.')
        return

    app.mainloop()


if __name__ == '__main__':
    main()
