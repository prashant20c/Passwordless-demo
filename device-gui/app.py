import argparse
import base64
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
        self.pending_logins = []
        self.polling = False
        self._poll_callback = None
        self.last_poll_ok = None
        self.last_checked_at = None
        self.last_error = ''

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

    def link_device(self, email, link_code, device_name):
        signing_key = signing.SigningKey.generate()
        verify_key = signing_key.verify_key
        normalized_code = ''.join(ch for ch in link_code if ch.isdigit())
        if len(normalized_code) != 6:
            raise DeviceError('A 6-digit link code is required. Generate one from the Trustlogin web app.')
        payload = {
            'email': email,
            'device_name': device_name,
            'link_code': normalized_code,
            'public_key': base64.b64encode(verify_key.encode()).decode()
        }
        try:
            response = requests.post(f'{self.api_base}/api/device/link/complete', json=payload, timeout=10)
            response.raise_for_status()
            result = response.json()
        except requests.RequestException as exc:
            raise DeviceError(f'Could not link device: {exc}') from exc
        except ValueError:
            result = {}

        self.state_data = {
            'email': email,
            'device_name': device_name,
            'private_key': base64.b64encode(signing_key.encode()).decode(),
            'public_key': payload['public_key'],
            'device_id': result.get('device_id')
        }
        save_state(self.state_data)
        self.signing_key = signing_key
        self.pending_logins = []
        self.log('Device linked successfully.')

    def relink(self):
        self.stop_polling()
        self.state_data = {}
        self.signing_key = None
        self.pending_logins = []
        save_state(self.state_data)

    def start_polling(self, on_poll):
        if self.polling or not self.is_linked():
            return
        if not self.signing_key:
            self.bootstrap_signing_key()
        self.polling = True
        self._poll_callback = on_poll
        threading.Thread(target=self._poll_loop, daemon=True).start()

    def stop_polling(self):
        self.polling = False

    def _poll_loop(self):
        while self.polling and self.is_linked():
            logins = None
            try:
                resp = requests.get(
                    f'{self.api_base}/api/device/pending',
                    params={'email': self.state_data['email']},
                    timeout=10
                )
                resp.raise_for_status()
                data = resp.json()
                logins = data.get('logins', [])
                self.pending_logins = logins
                self.last_poll_ok = True
                self.last_error = ''
            except requests.RequestException as exc:
                self.last_poll_ok = False
                self.last_error = str(exc)
                self.log(f'Polling failed: {exc}')
            finally:
                self.last_checked_at = time.time()
                self._emit_poll_update(logins if logins is not None else self.pending_logins)
                time.sleep(self.poll_interval)

    def _emit_poll_update(self, logins):
        if not self._poll_callback:
            return
        payload = {
            'logins': logins or [],
            'status': {
                'ok': self.last_poll_ok,
                'checked_at': self.last_checked_at,
                'error': self.last_error
            }
        }
        try:
            self._poll_callback(payload)
        except Exception as exc:
            self.log(f'Poll handler failed: {exc}')

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
            self._remove_login(login['login_id'])
        except Exception as exc:
            raise DeviceError(f'Could not approve login: {exc}') from exc

    def reject_login(self, login):
        """
        Reject a login challenge via the API so the server knows it was denied.
        """
        if not self.is_linked():
            raise DeviceError('Device not linked.')
        device_id = self.state_data.get('device_id')
        if not device_id:
            self._remove_login(login['login_id'])
            self.log('Device id missing; removed login locally.')
            return
        payload = {
            'login_id': login['login_id'],
            'device_id': device_id
        }
        try:
            resp = requests.post(f'{self.api_base}/api/device/reject', json=payload, timeout=10)
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise DeviceError(f'Failed to reject login: {exc}') from exc

        self._remove_login(login['login_id'])
        self.log('Login rejected and server notified.')

    def end_sessions(self):
        """
        Attempts to revoke active sessions via a backend endpoint.
        """
        if not self.is_linked():
            raise DeviceError('Device not linked.')
        payload = {'email': self.state_data['email']}
        try:
            resp = requests.post(f'{self.api_base}/api/device/sessions/end', json=payload, timeout=10)
            if resp.status_code == 404:
                raise DeviceError('Session revoke endpoint not available yet (TODO on backend).')
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise DeviceError(f'Failed to end sessions: {exc}') from exc

    def clear_pending_login(self, login_id=None):
        if login_id:
            self._remove_login(login_id)
        else:
            self.pending_logins = []

    def get_status_snapshot(self):
        return {
            'ok': self.last_poll_ok,
            'checked_at': self.last_checked_at,
            'error': self.last_error
        }

    def _remove_login(self, login_id):
        self.pending_logins = [
            login for login in self.pending_logins if login.get('login_id') != login_id
        ]


if tk is not None:
    class DeviceApp(tk.Tk):
        def __init__(self, poll_interval=POLL_INTERVAL):
            super().__init__()
            self.title('Trustlogin Device App')
            self.geometry('780x620')
            self.minsize(740, 560)

            self.client = DeviceClient(logger=self.log, poll_interval=poll_interval)

            self.status_var = tk.StringVar(value='Status: waiting…')
            self.last_checked_var = tk.StringVar(value='Last checked: —')
            self.login_lookup = {}
            self.selected_login_id = None
            self.tree = None
            self.status_dot = None

            self._build_layout()
            self.protocol('WM_DELETE_WINDOW', self.on_close)

            if self.client.is_linked():
                self.log(f"Device linked as {self.client.state_data.get('device_name')}")
                self.render_dashboard()
                self.start_polling()
            else:
                self.log('Link your device to begin.')
                self.render_link_form()

        def _build_layout(self):
            self.columnconfigure(0, weight=1)
            self.rowconfigure(0, weight=1)

            self.style = ttk.Style(self)
            try:
                self.style.theme_use('clam')
            except tk.TclError:
                pass
            self.style.configure('Header.TLabel', font=('Poppins', 20, 'bold'))
            self.style.configure('Section.TLabel', font=('Poppins', 13, 'bold'))

            self.wrapper = ttk.Frame(self, padding=20)
            self.wrapper.grid(row=0, column=0, sticky='nsew')
            self.wrapper.columnconfigure(0, weight=1)
            self.wrapper.rowconfigure(1, weight=1)

            self.header_frame = ttk.Frame(self.wrapper)
            self.header_frame.grid(row=0, column=0, sticky='ew')
            ttk.Label(self.header_frame, text='Trustlogin Device App', style='Header.TLabel').pack(side='left')
            self.header_subtitle = ttk.Label(self.header_frame, text='Secure approvals from your desktop')
            self.header_subtitle.pack(side='left', padx=(12, 0))

            self.content = ttk.Frame(self.wrapper)
            self.content.grid(row=1, column=0, sticky='nsew', pady=(16, 0))
            self.content.columnconfigure(0, weight=1)
            self.content.rowconfigure(0, weight=1)

            self.log_area = scrolledtext.ScrolledText(self.wrapper, height=6, state='disabled', wrap='word')
            self.log_area.grid(row=2, column=0, sticky='nsew', pady=(12, 6))
            self.log_area.configure(background='#0f172a', foreground='#e2e8f0', insertbackground='#e2e8f0')

            status_bar = ttk.Frame(self.wrapper)
            status_bar.grid(row=3, column=0, sticky='ew')
            self.status_dot = tk.Label(status_bar, width=2, height=1, background='#f97316')
            self.status_dot.pack(side='left')
            ttk.Label(status_bar, textvariable=self.status_var).pack(side='left', padx=(8, 0))
            ttk.Label(status_bar, textvariable=self.last_checked_var).pack(side='right')

        def set_header_subtitle(self, text):
            self.header_subtitle.configure(text=text)

        def clear_content(self):
            for widget in self.content.winfo_children():
                widget.destroy()
            self.tree = None
            self.login_lookup = {}
            self.selected_login_id = None

        def render_link_form(self):
            self.clear_content()
            self.set_header_subtitle('Link this device to begin approving sign-ins')

            form = ttk.Frame(self.content)
            form.grid(row=0, column=0, sticky='nsew')
            form.columnconfigure(0, weight=1)

            ttk.Label(form, text='Link this device', style='Section.TLabel').grid(row=0, column=0, sticky='w')
            ttk.Label(
                form,
                text='Generate a 6-digit link code from the Trustlogin dashboard, then enter it here with your email.',
                wraplength=520
            ).grid(row=1, column=0, sticky='w', pady=(4, 12))

            self.email_var = tk.StringVar()
            self.code_var = tk.StringVar()
            self.device_var = tk.StringVar(value='My Device')

            ttk.Label(form, text='Email').grid(row=2, column=0, sticky='w')
            ttk.Entry(form, textvariable=self.email_var).grid(row=3, column=0, sticky='ew')

            ttk.Label(form, text='Device link code').grid(row=4, column=0, sticky='w', pady=(12, 0))
            ttk.Entry(form, textvariable=self.code_var).grid(row=5, column=0, sticky='ew')
            ttk.Label(form, text='Codes expire in minutes and are single-use.', foreground='#64748b').grid(row=6, column=0, sticky='w', pady=(2, 0))

            ttk.Label(form, text='Device name').grid(row=7, column=0, sticky='w', pady=(12, 0))
            ttk.Entry(form, textvariable=self.device_var).grid(row=8, column=0, sticky='ew')

            ttk.Button(form, text='Link device', command=self.link_device).grid(row=9, column=0, pady=(20, 0), sticky='ew')

        def render_dashboard(self):
            self.clear_content()
            state = self.client.state_data
            self.set_header_subtitle(f"Linked as {state.get('email')} · {state.get('device_name')}")

            dashboard = ttk.Frame(self.content)
            dashboard.grid(row=0, column=0, sticky='nsew')
            dashboard.columnconfigure(0, weight=1)
            dashboard.rowconfigure(2, weight=1)

            ttk.Label(dashboard, text='Pending Logins', style='Section.TLabel').grid(row=0, column=0, sticky='w')

            toolbar = ttk.Frame(dashboard)
            toolbar.grid(row=1, column=0, sticky='ew', pady=(8, 4))
            toolbar.columnconfigure(4, weight=1)

            self.approve_btn = ttk.Button(toolbar, text='Approve', command=self.handle_approve_selected, state='disabled')
            self.approve_btn.grid(row=0, column=0, padx=(0, 6))
            self.reject_btn = ttk.Button(toolbar, text='Reject', command=self.handle_reject_selected, state='disabled')
            self.reject_btn.grid(row=0, column=1, padx=(0, 6))
            self.end_sessions_btn = ttk.Button(toolbar, text='End Sessions', command=self.handle_end_sessions)
            self.end_sessions_btn.grid(row=0, column=2, padx=(0, 6))
            self.logout_btn = ttk.Button(toolbar, text='Logout', command=self.logout_device)
            self.logout_btn.grid(row=0, column=3)

            table_frame = ttk.Frame(dashboard)
            table_frame.grid(row=2, column=0, sticky='nsew')
            table_frame.columnconfigure(0, weight=1)
            table_frame.rowconfigure(0, weight=1)

            columns = ('login_id', 'email', 'requested')
            self.tree = ttk.Treeview(table_frame, columns=columns, show='headings', selectmode='browse')
            self.tree.heading('email', text='Email')
            self.tree.heading('requested', text='Requested')
            self.tree.heading('login_id', text='Login ID')
            self.tree.column('login_id', width=120, anchor='center')
            self.tree.column('email', width=220, anchor='w')
            self.tree.column('requested', width=180, anchor='w')
            self.tree.grid(row=0, column=0, sticky='nsew')

            scrollbar = ttk.Scrollbar(table_frame, orient='vertical', command=self.tree.yview)
            scrollbar.grid(row=0, column=1, sticky='ns')
            self.tree.configure(yscrollcommand=scrollbar.set)
            self.tree.bind('<<TreeviewSelect>>', self.on_row_select)

        def link_device(self):
            email = self.email_var.get().strip()
            link_code = self.code_var.get().strip()
            device_name = self.device_var.get().strip() or 'My Device'

            if not email or '@' not in email:
                messagebox.showwarning('Invalid email', 'Enter a valid email address.')
                return
            if not link_code:
                messagebox.showwarning('Missing code', 'Enter the 6-digit device link code.')
                return

            self.log('Linking device…')
            try:
                self.client.link_device(email, link_code, device_name)
            except DeviceError as exc:
                messagebox.showerror('Link failed', str(exc))
                return

            self.render_dashboard()
            self.start_polling()

        def logout_device(self):
            self.client.relink()
            self.login_lookup.clear()
            self.selected_login_id = None
            self.stop_polling()
            self.log('Device logged out locally.')
            self.render_link_form()

        def start_polling(self):
            try:
                self.client.start_polling(self.handle_poll_update)
            except DeviceError as exc:
                messagebox.showerror('Error', str(exc))

        def stop_polling(self):
            self.client.stop_polling()

        def handle_poll_update(self, payload):
            self.after(0, lambda: self._process_poll_payload(payload))

        def _process_poll_payload(self, payload):
            logins = payload.get('logins', [])
            status = payload.get('status', {})
            if self.tree:
                self.refresh_login_table(logins)
            self.update_status_bar(status)

        def refresh_login_table(self, logins):
            current_ids = set(self.tree.get_children())
            incoming_ids = set()
            self.login_lookup = {}

            for login in logins:
                login_id = login['login_id']
                incoming_ids.add(login_id)
                self.login_lookup[login_id] = login
                values = (
                    login_id,
                    self.client.state_data.get('email', '—'),
                    login.get('created_at', '—')
                )
                if login_id in current_ids:
                    self.tree.item(login_id, values=values)
                else:
                    self.tree.insert('', 'end', iid=login_id, values=values)

            for missing in current_ids - incoming_ids:
                self.tree.delete(missing)

            if self.selected_login_id and self.selected_login_id not in incoming_ids:
                self.selected_login_id = None
                self.tree.selection_remove(self.tree.selection())
            self.update_buttons_state()

        def update_status_bar(self, status):
            ok = status.get('ok')
            checked_at = status.get('checked_at')
            error = status.get('error') or ''

            if ok is True:
                self.status_var.set('Connected to server ✅')
                color = '#22c55e'
            elif ok is False:
                self.status_var.set(f'Cannot reach server ❌ {error}')
                color = '#ef4444'
            else:
                self.status_var.set('Status: waiting…')
                color = '#facc15'

            if checked_at:
                ts = time.strftime('%H:%M:%S', time.localtime(checked_at))
                self.last_checked_var.set(f'Last checked: {ts}')
            else:
                self.last_checked_var.set('Last checked: —')

            if self.status_dot:
                self.status_dot.configure(background=color)

        def on_row_select(self, _event):
            selection = self.tree.selection()
            self.selected_login_id = selection[0] if selection else None
            self.update_buttons_state()

        def update_buttons_state(self):
            state = 'normal' if self.selected_login_id else 'disabled'
            if self.approve_btn:
                self.approve_btn.configure(state=state)
            if self.reject_btn:
                self.reject_btn.configure(state=state)

        def get_selected_login(self):
            if not self.selected_login_id:
                return None
            return self.login_lookup.get(self.selected_login_id)

        def handle_approve_selected(self):
            login = self.get_selected_login()
            if not login:
                messagebox.showinfo('No selection', 'Select a pending login to approve.')
                return
            try:
                self.client.approve_login(login)
                self.log(f'Approved login {login["login_id"]}.')
            except DeviceError as exc:
                messagebox.showerror('Approval failed', str(exc))

        def handle_reject_selected(self):
            login = self.get_selected_login()
            if not login:
                messagebox.showinfo('No selection', 'Select a pending login to reject.')
                return
            self.client.reject_login(login)
            self.log(f'Rejected login {login["login_id"]}.')

        def handle_end_sessions(self):
            try:
                self.client.end_sessions()
            except DeviceError as exc:
                messagebox.showerror('Unable to end sessions', str(exc))
                return
            messagebox.showinfo('Sessions ended', 'Requested the server to end active sessions.')

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
            self.stop_polling()
            self.destroy()


class DeviceCLI:
    def __init__(self, poll_interval=POLL_INTERVAL):
        self.login_queue = queue.Queue()
        self.client = DeviceClient(logger=self.log, poll_interval=poll_interval)
        self.seen_login_ids = set()

    def log(self, message):
        print(f'[{time.strftime("%H:%M:%S")}] {message}')

    def run(self):
        self.log('Trustlogin Device CLI')
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
            link_code = input('Device link code: ').strip()
            device_name = input('Device name [My Device]: ').strip() or 'My Device'

            if not email or not link_code:
                self.log('Email and link code are required.')
                continue
            if '@' not in email:
                self.log('Enter a valid email.')
                continue

            self.log('Linking device…')
            try:
                self.client.link_device(email, link_code, device_name)
                break
            except DeviceError as exc:
                self.log(str(exc))
                retry = input('Try again? [y/N]: ').strip().lower()
                if retry not in ('y', 'yes'):
                    raise SystemExit(1)

        self.log(f"Device linked as {self.client.state_data.get('device_name')}")

    def enqueue_login(self, payload):
        status = payload.get('status', {})
        if status.get('ok') is False and status.get('error'):
            self.log(f"Polling error: {status.get('error')}")
        logins = payload.get('logins', [])
        for login in logins:
            login_id = login['login_id']
            if login_id in self.seen_login_ids:
                continue
            self.seen_login_ids.add(login_id)
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
                    self.seen_login_ids.discard(login['login_id'])
                except DeviceError as exc:
                    self.log(str(exc))
                break
            if choice in ('n', 'no', ''):
                try:
                    self.client.reject_login(login)
                except DeviceError as exc:
                    self.log(str(exc))
                self.seen_login_ids.discard(login['login_id'])
                self.log('Login ignored. It will expire shortly if not approved.')
                break
            print('Please respond with y or n.')


def main():
    parser = argparse.ArgumentParser(description='Trustlogin device app')
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
