import argparse
import base64
import hashlib
import json
import os
import queue
import threading
import time
from getpass import getpass
from typing import Dict, List

import requests
from nacl import signing


try:
    import tkinter as tk
    from tkinter import messagebox, scrolledtext, simpledialog, ttk
    TclError = tk.TclError
except Exception:  # Tk is optional for CLI mode
    tk = None
    messagebox = scrolledtext = simpledialog = ttk = None

    class TclError(Exception):
        pass

API_BASE = os.environ.get('API_BASE', 'http://localhost:8080').rstrip('/')
STATE_FILE = os.path.join(os.path.dirname(__file__), 'state.json')
POLL_INTERVAL = 4
PIN_MIN_LENGTH = 4
PIN_MAX_LENGTH = 6

OS_SIGNATURES = [
    ('windows', 'Windows'),
    ('mac os x', 'macOS'),
    ('iphone', 'iPhone'),
    ('ipad', 'iPad'),
    ('android', 'Android'),
    ('linux', 'Linux'),
]

BROWSER_SIGNATURES = [
    ('edg', 'Microsoft Edge'),
    ('crios', 'Chrome'),
    ('chrome', 'Chrome'),
    ('safari', 'Safari'),
    ('firefox', 'Firefox'),
    ('fxios', 'Firefox'),
    ('opr', 'Opera'),
    ('opera', 'Opera'),
    ('msie', 'Internet Explorer'),
    ('trident', 'Internet Explorer'),
]


def describe_user_agent(user_agent: str) -> str:
    ua = (user_agent or '').lower()
    if not ua:
        return 'Unknown device'

    os_label = 'Unknown device'
    for needle, label in OS_SIGNATURES:
        if needle in ua:
            os_label = label
            break
    if os_label == 'Unknown device' and 'macintosh' in ua:
        os_label = 'macOS'

    browser_label = 'Unknown browser'
    for needle, label in BROWSER_SIGNATURES:
        if needle in ua:
            browser_label = label
            break

    if browser_label == 'Safari' and ('iphone' in ua or 'ipad' in ua):
        browser_label = 'Mobile Safari'
    if browser_label == 'Chrome' and 'edg' in ua:
        browser_label = 'Microsoft Edge'

    if browser_label == 'Unknown browser' and os_label == 'Unknown device':
        return 'Unknown device'
    if browser_label == 'Unknown browser':
        return os_label
    if os_label == 'Unknown device':
        return browser_label

    return f'{browser_label} on {os_label}'


def client_label_from_metadata(metadata: Dict) -> str:
    label = metadata.get('client_label')
    if label:
        return label
    return describe_user_agent(metadata.get('user_agent', ''))


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
        self.active_sessions: List[Dict] = []
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
            'device_id': result.get('device_id'),
            'pin_hash': None
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
        self.active_sessions = []
        save_state(self.state_data)

    def has_pin(self):
        return bool(self.state_data.get('pin_hash'))

    def set_pin(self, pin):
        if not self.is_linked():
            raise DeviceError('Device not linked.')
        cleaned = pin.strip()
        if not (PIN_MIN_LENGTH <= len(cleaned) <= PIN_MAX_LENGTH) or not cleaned.isdigit():
            raise DeviceError(f'PIN must be {PIN_MIN_LENGTH}-{PIN_MAX_LENGTH} digits.')
        self.state_data['pin_hash'] = self._hash_pin(cleaned)
        save_state(self.state_data)

    def verify_pin(self, pin):
        if not self.is_linked():
            return False
        stored = self.state_data.get('pin_hash')
        if not stored:
            return False
        return stored == self._hash_pin(pin.strip())

    @staticmethod
    def _hash_pin(pin):
        return hashlib.sha256(pin.encode('utf-8')).hexdigest()

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
            sessions = None
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
            try:
                sessions = self.fetch_active_sessions(allow_missing_device=True)
            except DeviceError as exc:
                self.log(f'Session sync failed: {exc}')
            finally:
                self.last_checked_at = time.time()
                self._emit_poll_update(
                    logins if logins is not None else self.pending_logins,
                    sessions if sessions is not None else self.active_sessions
                )
                time.sleep(self.poll_interval)

    def _emit_poll_update(self, logins, sessions):
        if not self._poll_callback:
            return
        payload = {
            'logins': logins or [],
            'sessions': sessions or [],
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
        return self._end_sessions()

    def _end_sessions(self, session_id=None):
        """
        Attempts to revoke active sessions via a backend endpoint.
        """
        if not self.is_linked():
            raise DeviceError('Device not linked.')
        device_id = self.state_data.get('device_id')
        if not device_id:
            raise DeviceError('Device id missing; relink your device to manage sessions.')
        payload = {'email': self.state_data['email'], 'device_id': device_id}
        if session_id:
            payload['session_id'] = session_id
        try:
            resp = requests.post(f'{self.api_base}/api/device/sessions/end', json=payload, timeout=10)
            resp.raise_for_status()
            try:
                return resp.json()
            except ValueError:
                return {}
        except requests.RequestException as exc:
            raise DeviceError(f'Failed to end sessions: {exc}') from exc

    def end_single_session(self, session_id):
        return self._end_sessions(session_id=session_id)

    def fetch_active_sessions(self, allow_missing_device=False):
        if not self.is_linked():
            return []
        device_id = self.state_data.get('device_id')
        if not device_id:
            if allow_missing_device:
                return []
            raise DeviceError('Device id missing; relink your device to manage sessions.')
        try:
            resp = requests.get(
                f'{self.api_base}/api/device/sessions',
                params={'email': self.state_data['email'], 'device_id': device_id},
                timeout=10
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            raise DeviceError(f'Failed to fetch sessions: {exc}') from exc
        except ValueError:
            data = {}

        sessions = data.get('sessions', [])
        self.active_sessions = sessions
        return sessions

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
            self.unlock_error_var = tk.StringVar(value='')
            self.unlock_pin_var = tk.StringVar()
            self.login_lookup = {}
            self.session_lookup = {}
            self.selected_login_id = None
            self.selected_session_id = None
            self.pending_tree = None
            self.sessions_tree = None
            self.status_dot = None
            self.is_unlocked = False

            self._build_layout()
            self.protocol('WM_DELETE_WINDOW', self.on_close)

            if self.client.is_linked():
                self.log(f"Device linked as {self.client.state_data.get('device_name')}")
                self.ensure_pin_exists()
                if self.client.has_pin():
                    self.render_unlock_screen()
                else:
                    self.render_link_form()
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
            self.pending_tree = None
            self.sessions_tree = None
            self.login_lookup = {}
            self.session_lookup = {}
            self.selected_login_id = None
            self.selected_session_id = None

        def render_link_form(self):
            self.clear_content()
            self.is_unlocked = False
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

        def ensure_pin_exists(self):
            if not self.client.is_linked():
                return
            if self.client.has_pin():
                return
            self.prompt_set_pin(force=True)

        def prompt_set_pin(self, force=False):
            if tk is None or simpledialog is None:
                messagebox.showerror('PIN required', 'Unable to set a PIN because Tk dialogs are unavailable.')
                return False
            while True:
                pin = simpledialog.askstring('Set PIN', f'Choose a {PIN_MIN_LENGTH}-{PIN_MAX_LENGTH} digit PIN', show='*', parent=self)
                if pin is None:
                    if force and not self.client.has_pin():
                        messagebox.showwarning('PIN required', 'A PIN is required to protect your device before use.')
                        continue
                    return self.client.has_pin()
                if not self._valid_pin(pin):
                    messagebox.showerror('Invalid PIN', f'PIN must be {PIN_MIN_LENGTH}-{PIN_MAX_LENGTH} digits.')
                    continue
                confirm = simpledialog.askstring('Confirm PIN', 'Re-enter PIN to confirm', show='*', parent=self)
                if confirm is None:
                    messagebox.showwarning('PIN not set', 'Confirmation cancelled. Please try again.')
                    continue
                if pin != confirm:
                    messagebox.showerror('Mismatch', 'PIN entries did not match. Try again.')
                    continue
                try:
                    self.client.set_pin(pin)
                    messagebox.showinfo('PIN set', 'Device PIN created successfully.')
                except DeviceError as exc:
                    messagebox.showerror('Unable to set PIN', str(exc))
                    continue
                return True

        def _valid_pin(self, pin):
            cleaned = (pin or '').strip()
            return cleaned.isdigit() and PIN_MIN_LENGTH <= len(cleaned) <= PIN_MAX_LENGTH

        def render_unlock_screen(self):
            self.clear_content()
            if not self.client.is_linked():
                self.render_link_form()
                return
            self.set_header_subtitle('Unlock this device to manage logins')
            self.unlock_error_var.set('')
            wrapper = ttk.Frame(self.content)
            wrapper.grid(row=0, column=0, sticky='nsew')
            wrapper.columnconfigure(0, weight=1)
            ttk.Label(wrapper, text='Trustlogin Device App — Unlock', style='Section.TLabel').grid(row=0, column=0, sticky='w')
            ttk.Label(wrapper, text=f"Linked account: {self.client.state_data.get('email', '—')}").grid(row=1, column=0, sticky='w', pady=(6, 12))

            if not self.client.has_pin():
                ttk.Label(
                    wrapper,
                    text='Create a PIN to secure this device before unlocking.',
                    wraplength=480
                ).grid(row=2, column=0, sticky='w')
                ttk.Button(wrapper, text='Set PIN', command=lambda: self._handle_unlock_set_pin()).grid(row=3, column=0, sticky='w', pady=(10, 0))
                ttk.Button(wrapper, text='Unlink Device', command=self.unlink_device).grid(row=4, column=0, sticky='w', pady=(6, 0))
                return

            form = ttk.Frame(wrapper)
            form.grid(row=2, column=0, sticky='nsew')
            form.columnconfigure(0, weight=1)
            ttk.Label(form, text='Enter PIN to unlock:').grid(row=0, column=0, sticky='w')
            entry = ttk.Entry(form, textvariable=self.unlock_pin_var, show='*')
            entry.grid(row=1, column=0, sticky='ew', pady=(4, 0))
            entry.focus_set()

            error_label = ttk.Label(form, textvariable=self.unlock_error_var, foreground='#ef4444')
            error_label.grid(row=2, column=0, sticky='w', pady=(6, 0))

            actions = ttk.Frame(form)
            actions.grid(row=3, column=0, sticky='ew', pady=(12, 0))
            ttk.Button(actions, text='Unlock', command=self.handle_unlock).grid(row=0, column=0, padx=(0, 8))
            ttk.Button(actions, text='Unlink Device', command=self.unlink_device).grid(row=0, column=1)

        def _handle_unlock_set_pin(self):
            if self.prompt_set_pin(force=True):
                self.render_unlock_screen()

        def render_dashboard(self):
            if not self.client.is_linked():
                self.render_link_form()
                return
            if not self.is_unlocked and self.client.has_pin():
                self.render_unlock_screen()
                return
            self.clear_content()
            state = self.client.state_data
            self.set_header_subtitle(f"Linked as {state.get('email')} · {state.get('device_name')}")

            dashboard = ttk.Frame(self.content)
            dashboard.grid(row=0, column=0, sticky='nsew')
            dashboard.columnconfigure(0, weight=1)
            dashboard.rowconfigure(2, weight=1)

            ttk.Label(dashboard, text='Trustlogin Security Console', style='Section.TLabel').grid(row=0, column=0, sticky='w')

            top_toolbar = ttk.Frame(dashboard)
            top_toolbar.grid(row=1, column=0, sticky='ew', pady=(6, 8))
            top_toolbar.columnconfigure(0, weight=1)
            ttk.Label(
                top_toolbar,
                text='Approve sign-ins and manage logged-in browsers right from your linked device.'
            ).grid(row=0, column=0, sticky='w')
            buttons = ttk.Frame(top_toolbar)
            buttons.grid(row=0, column=1, sticky='e')
            self.lock_btn = ttk.Button(buttons, text='Lock App', command=self.lock_app)
            self.lock_btn.grid(row=0, column=0, padx=(0, 6))
            self.unlink_btn = ttk.Button(buttons, text='Unlink Device', command=self.unlink_device)
            self.unlink_btn.grid(row=0, column=1)

            notebook = ttk.Notebook(dashboard)
            notebook.grid(row=2, column=0, sticky='nsew')

            pending_frame = ttk.Frame(notebook, padding=(4, 6))
            pending_frame.columnconfigure(0, weight=1)
            pending_frame.rowconfigure(1, weight=1)
            notebook.add(pending_frame, text='Pending Logins')

            pending_toolbar = ttk.Frame(pending_frame)
            pending_toolbar.grid(row=0, column=0, sticky='ew', pady=(0, 4))
            pending_toolbar.columnconfigure(3, weight=1)
            self.approve_btn = ttk.Button(
                pending_toolbar, text='Approve', command=self.handle_approve_selected, state='disabled'
            )
            self.approve_btn.grid(row=0, column=0, padx=(0, 6))
            self.reject_btn = ttk.Button(
                pending_toolbar, text='Reject', command=self.handle_reject_selected, state='disabled'
            )
            self.reject_btn.grid(row=0, column=1, padx=(0, 6))
            ttk.Label(
                pending_toolbar,
                text='Select a login to approve or reject.'
            ).grid(row=0, column=2, sticky='w')

            pending_table = ttk.Frame(pending_frame)
            pending_table.grid(row=1, column=0, sticky='nsew')
            pending_table.columnconfigure(0, weight=1)
            pending_table.rowconfigure(0, weight=1)

            pending_columns = ('client', 'ip', 'requested')
            self.pending_tree = ttk.Treeview(
                pending_table,
                columns=pending_columns,
                show='headings',
                selectmode='browse'
            )
            self.pending_tree.heading('client', text='Browser / Device')
            self.pending_tree.heading('ip', text='IP Address')
            self.pending_tree.heading('requested', text='Requested')
            self.pending_tree.column('client', width=250, anchor='w')
            self.pending_tree.column('ip', width=140, anchor='center')
            self.pending_tree.column('requested', width=180, anchor='w')
            self.pending_tree.grid(row=0, column=0, sticky='nsew')
            pending_scroll = ttk.Scrollbar(pending_table, orient='vertical', command=self.pending_tree.yview)
            pending_scroll.grid(row=0, column=1, sticky='ns')
            self.pending_tree.configure(yscrollcommand=pending_scroll.set)
            self.pending_tree.bind('<<TreeviewSelect>>', self.on_pending_row_select)

            sessions_frame = ttk.Frame(notebook, padding=(4, 6))
            sessions_frame.columnconfigure(0, weight=1)
            sessions_frame.rowconfigure(1, weight=1)
            notebook.add(sessions_frame, text='Active Sessions')

            sessions_toolbar = ttk.Frame(sessions_frame)
            sessions_toolbar.grid(row=0, column=0, sticky='ew', pady=(0, 4))
            sessions_toolbar.columnconfigure(2, weight=1)
            ttk.Label(sessions_toolbar, text='View browsers that are currently signed in.').grid(row=0, column=0, sticky='w')
            self.refresh_sessions_btn = ttk.Button(
                sessions_toolbar, text='Refresh', command=self.handle_refresh_sessions
            )
            self.refresh_sessions_btn.grid(row=0, column=1, padx=(6, 6))
            self.logout_session_btn = ttk.Button(
                sessions_toolbar, text='Logout Session', command=self.handle_logout_session, state='disabled'
            )
            self.logout_session_btn.grid(row=0, column=2, padx=(0, 6), sticky='e')
            self.end_sessions_btn = ttk.Button(
                sessions_toolbar, text='End All Sessions', command=self.handle_end_sessions
            )
            self.end_sessions_btn.grid(row=0, column=3, sticky='e')

            sessions_table = ttk.Frame(sessions_frame)
            sessions_table.grid(row=1, column=0, sticky='nsew')
            sessions_table.columnconfigure(0, weight=1)
            sessions_table.rowconfigure(0, weight=1)

            session_columns = ('client', 'ip', 'created', 'last_seen')
            self.sessions_tree = ttk.Treeview(
                sessions_table,
                columns=session_columns,
                show='headings',
                selectmode='browse'
            )
            self.sessions_tree.heading('client', text='Browser / Device')
            self.sessions_tree.heading('ip', text='IP Address')
            self.sessions_tree.heading('created', text='Logged in at')
            self.sessions_tree.heading('last_seen', text='Last active')
            self.sessions_tree.column('client', width=220, anchor='w')
            self.sessions_tree.column('ip', width=140, anchor='center')
            self.sessions_tree.column('created', width=180, anchor='w')
            self.sessions_tree.column('last_seen', width=180, anchor='w')
            self.sessions_tree.grid(row=0, column=0, sticky='nsew')
            sessions_scroll = ttk.Scrollbar(sessions_table, orient='vertical', command=self.sessions_tree.yview)
            sessions_scroll.grid(row=0, column=1, sticky='ns')
            self.sessions_tree.configure(yscrollcommand=sessions_scroll.set)
            self.sessions_tree.bind('<<TreeviewSelect>>', self.on_session_row_select)

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

            if not self.prompt_set_pin(force=True):
                messagebox.showerror('PIN required', 'Unable to set a PIN. Device will remain locked.')
            self.is_unlocked = True
            self.unlock_pin_var.set('')
            self.unlock_error_var.set('')
            self.render_dashboard()
            self.start_polling()

        def handle_unlock(self):
            pin = self.unlock_pin_var.get().strip()
            if not pin:
                self.unlock_error_var.set('Enter your PIN to continue.')
                return
            if not self.client.verify_pin(pin):
                self.unlock_error_var.set('Incorrect PIN. Please try again.')
                self.unlock_pin_var.set('')
                return
            self.unlock_pin_var.set('')
            self.unlock_error_var.set('')
            self.is_unlocked = True
            self.render_dashboard()
            self.start_polling()

        def lock_app(self):
            if not self.client.is_linked():
                return
            self.stop_polling()
            self.is_unlocked = False
            self.unlock_pin_var.set('')
            self.unlock_error_var.set('')
            self.render_unlock_screen()

        def unlink_device(self):
            if not self.client.is_linked():
                self.render_link_form()
                return
            confirm = messagebox.askyesno(
                'Unlink Device',
                'Are you sure you want to unlink this device? You will need a new link code to re-enrol.'
            )
            if not confirm:
                return
            self.client.relink()
            self.login_lookup.clear()
            self.selected_login_id = None
            self.stop_polling()
            self.is_unlocked = False
            self.unlock_pin_var.set('')
            self.unlock_error_var.set('')
            self.log('Device unlinked. Link again to approve logins.')
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
            sessions = payload.get('sessions', [])
            status = payload.get('status', {})
            if self.pending_tree:
                self.refresh_login_table(logins)
            if self.sessions_tree:
                self.refresh_sessions_table(sessions)
            self.update_status_bar(status)

        def refresh_login_table(self, logins):
            current_ids = set(self.pending_tree.get_children())
            incoming_ids = set()
            self.login_lookup = {}

            for login in logins:
                login_id = login['login_id']
                incoming_ids.add(login_id)
                self.login_lookup[login_id] = login
                values = (
                    client_label_from_metadata(login),
                    login.get('ip_address') or '—',
                    login.get('created_at', '—')
                )
                if login_id in current_ids:
                    self.pending_tree.item(login_id, values=values)
                else:
                    self.pending_tree.insert('', 'end', iid=login_id, values=values)

            for missing in current_ids - incoming_ids:
                self.pending_tree.delete(missing)

            if self.selected_login_id and self.selected_login_id not in incoming_ids:
                self.selected_login_id = None
                self.pending_tree.selection_remove(self.pending_tree.selection())
            self.update_login_buttons()

        def refresh_sessions_table(self, sessions):
            current_ids = set(self.sessions_tree.get_children())
            incoming_ids = set()
            self.session_lookup = {}

            for session in sessions:
                session_id = session['session_id']
                incoming_ids.add(session_id)
                self.session_lookup[session_id] = session
                values = (
                    client_label_from_metadata(session),
                    session.get('ip_address') or '—',
                    session.get('created_at', '—'),
                    session.get('last_seen_at', '—')
                )
                if session_id in current_ids:
                    self.sessions_tree.item(session_id, values=values)
                else:
                    self.sessions_tree.insert('', 'end', iid=session_id, values=values)

            for missing in current_ids - incoming_ids:
                self.sessions_tree.delete(missing)

            if self.selected_session_id and self.selected_session_id not in incoming_ids:
                self.selected_session_id = None
                self.sessions_tree.selection_remove(self.sessions_tree.selection())
            self.update_session_buttons()

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

        def on_pending_row_select(self, _event):
            selection = self.pending_tree.selection()
            self.selected_login_id = selection[0] if selection else None
            self.update_login_buttons()

        def on_session_row_select(self, _event):
            selection = self.sessions_tree.selection()
            self.selected_session_id = selection[0] if selection else None
            self.update_session_buttons()

        def update_login_buttons(self):
            state = 'normal' if self.selected_login_id else 'disabled'
            if self.approve_btn:
                self.approve_btn.configure(state=state)
            if self.reject_btn:
                self.reject_btn.configure(state=state)

        def update_session_buttons(self):
            state = 'normal' if self.selected_session_id else 'disabled'
            if self.logout_session_btn:
                self.logout_session_btn.configure(state=state)

        def get_selected_login(self):
            if not self.selected_login_id:
                return None
            return self.login_lookup.get(self.selected_login_id)

        def get_selected_session(self):
            if not self.selected_session_id:
                return None
            return self.session_lookup.get(self.selected_session_id)

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
                result = self.client.end_sessions()
            except DeviceError as exc:
                messagebox.showerror('Unable to end sessions', str(exc))
                return
            ended = result.get('ended_sessions') if isinstance(result, dict) else None
            summary = f'Revoked {ended} session(s).' if ended is not None else 'Requested the server to end active sessions.'
            messagebox.showinfo('Sessions ended', summary)
            self.handle_refresh_sessions()

        def handle_refresh_sessions(self):
            threading.Thread(target=self._refresh_sessions_thread, daemon=True).start()

        def _refresh_sessions_thread(self):
            try:
                sessions = self.client.fetch_active_sessions()
            except DeviceError as exc:
                self.after(0, lambda: messagebox.showerror('Unable to refresh sessions', str(exc)))
                return
            self.after(0, lambda: self.refresh_sessions_table(sessions))

        def handle_logout_session(self):
            session = self.get_selected_session()
            if not session:
                messagebox.showinfo('No selection', 'Select an active session to log out.')
                return
            label = client_label_from_metadata(session)
            try:
                self.client.end_single_session(session['session_id'])
            except DeviceError as exc:
                messagebox.showerror('Unable to logout session', str(exc))
                return
            self.log(f'Logged out session {session["session_id"]} ({label}).')
            self.selected_session_id = None
            self.handle_refresh_sessions()

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

        if self.client.is_linked() and not self.unlock_with_pin():
            return

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

    def run_session_manager(self):
        self.log('Trustlogin Device CLI · Session Manager')
        if not self.client.is_linked():
            self.log('No linked device found. Follow the prompts to link this terminal.')
            try:
                self.prompt_link()
            except SystemExit:
                return
        if self.client.is_linked() and not self.unlock_with_pin():
            return
        while True:
            try:
                sessions = self.client.fetch_active_sessions()
            except DeviceError as exc:
                self.log(f'Unable to load sessions: {exc}')
                return

            if not sessions:
                self.log('No active sessions for this account.')
            else:
                self.log('Active sessions:')
                for idx, session in enumerate(sessions, start=1):
                    label = client_label_from_metadata(session)
                    created = session.get('created_at', '—')
                    last_seen = session.get('last_seen_at', '—')
                    ip = session.get('ip_address') or '—'
                    print(f'  [{idx}] {label} · IP {ip} · started {created} · last seen {last_seen}')

            choice = input(
                "Select a session number to revoke, 'a' to revoke all sessions, or press Enter to exit: "
            ).strip()
            if not choice:
                break
            if choice.lower() == 'a':
                try:
                    result = self.client.end_sessions()
                    ended = result.get('ended_sessions') if isinstance(result, dict) else None
                    note = f"Revoked {ended} session(s)." if ended is not None else 'Requested session revoke.'
                    self.log(note)
                except DeviceError as exc:
                    self.log(f'Unable to revoke sessions: {exc}')
                continue

            if not choice.isdigit():
                self.log('Enter a valid number.')
                continue
            idx = int(choice)
            if idx < 1 or idx > len(sessions):
                self.log('Number out of range.')
                continue

            session = sessions[idx - 1]
            label = client_label_from_metadata(session)
            try:
                self.client.end_single_session(session['session_id'])
                self.log(f'Revoked {label} session.')
            except DeviceError as exc:
                self.log(f'Unable to revoke session: {exc}')

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
        self.prompt_pin_setup(force=True)

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
        label = client_label_from_metadata(login)
        self.log(f'Login request from {label} for {email} @ {created_at}')
        if login.get('ip_address'):
            self.log(f"Origin IP: {login['ip_address']}")
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

    def prompt_pin_setup(self, force=False):
        while True:
            pin = getpass(f'Set a {PIN_MIN_LENGTH}-{PIN_MAX_LENGTH} digit PIN: ').strip()
            if not pin:
                if force:
                    self.log('PIN is required to protect this device.')
                    continue
                return
            if not pin.isdigit() or not (PIN_MIN_LENGTH <= len(pin) <= PIN_MAX_LENGTH):
                self.log(f'PIN must be {PIN_MIN_LENGTH}-{PIN_MAX_LENGTH} digits.')
                continue
            confirm = getpass('Confirm PIN: ').strip()
            if pin != confirm:
                self.log('PIN entries did not match.')
                continue
            try:
                self.client.set_pin(pin)
                self.log('PIN saved.')
                return
            except DeviceError as exc:
                self.log(f'Unable to set PIN: {exc}')

    def unlock_with_pin(self):
        if not self.client.is_linked():
            return False
        if not self.client.has_pin():
            self.prompt_pin_setup(force=True)
        attempts = 3
        while attempts > 0:
            pin = getpass('Enter device PIN to unlock: ').strip()
            if self.client.verify_pin(pin):
                self.log('Device unlocked.')
                return True
            attempts -= 1
            self.log('Incorrect PIN.')
        self.log('Too many incorrect PIN attempts. Exiting.')
        return False


def main():
    parser = argparse.ArgumentParser(description='Trustlogin device app')
    parser.add_argument('--cli', action='store_true', help='Run in terminal mode instead of the Tk GUI.')
    parser.add_argument('--sessions', action='store_true', help='In CLI mode, manage active sessions.')
    parser.add_argument('--poll-interval', type=int, default=POLL_INTERVAL, help='Seconds between poll requests.')
    args = parser.parse_args()

    if args.cli:
        cli = DeviceCLI(poll_interval=args.poll_interval)
        if args.sessions:
            cli.run_session_manager()
        else:
            cli.run()
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
