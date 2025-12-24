import asyncio
import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from typing import Optional

from client.app import ClientRuntime


class LoginWindow:
    """Initial login screen with options to create account or login."""
    
    def __init__(self, parent: tk.Tk, on_create_account: callable, on_login: callable):
        self.parent = parent
        self.on_create_account = on_create_account
        self.on_login = on_login
        self.frame = ttk.Frame(parent, padding=40)
        self.frame.pack(fill="both", expand=True)
        self._build_ui()
    
    def _build_ui(self) -> None:
        # Title
        title_label = ttk.Label(
            self.frame,
            text="E2E Messenger",
            font=("TkDefaultFont", 24, "bold")
        )
        title_label.pack(pady=(0, 40))
        
        # Subtitle
        subtitle_label = ttk.Label(
            self.frame,
            text="Secure End-to-End Encrypted Messaging",
            font=("TkDefaultFont", 10)
        )
        subtitle_label.pack(pady=(0, 60))
        
        # Buttons frame
        buttons_frame = ttk.Frame(self.frame)
        buttons_frame.pack(pady=20)
        
        # Create Account button
        create_btn = ttk.Button(
            buttons_frame,
            text="Create New Account",
            command=self.on_create_account,
            width=25
        )
        create_btn.pack(pady=10)
        
        # Login button
        login_btn = ttk.Button(
            buttons_frame,
            text="Login to Existing Account",
            command=self.on_login,
            width=25
        )
        login_btn.pack(pady=10)
    
    def destroy(self) -> None:
        self.frame.destroy()


class CreateAccountWindow:
    """Window for creating a new account."""
    
    def __init__(self, parent: tk.Tk, on_back: callable, on_create: callable):
        self.parent = parent
        self.on_back = on_back
        self.on_create = on_create
        self.frame = ttk.Frame(parent, padding=40)
        self.frame.pack(fill="both", expand=True)
        
        self.username_var = tk.StringVar()
        self.pass_var = tk.StringVar()
        self.confirm_pass_var = tk.StringVar()
        self.status_var = tk.StringVar(value="")
        
        self._build_ui()
    
    def _build_ui(self) -> None:
        # Title
        title_label = ttk.Label(
            self.frame,
            text="Create New Account",
            font=("TkDefaultFont", 18, "bold")
        )
        title_label.pack(pady=(0, 30))
        
        # Form frame
        form_frame = ttk.Frame(self.frame)
        form_frame.pack(pady=20)
        
        # Username
        ttk.Label(form_frame, text="Username:").grid(row=0, column=0, sticky="w", pady=5)
        username_entry = ttk.Entry(form_frame, textvariable=self.username_var, width=30)
        username_entry.grid(row=0, column=1, padx=10, pady=5)
        username_entry.focus_set()
        
        # Passphrase
        ttk.Label(form_frame, text="Passphrase:").grid(row=1, column=0, sticky="w", pady=5)
        pass_entry = ttk.Entry(form_frame, textvariable=self.pass_var, show="*", width=30)
        pass_entry.grid(row=1, column=1, padx=10, pady=5)
        
        # Confirm passphrase
        ttk.Label(form_frame, text="Confirm:").grid(row=2, column=0, sticky="w", pady=5)
        confirm_entry = ttk.Entry(form_frame, textvariable=self.confirm_pass_var, show="*", width=30)
        confirm_entry.grid(row=2, column=1, padx=10, pady=5)
        confirm_entry.bind("<Return>", lambda e: self._handle_create())
        
        # Status label
        status_label = ttk.Label(self.frame, textvariable=self.status_var, foreground="red")
        status_label.pack(pady=10)
        
        # Buttons frame
        buttons_frame = ttk.Frame(self.frame)
        buttons_frame.pack(pady=20)
        
        # Back button
        back_btn = ttk.Button(buttons_frame, text="Back", command=self.on_back)
        back_btn.pack(side="left", padx=5)
        
        # Create button
        create_btn = ttk.Button(buttons_frame, text="Create Account", command=self._handle_create)
        create_btn.pack(side="left", padx=5)
    
    def _validate_input(self) -> tuple[bool, str]:
        """Validate user input. Returns (is_valid, error_message)."""
        username = self.username_var.get().strip()
        passphrase = self.pass_var.get()
        confirm_pass = self.confirm_pass_var.get()
        
        if not username:
            return False, "Username is required."
        
        if len(username) < 3:
            return False, "Username must be at least 3 characters."
        
        if not username.replace("_", "").replace("-", "").replace(".", "").isalnum():
            return False, "Username can only contain letters, numbers, _, -, and ."
        
        if not passphrase:
            return False, "Passphrase is required."
        
        if len(passphrase) < 8:
            return False, "Passphrase must be at least 8 characters long."
        
        if passphrase != confirm_pass:
            return False, "Passphrases do not match."
        
        return True, ""
    
    def _handle_create(self) -> None:
        is_valid, error_msg = self._validate_input()
        if not is_valid:
            self.status_var.set(error_msg)
            return
        
        username = self.username_var.get().strip()
        passphrase = self.pass_var.get()
        
        # Check if account already exists
        if ClientRuntime.check_account_exists(username):
            self.status_var.set(f"Account '{username}' already exists. Please login instead.")
            return
        
        # Call the create callback
        self.on_create(username, passphrase)
    
    def destroy(self) -> None:
        self.frame.destroy()


class LoginFormWindow:
    """Window for logging into an existing account."""
    
    def __init__(self, parent: tk.Tk, on_back: callable, on_login: callable):
        self.parent = parent
        self.on_back = on_back
        self.on_login = on_login
        self.frame = ttk.Frame(parent, padding=40)
        self.frame.pack(fill="both", expand=True)
        
        self.username_var = tk.StringVar()
        self.pass_var = tk.StringVar()
        self.status_var = tk.StringVar(value="")
        
        self._build_ui()
    
    def _build_ui(self) -> None:
        # Title
        title_label = ttk.Label(
            self.frame,
            text="Login to Account",
            font=("TkDefaultFont", 18, "bold")
        )
        title_label.pack(pady=(0, 30))
        
        # Form frame
        form_frame = ttk.Frame(self.frame)
        form_frame.pack(pady=20)
        
        # Username
        ttk.Label(form_frame, text="Username:").grid(row=0, column=0, sticky="w", pady=5)
        username_entry = ttk.Entry(form_frame, textvariable=self.username_var, width=30)
        username_entry.grid(row=0, column=1, padx=10, pady=5)
        username_entry.focus_set()
        
        # Passphrase
        ttk.Label(form_frame, text="Passphrase:").grid(row=1, column=0, sticky="w", pady=5)
        pass_entry = ttk.Entry(form_frame, textvariable=self.pass_var, show="*", width=30)
        pass_entry.grid(row=1, column=1, padx=10, pady=5)
        pass_entry.bind("<Return>", lambda e: self._handle_login())
        
        # Status label
        status_label = ttk.Label(self.frame, textvariable=self.status_var, foreground="red")
        status_label.pack(pady=10)
        
        # Buttons frame
        buttons_frame = ttk.Frame(self.frame)
        buttons_frame.pack(pady=20)
        
        # Back button
        back_btn = ttk.Button(buttons_frame, text="Back", command=self.on_back)
        back_btn.pack(side="left", padx=5)
        
        # Login button
        login_btn = ttk.Button(buttons_frame, text="Login", command=self._handle_login)
        login_btn.pack(side="left", padx=5)
    
    def _handle_login(self) -> None:
        username = self.username_var.get().strip()
        passphrase = self.pass_var.get()
        
        if not username:
            self.status_var.set("Username is required.")
            return
        
        if not passphrase:
            self.status_var.set("Passphrase is required.")
            return
        
        # Check if account exists
        if not ClientRuntime.check_account_exists(username):
            self.status_var.set(f"Account '{username}' does not exist. Please create a new account.")
            return
        
        # Call the login callback
        self.on_login(username, passphrase)
    
    def destroy(self) -> None:
        self.frame.destroy()


class ClientGUI:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("E2E Messenger")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.status_var = tk.StringVar(value="Disconnected")

        self.loop = asyncio.new_event_loop()
        self.loop_thread: Optional[threading.Thread] = None
        self.client: Optional[ClientRuntime] = None
        self.connected = False
        self.friends: list[dict] = []
        self.online_users: list[dict] = []
        self._refresh_job: Optional[str] = None
        self._online_request_active = False
        self.event_queue: queue.Queue = queue.Queue()
        self.chat_active_alias: Optional[str] = None
        self._listener_registered = False
        self.friend_lookup: dict[str, dict] = {}
        self._pending_incoming: dict[str, dict[tuple[int, int], dict]] = {}
        self._friends_sig: Optional[tuple] = None
        self._online_sig: Optional[tuple] = None
        
        # Authentication state
        self._current_window: Optional[tk.Widget] = None
        self._main_window: Optional[ttk.Frame] = None
        self._account_creation_in_progress: bool = False
        self._pending_username: Optional[str] = None

        # Show login screen first
        self._show_login_screen()
        self.root.after(200, self._drain_events)

    def _is_device_limit_error(self, msg: str) -> bool:
        m = msg.lower()
        return "device limit" in m or "maximum 2 devices" in m

    def _show_login_screen(self) -> None:
        """Show the initial login screen."""
        if self._current_window:
            self._current_window.destroy()
        
        login_window = LoginWindow(
            self.root,
            on_create_account=self._show_create_account_screen,
            on_login=self._show_login_form_screen
        )
        self._current_window = login_window.frame
    
    def _show_create_account_screen(self) -> None:
        """Show the create account screen."""
        if self._current_window:
            self._current_window.destroy()
        
        create_window = CreateAccountWindow(
            self.root,
            on_back=self._show_login_screen,
            on_create=self._handle_create_account
        )
        self._current_window = create_window.frame
    
    def _show_login_form_screen(self) -> None:
        """Show the login form screen."""
        if self._current_window:
            self._current_window.destroy()
        
        login_form = LoginFormWindow(
            self.root,
            on_back=self._show_login_screen,
            on_login=self._handle_login
        )
        self._current_window = login_form.frame
    
    def _show_main_window(self) -> None:
        """Show the main application window."""
        if self._current_window:
            self._current_window.destroy()
        
        main = ttk.Frame(self.root, padding=12)
        main.pack(fill="both", expand=True)
        self._main_window = main
        self._current_window = main
        
        # Status row
        status_row = ttk.Frame(main)
        status_row.pack(fill="x", pady=(6, 6))
        ttk.Label(status_row, textvariable=self.status_var).pack(side="left")
        
        self._build_main_ui(main)
    
    def _show_main_window_after_account_creation(self, username: str) -> None:
        """Fallback method to show main window after account creation if callback didn't fire."""
        if self.connected:
            return  # Already connected
        
        # Try to create client if it doesn't exist
        if not self.client:
            try:
                # Create client in a way that won't fail
                from client.app import ClientRuntime
                # We'll create it without connecting to server for now
                passphrase = ""  # We don't have it here, but we'll handle it
                # Actually, we need the client to be created properly
                # Let's just show the window and let user login again if needed
                print(f"[GUI] Showing main window for account {username} (fallback)")
            except Exception as e:
                print(f"[GUI] Error in fallback: {e}")
        
        # Show main window anyway
        self.connected = True
        self.status_var.set(f"Account: {username}")
        self._show_main_window()
        
        # Show info message
        messagebox.showinfo("Account Created", 
            f"Your account '{username}' was created successfully.\n\n"
            "Please restart the app and login to connect to the server.")
    
    def _build_main_ui(self, main: ttk.Frame) -> None:
        """Build the main application UI (friends, online users, chat)."""

        friends_frame = ttk.LabelFrame(main, text="Friends", padding=8)
        friends_frame.pack(fill="both", expand=True, pady=(8, 6))
        self.friend_container = ttk.Frame(friends_frame)
        self.friend_container.pack(fill="both", expand=True)

        online_frame = ttk.LabelFrame(main, text="Online Users", padding=8)
        online_frame.pack(fill="both", expand=True)
        self.online_container = ttk.Frame(online_frame)
        self.online_container.pack(fill="both", expand=True)

        chat_frame = ttk.LabelFrame(main, text="Chat", padding=8)
        chat_frame.pack(fill="both", expand=True, pady=(8, 0))

        header = ttk.Frame(chat_frame)
        header.pack(fill="x")
        self.chat_title = tk.StringVar(value="No chat selected")
        ttk.Label(header, textvariable=self.chat_title, font=("TkDefaultFont", 10, "bold")).pack(side="left")

        self.chat_text = tk.Text(chat_frame, height=12, wrap="word", state="disabled")
        self.chat_text.pack(fill="both", expand=True, pady=4)

        input_row = ttk.Frame(chat_frame)
        input_row.pack(fill="x")
        self.chat_entry = ttk.Entry(input_row)
        self.chat_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.chat_entry.bind("<Return>", self.send_chat_message)
        self.chat_send_btn = ttk.Button(input_row, text="Send", command=self.send_chat_message)
        self.chat_send_btn.pack(side="left")
        self._update_chat_controls(enabled=False)
    
    def _handle_create_account(self, username: str, passphrase: str) -> None:
        """Handle account creation."""
        self.status_var.set("Creating account...")
        if self.loop_thread is None:
            self.loop_thread = threading.Thread(target=self._run_loop, daemon=True)
            self.loop_thread.start()
        
        # Store username for later checking
        self._pending_username = username
        
        def safe_callback(fut):
            """Ensure callback always executes, even if there's an error."""
            try:
                self.root.after(0, self._handle_connect_result, fut)
            except Exception as e:
                print(f"[GUI] Error in callback: {e}")
                import traceback
                traceback.print_exc()
                # Fallback: check if account was created and show main window
                from client.app import ClientRuntime
                if ClientRuntime.check_account_exists(username):
                    self.root.after(0, lambda: self._show_main_window_after_account_creation(username))
        
        future = asyncio.run_coroutine_threadsafe(
            self._init_client(username, passphrase, is_new_account=True),
            self.loop
        )
        future.add_done_callback(safe_callback)
        
        # Also set a timeout to check if account was created
        def check_account_created():
            from client.app import ClientRuntime
            if ClientRuntime.check_account_exists(username) and not self.connected:
                # Account was created but callback didn't fire - show main window
                print(f"[GUI] Account {username} exists but callback didn't fire - showing main window")
                self._show_main_window_after_account_creation(username)
        
        # Check after 3 seconds if account was created
        self.root.after(3000, check_account_created)
    
    def _handle_login(self, username: str, passphrase: str) -> None:
        """Handle login."""
        self.status_var.set("Connecting...")
        if self.loop_thread is None:
            self.loop_thread = threading.Thread(target=self._run_loop, daemon=True)
            self.loop_thread.start()
        self._pending_username = username
        future = asyncio.run_coroutine_threadsafe(
            self._init_client(username, passphrase, is_new_account=False),
            self.loop
        )

        def check_future() -> None:
            if future.done():
                self._handle_connect_result(future)
                return
            self.root.after(100, check_future)

        self.root.after(100, check_future)

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    async def _init_client(self, username: str, passphrase: str, is_new_account: bool = False) -> None:
        client = ClientRuntime(username, passphrase)
        self.client = client
        # Track if this is account creation so we can show main window even if server connection fails
        self._account_creation_in_progress = is_new_account
        await client.start(is_new_account=is_new_account)
        # If we get here, everything succeeded including server connection
        self._account_creation_in_progress = False

    def _handle_connect_result(self, fut: asyncio.Future) -> None:
        import traceback
        import sys
        
        # Check if account was actually created (by checking filesystem)
        account_was_created = False
        username_for_check = None
        
        # First try to get username from client
        if self.client:
            username_for_check = getattr(self.client, 'username', None)
        
        # Fallback to pending username if client doesn't have it
        if not username_for_check:
            username_for_check = getattr(self, '_pending_username', None)
        
        # Check filesystem to see if account was created
        if username_for_check:
            from client.app import ClientRuntime
            account_was_created = ClientRuntime.check_account_exists(username_for_check)
            print(f"[GUI] Checking account existence for {username_for_check}: {account_was_created}")
        
        try:
            fut.result()
            # Success: show main window
            self.connected = True
            self.status_var.set(f"Connected as {self.client.username}")
            self._show_main_window()
            if self.client and not self._listener_registered:
                self.loop.call_soon_threadsafe(self.client.add_event_listener, self._on_runtime_event)
                self._listener_registered = True
            self._start_polling()
            self._account_creation_in_progress = False
            return
        except SystemExit as exc:
            msg = str(exc) or "Authentication failed."
            # If account was created, show main window anyway
            if account_was_created and username_for_check:
                self.status_var.set(f"Account created, but authentication failed: {msg}")
                messagebox.showwarning("Authentication Warning", 
                    f"Your account '{username_for_check}' was created, but there was an authentication issue.\n\n"
                    f"Error: {msg}\n\n"
                    "You can still use the app.")
                self.connected = True
                self.status_var.set(f"Account: {username_for_check}")
                self._show_main_window()
                if self.client and not self._listener_registered:
                    self.loop.call_soon_threadsafe(self.client.add_event_listener, self._on_runtime_event)
                    self._listener_registered = True
                self._account_creation_in_progress = False
                return
            self.status_var.set("Authentication failed.")
            messagebox.showerror("Authentication failed", msg)
            self.client = None
            self._account_creation_in_progress = False
            return
        except RuntimeError as exc:
            error_msg = str(exc)
            if self._is_device_limit_error(error_msg):
                self.status_var.set("Device limit exceeded.")
                messagebox.showerror("Device limit exceeded", error_msg or "Maximum devices reached for this account.")
                self.client = None
                self._account_creation_in_progress = False
                self.root.after(0, self.on_close)
                return
            # Check if this is an account creation error (should stay on create screen)
            if "already exists" in error_msg.lower() or "does not exist" in error_msg.lower():
                self.status_var.set("Account error.")
                messagebox.showerror("Account error", error_msg)
                self.client = None
                self._account_creation_in_progress = False
                return
            
            # If account was created (either by flag or filesystem check), show main window
            if (self._account_creation_in_progress or account_was_created) and self.client:
                username = username_for_check or getattr(self.client, 'username', 'Unknown')
                self.status_var.set(f"Account created, but server connection failed: {error_msg}")
                messagebox.showwarning("Server Connection Failed", 
                    f"Your account '{username}' was created successfully, but couldn't connect to the server.\n\n"
                    f"Error: {error_msg}\n\n"
                    "You can still use the app, but messaging features won't work until the server is available.")
                # Show main window anyway - account was created
                self.connected = True
                self.status_var.set(f"Account: {username} (Offline)")
                self._show_main_window()
                if self.client and not self._listener_registered:
                    self.loop.call_soon_threadsafe(self.client.add_event_listener, self._on_runtime_event)
                    self._listener_registered = True
                self._account_creation_in_progress = False
                return
            else:
                self.status_var.set("Connection failed.")
                messagebox.showerror("Connection failed", error_msg)
                self.client = None
                self._account_creation_in_progress = False
                return
        except Exception as exc:
            error_msg = str(exc)
            error_type = type(exc).__name__
            # Print full traceback for debugging
            print(f"[GUI] Exception during account creation/login: {error_type}: {error_msg}")
            traceback.print_exc()
            
            # If account was created (either by flag or filesystem check), show main window
            if (self._account_creation_in_progress or account_was_created) and self.client:
                username = username_for_check or getattr(self.client, 'username', 'Unknown')
                self.status_var.set(f"Warning: {error_msg}")
                messagebox.showwarning("Connection Warning", 
                    f"Your account '{username}' was created, but there was an issue:\n\n"
                    f"Error ({error_type}): {error_msg}\n\n"
                    "You can still use the app.")
                self.connected = True
                self.status_var.set(f"Account: {username}")
                self._show_main_window()
                if self.client and not self._listener_registered:
                    self.loop.call_soon_threadsafe(self.client.add_event_listener, self._on_runtime_event)
                    self._listener_registered = True
                self._account_creation_in_progress = False
                return
            else:
                self.status_var.set("Connection failed.")
                messagebox.showerror("Connection failed", f"{error_type}: {error_msg}")
                self.client = None
                self._account_creation_in_progress = False
                # Stay on current screen (login/create account)
                return

    def _start_polling(self) -> None:
        self._stop_polling()
        self._poll()

    def _stop_polling(self) -> None:
        if self._refresh_job is not None:
            self.root.after_cancel(self._refresh_job)
            self._refresh_job = None

    def _poll(self) -> None:
        if not self.connected or not self.client:
            return
        self.refresh_friend_list()
        self.refresh_online_list()
        self._refresh_job = self.root.after(5000, self._poll)

    def refresh_friend_list(self) -> None:
        if not self.client:
            return
        future = asyncio.run_coroutine_threadsafe(self.client.list_contacts(), self.loop)

        def check_future() -> None:
            if future.done():
                self._update_friends_from_future(future)
                return
            self.root.after(100, check_future)

        self.root.after(100, check_future)

    def _friends_signature(self, friends: list[dict]) -> tuple:
        return tuple(
            (f.get("alias"), f.get("remote_username"), bool(f.get("verified")), f.get("fingerprint"))
            for f in friends
        )

    def _update_friends_from_future(self, fut: asyncio.Future) -> None:
        if not self.connected:
            return
        try:
            friends = fut.result()
        except Exception as exc:
            self.status_var.set(f"Friend list error: {exc}")
            return
        sig = self._friends_signature(friends)
        if sig == self._friends_sig:
            return
        self._friends_sig = sig
        self.friends = friends
        self.friend_lookup = {f["alias"]: f for f in friends}
        self._render_friend_list()

    def refresh_online_list(self) -> None:
        if not self.client or self._online_request_active:
            return
        self._online_request_active = True
        future = asyncio.run_coroutine_threadsafe(self.client.get_online_users(), self.loop)

        def check_future() -> None:
            if future.done():
                self._handle_online_result(future)
                return
            self.root.after(100, check_future)

        self.root.after(100, check_future)

    def _online_signature(self, users: list[dict]) -> tuple:
        return tuple((u.get("user"), u.get("fingerprint")) for u in users)

    def _handle_online_result(self, fut: asyncio.Future) -> None:
        self._online_request_active = False
        if not self.connected:
            return
        try:
            users = fut.result() or []
        except Exception as exc:
            self.status_var.set(f"Online query error: {exc}")
            return
        sig = self._online_signature(users)
        if sig == self._online_sig:
            return
        self._online_sig = sig
        self.online_users = users
        self._render_online_list()
        self._render_friend_list()

    def _render_friend_list(self) -> None:
        if not hasattr(self, 'friend_container') or self.friend_container is None:
            return
        for child in self.friend_container.winfo_children():
            child.destroy()
        if not self.friends:
            ttk.Label(self.friend_container, text="No friends yet.").pack(anchor="w")
            return
        online_set = {entry.get("user") for entry in self.online_users}
        for friend in self.friends:
            alias = friend["alias"]
            remote = friend["remote_username"]
            row = ttk.Frame(self.friend_container)
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=alias, width=20).pack(side="left", padx=(0, 8))
            status = "Online" if remote in online_set else "Offline"
            if not friend["verified"]:
                status += " (pending)"
            color = "#0a6" if remote in online_set else "#a33"
            ttk.Label(row, text=status, foreground=color).pack(side="left", padx=(0, 8))
            button_box = ttk.Frame(row)
            button_box.pack(side="right")
            remove_btn = ttk.Button(button_box, text="Remove", command=lambda a=alias: self.remove_friend_gui(a))
            remove_btn.pack(side="right", padx=(4, 0))
            open_btn = ttk.Button(button_box, text="Open Chat", command=lambda a=alias: self.open_chat(a))
            if not friend["verified"]:
                open_btn.state(["disabled"])
            open_btn.pack(side="right", padx=(4, 0))

    def _render_online_list(self) -> None:
        if not hasattr(self, 'online_container') or self.online_container is None:
            return
        for child in self.online_container.winfo_children():
            child.destroy()
        if not self.online_users:
            ttk.Label(self.online_container, text="No users online.").pack(anchor="w")
            return
        alias_map = {f["remote_username"]: f for f in self.friends}
        for entry in sorted(self.online_users, key=lambda e: e.get("user", "")):
            user = entry.get("user", "?")
            fp = entry.get("fingerprint")
            friend = alias_map.get(user)
            row = ttk.Frame(self.online_container)
            row.pack(fill="x", pady=2)
            label_text = user
            if friend and friend["alias"] != user:
                label_text = f"{friend['alias']} ({user})"
            if fp:
                label_text = f"{label_text} [{fp[:8]}]"
            ttk.Label(row, text=label_text).pack(side="left", padx=(0, 8))
            if friend and friend.get("verified"):
                ttk.Button(row, text="Open Chat", command=lambda a=friend["alias"]: self.open_chat(a)).pack(side="right")
            elif friend and not friend.get("verified"):
                ttk.Label(row, text="Pending verification").pack(side="right")
            else:
                ttk.Button(
                    row,
                    text="Send Friend Request",
                    command=lambda u=user: self.send_friend_request_online(u),
                ).pack(side="right")

    def remove_friend_gui(self, alias: str) -> None:
        if not self.client:
            return
        if not messagebox.askyesno("Remove friend", f"Remove {alias} from your contacts?"):
            return
        future = asyncio.run_coroutine_threadsafe(self.client.remove_friend(alias), self.loop)
        future.add_done_callback(lambda fut: self.root.after(0, self._handle_remove_result, fut))

    def send_friend_request_online(self, remote_username: str) -> None:
        if not self.client:
            return
        alias = simpledialog.askstring(
            "Friend request",
            f"Choose a nickname for {remote_username}:",
            initialvalue=remote_username,
            parent=self.root,
        )
        if alias is None:
            return
        alias = alias.strip() or remote_username
        future = asyncio.run_coroutine_threadsafe(
            self.client.send_friend_request(alias, remote_username),
            self.loop,
        )
        future.add_done_callback(
            lambda fut: self.root.after(0, self._handle_future_error, fut, f"friend request to {remote_username}")
        )

    def open_chat(self, alias: str, focus: bool = True) -> None:
        if not self.client:
            return
        self.chat_active_alias = alias
        self.chat_title.set(f"Chat with {alias}")
        self._update_chat_controls(enabled=True)
        self._load_chat_history(alias)
        future = asyncio.run_coroutine_threadsafe(self.client.open_chat(alias), self.loop)
        future.add_done_callback(
            lambda fut, name=alias: self.root.after(0, self._handle_future_error, fut, f"open chat with {name}")
        )
        if focus:
            self.chat_entry.focus_set()

    def _load_chat_history(self, alias: str) -> None:
        if not self.client:
            return
        self._set_chat_text("")
        future = asyncio.run_coroutine_threadsafe(self.client.list_messages(alias, limit=200), self.loop)

        def check_future() -> None:
            if future.done():
                self._populate_chat_history(alias, future)
                return
            self.root.after(100, check_future)

        self.root.after(100, check_future)

    def _populate_chat_history(self, alias: str, fut: asyncio.Future) -> None:
        if alias != self.chat_active_alias:
            return
        try:
            messages = fut.result()
        except Exception as exc:
            self.status_var.set(f"History error: {exc}")
            return
        lines = []
        seen = set()
        for entry in messages:
            text = entry.get("text") or ""
            if entry.get("direction") == "out":
                prefix = "You"
            else:
                prefix = alias
            lines.append(f"{prefix}: {text}")
            sess = entry.get("session_epoch")
            rid = entry.get("remote_id")
            if sess is not None and rid is not None:
                try:
                    seen.add((int(sess), int(rid)))
                except Exception:
                    pass
        pending = self._pending_incoming.pop(alias, {})
        remote_key = None
        if hasattr(self, 'friend_lookup') and alias in self.friend_lookup:
            remote_key = self.friend_lookup[alias].get("remote_username")
        if remote_key and remote_key != alias:
            pending.update(self._pending_incoming.pop(remote_key, {}))
        for key, pdata in pending.items():
            if key in seen:
                continue
            p_text = pdata.get("text") or ""
            p_dir = pdata.get("direction", "in")
            prefix = "You" if p_dir == "out" else alias
            lines.append(f"{prefix}: {p_text}")
        self._set_chat_text("\n".join(lines) + ("\n" if lines else ""))

    def send_chat_message(self, event: Optional[tk.Event] = None) -> None:
        if not self.client or not self.chat_active_alias:
            return
        text = self.chat_entry.get().strip()
        if not text:
            return
        self.chat_entry.delete(0, tk.END)
        future = asyncio.run_coroutine_threadsafe(self.client.send_text(self.chat_active_alias, text), self.loop)
        future.add_done_callback(lambda fut: self.root.after(0, self._handle_send_result, fut))

    def _handle_send_result(self, fut: asyncio.Future) -> None:
        try:
            fut.result()
        except Exception as exc:
            messagebox.showerror("Send failed", str(exc))

    def _handle_remove_result(self, fut: asyncio.Future) -> None:
        try:
            success = fut.result()
        except Exception as exc:
            messagebox.showerror("Remove friend", str(exc))
            return
        if success:
            self.status_var.set("Friend removed.")
        else:
            self.status_var.set("Friend removal failed; check console.")

    def _append_chat_line(
        self,
        alias: str,
        direction: str,
        text: str,
        session_id: Optional[int] = None,
        seq: Optional[int] = None,
        remote: Optional[str] = None,
    ) -> None:
        if not hasattr(self, 'chat_text') or self.chat_text is None:
            return
        if alias != self.chat_active_alias:
            self.status_var.set(f"New message from {alias}")
            if session_id is not None and seq is not None:
                pending = self._pending_incoming.setdefault(alias, {})
                pending[(session_id, seq)] = {"direction": direction, "text": text}
                if remote and remote != alias:
                    alt = self._pending_incoming.setdefault(remote, {})
                    alt[(session_id, seq)] = {"direction": direction, "text": text}
            return
        prefix = "You" if direction == "out" else alias
        line = f"{prefix}: {text}"
        self.chat_text.config(state="normal")
        self.chat_text.insert(tk.END, line + "\n")
        self.chat_text.config(state="disabled")
        self.chat_text.see(tk.END)

    def _set_chat_text(self, text: str) -> None:
        if not hasattr(self, 'chat_text') or self.chat_text is None:
            return
        self.chat_text.config(state="normal")
        self.chat_text.delete("1.0", tk.END)
        if text:
            self.chat_text.insert(tk.END, text)
        self.chat_text.config(state="disabled")
        self.chat_text.see(tk.END)

    def _update_chat_controls(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        self.chat_entry.config(state=state)
        self.chat_send_btn.config(state=state)
        if not enabled:
            self.chat_title.set("No chat selected")
            self._set_chat_text("")

    def _on_runtime_event(self, event: dict) -> None:
        self.event_queue.put(event)

    def _drain_events(self) -> None:
        try:
            while True:
                event = self.event_queue.get_nowait()
                self._handle_runtime_event(event)
        except queue.Empty:
            pass
        finally:
            self.root.after(200, self._drain_events)

    def _handle_runtime_event(self, event: dict) -> None:
        if not self.client:
            return
        etype = event.get("type")
        if etype == "friend_request":
            remote = event.get("remote")
            if not remote:
                return
            suggested = event.get("suggested_alias") or remote
            self.status_var.set(f"Friend request from {remote}")
            accept = messagebox.askyesno("Friend request", f"{remote} wants to connect. Accept?")
            if accept:
                alias = simpledialog.askstring(
                    "Friend request",
                    f"Nickname for {remote}:",
                    initialvalue=suggested,
                    parent=self.root,
                )
                if alias is None:
                    alias = suggested
            else:
                alias = None
            future = asyncio.run_coroutine_threadsafe(
                self.client.respond_friend_request(remote, accept, alias),
                self.loop,
            )
            future.add_done_callback(lambda fut: self.root.after(0, self._handle_future_error, fut, "friend response"))
        elif etype == "friend_request_sent":
            remote = event.get("remote")
            if remote:
                self.status_var.set(f"Friend request sent to {remote}.")
            self.refresh_friend_list()
            self.refresh_online_list()
        elif etype == "friend_accepted":
            alias = event.get("alias")
            remote = event.get("remote")
            if alias:
                self.status_var.set(f"{alias} accepted your friend request.")
            elif remote:
                self.status_var.set(f"{remote} accepted your friend request.")
            self.refresh_friend_list()
            self.refresh_online_list()
        elif etype == "friend_declined":
            remote = event.get("remote")
            if remote:
                self.status_var.set(f"{remote} declined the friend request.")
            self.refresh_friend_list()
            self.refresh_online_list()
        elif etype == "friend_added":
            alias = event.get("alias")
            if alias:
                self.status_var.set(f"Connected with {alias}.")
            self.refresh_friend_list()
            self.refresh_online_list()
        elif etype == "friend_removed":
            alias_name = event.get("alias")
            remote = event.get("remote")
            display = alias_name or remote or "A contact"
            initiator = event.get("initiator")
            if initiator == "local":
                self.status_var.set(f"Removed {display}.")
            else:
                self.status_var.set(f"{display} removed you.")
            if alias_name and alias_name == self.chat_active_alias:
                self.chat_active_alias = None
                self._update_chat_controls(False)
            self.refresh_friend_list()
            self.refresh_online_list()
        elif etype == "contact_unverified":
            alias = event.get("alias")
            if alias:
                self.status_var.set(f"{alias}'s key changed. Re-verify before chatting.")
            self.refresh_friend_list()
        elif etype == "message":
            alias = event.get("alias")
            remote = event.get("remote")
            text = event.get("text") or ""
            direction = event.get("direction", "in")
            session_id = event.get("session_id")
            seq = event.get("seq")
            label = alias or remote or "Unknown"
            self._append_chat_line(label, direction, text, session_id=session_id, seq=seq, remote=remote)

    def _handle_future_error(self, fut: asyncio.Future, context: str) -> None:
        try:
            fut.result()
        except Exception as exc:
            messagebox.showerror("Error", f"{context.capitalize()} failed: {exc}")

    def on_close(self) -> None:
        self._stop_polling()
        if self.client:
            if self._listener_registered:
                self.loop.call_soon_threadsafe(self.client.remove_event_listener, self._on_runtime_event)
                self._listener_registered = False
            future = asyncio.run_coroutine_threadsafe(self.client.shutdown(), self.loop)
            try:
                future.result(timeout=2)
            except Exception:
                pass
            self.client = None
        if self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)
        if self.loop_thread:
            self.loop_thread.join(timeout=2)
        if not self.loop.is_closed():
            self.loop.close()
        self.root.destroy()
        self.connected = False

    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    app = ClientGUI()
    app.run()


if __name__ == "__main__":
    main()
