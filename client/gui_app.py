import asyncio
import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from typing import Optional

from client.app import ClientRuntime


class ClientGUI:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("E2E Messenger")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.username_var = tk.StringVar()
        self.pass_var = tk.StringVar()
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

        self._build_ui()
        self.root.after(200, self._drain_events)

    def _build_ui(self) -> None:
        main = ttk.Frame(self.root, padding=12)
        main.pack(fill="both", expand=True)

        form = ttk.Frame(main)
        form.pack(fill="x")

        ttk.Label(form, text="Username").grid(row=0, column=0, sticky="w")
        self.username_entry = ttk.Entry(form, textvariable=self.username_var, width=24)
        self.username_entry.grid(row=0, column=1, padx=(6, 12), pady=(0, 4))

        ttk.Label(form, text="Passphrase").grid(row=1, column=0, sticky="w")
        self.pass_entry = ttk.Entry(form, textvariable=self.pass_var, show="*", width=24)
        self.pass_entry.grid(row=1, column=1, padx=(6, 12), pady=(0, 4))

        self.connect_button = ttk.Button(form, text="Connect", command=self.connect)
        self.connect_button.grid(row=0, column=2, rowspan=2, padx=(0, 4), pady=(0, 4))

        status_row = ttk.Frame(main)
        status_row.pack(fill="x", pady=(6, 6))
        ttk.Label(status_row, textvariable=self.status_var).pack(side="left")

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

    def connect(self) -> None:
        if self.connected:
            return
        username = self.username_var.get().strip()
        passphrase = self.pass_var.get()
        if not username or not passphrase:
            messagebox.showwarning("Missing information", "Enter both username and passphrase.")
            return
        self.status_var.set("Connecting...")
        self.connect_button.config(state="disabled")
        if self.loop_thread is None:
            self.loop_thread = threading.Thread(target=self._run_loop, daemon=True)
            self.loop_thread.start()
        future = asyncio.run_coroutine_threadsafe(self._init_client(username, passphrase), self.loop)
        future.add_done_callback(lambda fut: self.root.after(0, self._handle_connect_result, fut))

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    async def _init_client(self, username: str, passphrase: str) -> None:
        client = ClientRuntime(username, passphrase)
        self.client = client
        await client.start()

    def _handle_connect_result(self, fut: asyncio.Future) -> None:
        try:
            fut.result()
        except SystemExit as exc:
            msg = str(exc) or "Authentication failed."
            self.status_var.set("Authentication failed.")
            messagebox.showerror("Login failed", msg)
            self.connect_button.config(state="normal")
            self.client = None
            return
        except Exception as exc:
            self.status_var.set("Connection failed.")
            messagebox.showerror("Login failed", str(exc))
            self.connect_button.config(state="normal")
            self.client = None
            return

        self.connected = True
        self.status_var.set(f"Connected as {self.client.username}")
        self.username_entry.config(state="disabled")
        self.pass_entry.config(state="disabled")
        self.connect_button.config(text="Connected", state="disabled")
        if self.client and not self._listener_registered:
            self.loop.call_soon_threadsafe(self.client.add_event_listener, self._on_runtime_event)
            self._listener_registered = True
        self._start_polling()

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
        future.add_done_callback(lambda fut: self.root.after(0, self._update_friends_from_future, fut))

    def _update_friends_from_future(self, fut: asyncio.Future) -> None:
        if not self.connected:
            return
        try:
            friends = fut.result()
        except Exception as exc:
            self.status_var.set(f"Friend list error: {exc}")
            return
        self.friends = friends
        self.friend_lookup = {f["alias"]: f for f in friends}
        self._render_friend_list()

    def refresh_online_list(self) -> None:
        if not self.client or self._online_request_active:
            return
        self._online_request_active = True
        future = asyncio.run_coroutine_threadsafe(self.client.get_online_users(), self.loop)
        future.add_done_callback(lambda fut: self.root.after(0, self._handle_online_result, fut))

    def _handle_online_result(self, fut: asyncio.Future) -> None:
        self._online_request_active = False
        if not self.connected:
            return
        try:
            users = fut.result() or []
        except Exception as exc:
            self.status_var.set(f"Online query error: {exc}")
            return
        self.online_users = users
        self._render_online_list()
        self._render_friend_list()

    def _render_friend_list(self) -> None:
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
            request_btn = ttk.Button(button_box, text="Send Chat Request", command=lambda a=alias: self.request_chat(a))
            if not friend["verified"]:
                request_btn.state(["disabled"])
            request_btn.pack(side="right", padx=(4, 0))

    def _render_online_list(self) -> None:
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

    def request_chat(self, alias: str) -> None:
        if not self.client:
            return
        future = asyncio.run_coroutine_threadsafe(self.client.send_chat_request_feedback(alias), self.loop)
        future.add_done_callback(lambda fut, name=alias: self.root.after(0, self._handle_chat_feedback, name, fut))

    def _handle_chat_feedback(self, alias: str, fut: asyncio.Future) -> None:
        try:
            success, message = fut.result()
        except Exception as exc:
            messagebox.showerror("Chat request", f"Failed to contact {alias}: {exc}")
            return
        self.status_var.set(message)
        if success:
            messagebox.showinfo("Chat request", message)
        else:
            messagebox.showwarning("Chat request", message)

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
        if focus:
            self.chat_entry.focus_set()

    def _load_chat_history(self, alias: str) -> None:
        if not self.client:
            return
        self._set_chat_text("")
        future = asyncio.run_coroutine_threadsafe(self.client.list_messages(alias, limit=200), self.loop)
        future.add_done_callback(lambda fut, name=alias: self.root.after(0, self._populate_chat_history, name, fut))

    def _populate_chat_history(self, alias: str, fut: asyncio.Future) -> None:
        if alias != self.chat_active_alias:
            return
        try:
            messages = fut.result()
        except Exception as exc:
            self.status_var.set(f"History error: {exc}")
            return
        lines = []
        for entry in messages:
            text = entry.get("text") or ""
            if entry.get("direction") == "out":
                prefix = "You"
            else:
                prefix = alias
            lines.append(f"{prefix}: {text}")
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

    def _append_chat_line(self, alias: str, direction: str, text: str) -> None:
        if alias != self.chat_active_alias:
            self.status_var.set(f"New message from {alias}")
            return
        prefix = "You" if direction == "out" else alias
        line = f"{prefix}: {text}"
        self.chat_text.config(state="normal")
        self.chat_text.insert(tk.END, line + "\n")
        self.chat_text.config(state="disabled")
        self.chat_text.see(tk.END)

    def _set_chat_text(self, text: str) -> None:
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
        if etype == "chat_request":
            alias = event.get("alias")
            remote = event.get("remote")
            if alias:
                self.status_var.set(f"Chat request from {alias}")
            if remote:
                accept = messagebox.askyesno("Chat request", f"{alias} wants to start a chat. Accept?")
                future = asyncio.run_coroutine_threadsafe(
                    self.client.respond_chat_request(remote, accept),
                    self.loop,
                )
                future.add_done_callback(lambda fut: self.root.after(0, self._handle_future_error, fut, "chat response"))
        elif etype == "friend_request":
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
        elif etype == "chat_started":
            alias = event.get("alias")
            if alias:
                self.status_var.set(f"Chat active with {alias}")
                self.open_chat(alias, focus=True)
                self.refresh_friend_list()
        elif etype == "chat_declined":
            alias = event.get("alias")
            if alias:
                self.status_var.set(f"{alias} declined the chat request.")
                self.refresh_friend_list()
        elif etype == "contact_unverified":
            alias = event.get("alias")
            if alias:
                self.status_var.set(f"{alias}'s key changed. Re-verify before chatting.")
            self.refresh_friend_list()
        elif etype == "message":
            alias = event.get("alias")
            text = event.get("text") or ""
            direction = event.get("direction", "in")
            self._append_chat_line(alias or "Unknown", direction, text)

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
