import json
import tkinter as tk
from tkinter import ttk, messagebox
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

BASE_URL = "http://127.0.0.1:8000"
TOKEN = ""


def api_call(method: str, path: str, body: dict = None, token: str = ""):
    url = BASE_URL + path
    data_bytes = None

    headers = {"Content-Type": "application/json; charset=utf-8"}
    if token:
        headers["Authorization"] = f"Token {token}"

    if body is not None:
        data_bytes = json.dumps(body, ensure_ascii=False).encode("utf-8")

    req = Request(url, data=data_bytes, headers=headers, method=method)

    try:
        with urlopen(req, timeout=5) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw)
    except HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"error": raw}
    except URLError as e:
        return 0, {"error": f"Server not reachable: {e}"}
    except Exception as e:
        return 0, {"error": str(e)}


def set_output(text_widget: tk.Text, obj):
    text_widget.delete("1.0", tk.END)
    text_widget.insert(tk.END, json.dumps(obj, ensure_ascii=False, indent=2))


def on_register():
    login = reg_login.get().strip()
    password = reg_pass.get()
    password2 = reg_pass2.get()
    first_name = reg_first.get().strip()
    last_name = reg_last.get().strip()

    status, data = api_call("POST", "/register", {
        "login": login,
        "password": password,
        "password2": password2,
        "first_name": first_name,
        "last_name": last_name,
    })

    set_output(out, {"status": status, "response": data})
    if status == 200:
        messagebox.showinfo("Register", "Registered successfully.")


def on_login():
    global TOKEN
    login = login_login.get().strip()
    password = login_pass.get()

    status, data = api_call("POST", "/login", {"login": login, "password": password})
    set_output(out, {"status": status, "response": data})

    if status == 200 and "token" in data:
        TOKEN = data["token"]
        token_label.config(text=f"Token: {TOKEN}")
        messagebox.showinfo("Login", "Logged in.")


def on_logout():
    global TOKEN
    if not TOKEN:
        messagebox.showwarning("Logout", "You are not logged in.")
        return

    status, data = api_call("POST", "/logout", body={}, token=TOKEN)
    set_output(out, {"status": status, "response": data})

    if status == 200:
        TOKEN = ""
        token_label.config(text="Token: (empty)")
        messagebox.showinfo("Logout", "Logged out.")


def on_me():
    if not TOKEN:
        messagebox.showwarning("Me", "Login first.")
        return

    status, data = api_call("GET", "/me", token=TOKEN)
    set_output(out, {"status": status, "response": data})


def on_admin_users():
    if not TOKEN:
        messagebox.showwarning("Admin", "Login first (admin).")
        return

    status, data = api_call("GET", "/admin/users", token=TOKEN)
    set_output(out, {"status": status, "response": data})


# UI

root = tk.Tk()
root.title("Mini Auth Client (Registration/Login)")
root.geometry("820x540")

main = ttk.Frame(root, padding=12)
main.pack(fill="both", expand=True)

token_label = ttk.Label(main, text="Token: (empty)")
token_label.pack(anchor="w")

notebook = ttk.Notebook(main)
notebook.pack(fill="x")

# Register
tab_reg = ttk.Frame(notebook, padding=10)
notebook.add(tab_reg, text="Register")

reg_login = tk.StringVar()
reg_pass = tk.StringVar()
reg_pass2 = tk.StringVar()
reg_first = tk.StringVar()
reg_last = tk.StringVar()

def row(parent, r, label, var, show=None):
    ttk.Label(parent, text=label).grid(row=r, column=0, sticky="w", padx=4, pady=3)
    ttk.Entry(parent, textvariable=var, width=40, show=show).grid(row=r, column=1, sticky="w", padx=4, pady=3)

row(tab_reg, 0, "Login", reg_login)
row(tab_reg, 1, "Password", reg_pass, show="*")
row(tab_reg, 2, "Repeat password", reg_pass2, show="*")
row(tab_reg, 3, "First name", reg_first)
row(tab_reg, 4, "Last name", reg_last)

ttk.Button(tab_reg, text="Register", command=on_register).grid(row=5, column=0, sticky="w", pady=8)

# Login
tab_login = ttk.Frame(notebook, padding=10)
notebook.add(tab_login, text="Login / Profile")

login_login = tk.StringVar()
login_pass = tk.StringVar()

row(tab_login, 0, "Login", login_login)
row(tab_login, 1, "Password", login_pass, show="*")

btns = ttk.Frame(tab_login)
btns.grid(row=2, column=0, columnspan=2, sticky="w", pady=8)

ttk.Button(btns, text="Login", command=on_login).pack(side="left", padx=5)
ttk.Button(btns, text="Logout", command=on_logout).pack(side="left", padx=5)
ttk.Button(btns, text="GET /me", command=on_me).pack(side="left", padx=5)
ttk.Button(btns, text="Admin: users", command=on_admin_users).pack(side="left", padx=5)

# Output
ttk.Label(main, text="Output:").pack(anchor="w", pady=(12, 4))
out = tk.Text(main, height=16)
out.pack(fill="both", expand=True)

root.mainloop()
