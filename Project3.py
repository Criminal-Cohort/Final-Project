import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
import pyperclip
import base64

valid_credentials = {"user1": "w6XDlMOYw6Vi", "user2": "w6XDlMOYw6Vk"}
emails = {}
user_data = {}

root = tk.Tk()
root.title("Multi-tab GUI")
root.geometry("600x250")

style = ttk.Style()
style.theme_use('clam')

style.configure("TEntry", padding=5, font=("Helvetica", 11), fieldbackground="#F2F2F2", relief="flat")
style.configure("TButton", font=("Helvetica", 12), padding=6, relief="flat", background="#4CAF50", foreground="white")
style.map("TButton", background=[("active", "#45a049")])


def encode(key, clear):
    enc = []

    for i in range(len(clear)):
        key_c =  key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)

        enc.append(enc_c)

    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []

    enc = base64.urlsafe_b64decode(enc).decode()

    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec.append(chr((256 + ord(enc[i]) - ord(key_c)) % 256))

    return "".join(dec)

def toggle_password_visibility(event, button):
    current_show = button.cget("show")
    if current_show == "*":
        button.config(show="")
    else:
        button.config(show="*")

def verify_login():
    username = username_entry.get()
    password = password_entry.get()

    if username in valid_credentials and decode(username+str(len(username)*2), valid_credentials[username]) == password:
        current_user.set(username)
        messagebox.showinfo("Login Success", f"Welcome {username}!")
        login_frame.pack_forget()
        user_data[username] = {'passwords': {}, 'notes': {}}
        create_main_screen()
    else:
        messagebox.showerror("Login Failed", "Invalid username or password.")

def register_user():
    username = reg_username_entry.get()
    password = reg_password_entry.get()
    email = reg_email_entry.get()

    if username and password and email:
        if username in valid_credentials:
            messagebox.showerror("Registration Error", "Username already exists.")
        else:
            valid_credentials[username] = encode(username+str(len(username)*2), password)
            emails[username] = email
            messagebox.showinfo("Registration Successful", "User registered successfully!")
            reg_username_entry.delete(0, tk.END)
            reg_password_entry.delete(0, tk.END)
            reg_email_entry.delete(0, tk.END)
    else:
        messagebox.showerror("Input Error", "All fields are required.")

def create_main_screen():
    global revel

    root.geometry("900x600")
    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

    passwords_tab = tk.Frame(notebook, bg="#F4F7FB")
    notebook.add(passwords_tab, text="Passwords")

    passwords_table = ttk.Treeview(passwords_tab, columns=("Username", "Password"), show="headings")
    passwords_table.heading("Username", text="Username")
    passwords_table.heading("Password", text="Password")
    passwords_table.column("Username", anchor="w", width=200)
    passwords_table.column("Password", anchor="w", width=200)
    passwords_table.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

    passwords_tab.grid_rowconfigure(0, weight=1)
    passwords_tab.grid_columnconfigure(0, weight=1)
    passwords_tab.grid_columnconfigure(1, weight=4)

    tk.Label(passwords_tab, text="Username:", font=("Helvetica", 11), bg="#F4F7FB").grid(row=1, column=0, padx=10, pady=10, sticky="e")
    password_username_entry = ttk.Entry(passwords_tab, style="TEntry")
    password_username_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

    tk.Label(passwords_tab, text="Password:", font=("Helvetica", 11), bg="#F4F7FB").grid(row=2, column=0, padx=10, pady=10, sticky="e")
    password_entry = ttk.Entry(passwords_tab, style="TEntry", show="*")
    password_entry.grid(row=2, column=1, padx=10, pady=10, sticky="ew")

    password_entry.bind("<Double-3>", lambda event: toggle_password_visibility(event, password_entry))

    def load_all():
        print("proof2")
        for i in user_data[current_user.get()]['passwords']:
            print("proof")
            passwords_table.insert("", "end", values=(i, '*' * int((len(user_data[current_user.get()]['passwords'][i]) * 2.6) // 1)))

    load_all()

    def save_password():
        username = password_username_entry.get()
        password = password_entry.get()
        if username and password:
            user_data[current_user.get()]['passwords'][username] = encode(username+str(len(username)*2), password)
            print(user_data[current_user.get()]['passwords'][username])
            passwords_table.insert("", "end", values=(username, '*' * int((len(password) * 2.6) // 1)))
            password_username_entry.delete(0, tk.END)
            password_entry.delete(0, tk.END)
        else:
            messagebox.showerror("Input Error", "Please provide both username and password.")

    save_password_button = ttk.Button(passwords_tab, text="Save Password", command=save_password)
    save_password_button.grid(row=3, column=0, columnspan=2, pady=10)

    def on_password_double_click(event):
        item = passwords_table.selection()[0]
        username = passwords_table.item(item, "values")[0]

        print(passwords_table.item(item)['values'][1])

        st = ""
        for i in range(len(passwords_table.item(item)['values'][1])):
            if passwords_table.item(item)['values'][1][i] == "*":
                st += str(passwords_table.item(item)['values'][1][i])

        if passwords_table.item(item)['values'][1] == st:
            password_prompt = simpledialog.askstring("Password Prompt",
                                                     f"Enter the password for {current_user.get()} to reveal:")

            if password_prompt:
                if decode(current_user.get()+str(len(current_user.get())*2), valid_credentials.get(current_user.get())) == password_prompt:
                    passwords_table.item(item, values=(username, decode(username+str(len(username)*2), user_data[current_user.get()]['passwords'][username])))
                else:
                    messagebox.showerror("Error", "Incorrect password.")

        else:
            pyperclip.copy(passwords_table.item(item, "values")[0])
            pyperclip.copy(passwords_table.item(item, "values")[1])

    def on_password_double_rclick(event):
        item = passwords_table.selection()[0]
        username = passwords_table.item(item, "values")[0]

        passwords_table.item(item, values=(username,'*' * int((len(user_data[current_user.get()]['passwords'][username]) * 2.6) // 1)))

    passwords_table.bind("<Double-1>", on_password_double_click)
    passwords_table.bind("<Double-3>", on_password_double_rclick)

    notes_tab = tk.Frame(notebook, bg="#F4F7FB")
    notebook.add(notes_tab, text="Notes")

    notes_tab.grid_rowconfigure(0, weight=1)
    notes_tab.grid_columnconfigure(0, weight=1)
    notes_tab.grid_columnconfigure(1, weight=4)

    notes_table = ttk.Treeview(notes_tab, columns=("Title", "Note"), show="headings")
    notes_table.heading("Title", text="Note Title")
    notes_table.heading("Note", text="Note")
    notes_table.column("Title", anchor="w", width=200)
    notes_table.column("Note", anchor="w", width=350)
    notes_table.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

    tk.Label(notes_tab, text="Note Title:", font=("Helvetica", 11), bg="#F4F7FB").grid(row=1, column=0, padx=10, pady=10, sticky="e")
    note_title_entry = ttk.Entry(notes_tab, style="TEntry")
    note_title_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

    tk.Label(notes_tab, text="Note:", font=("Helvetica", 11), bg="#F4F7FB").grid(row=2, column=0, padx=10, pady=10, sticky="e")
    note_entry = ttk.Entry(notes_tab, style="TEntry")
    note_entry.grid(row=2, column=1, padx=10, pady=10, sticky="ew")

    def save_note():
        title = note_title_entry.get()
        note = note_entry.get()
        if title and note:
            user_data[current_user.get()]['notes'][title] = note
            notes_table.insert("", "end", values=(title, note))
            note_title_entry.delete(0, tk.END)
            note_entry.delete(0, tk.END)
        else:
            messagebox.showerror("Input Error", "Please provide both title and note.")

    save_note_button = ttk.Button(notes_tab, text="Save Note", command=save_note)
    save_note_button.grid(row=3, column=0, columnspan=2, pady=10)

login_frame = tk.Frame(root, bg="#F4F7FB")
login_frame.pack(fill=tk.BOTH, expand=True)

tk.Label(login_frame, text="Login", font=("Helvetica", 14, "bold"), bg="#F4F7FB").grid(row=0, column=0, columnspan=2, padx=20, pady=10)

tk.Label(login_frame, text="Username:", font=("Helvetica", 12), bg="#F4F7FB").grid(row=1, column=0, padx=10, pady=5, sticky="e")
username_entry = ttk.Entry(login_frame, style="TEntry")
username_entry.grid(row=1, column=1, padx=10, pady=5)

tk.Label(login_frame, text="Password:", font=("Helvetica", 12), bg="#F4F7FB").grid(row=2, column=0, padx=10, pady=5, sticky="e")
password_entry = ttk.Entry(login_frame, style="TEntry", show="*")
password_entry.grid(row=2, column=1, padx=10, pady=5)

password_entry.bind("<Double-3>", lambda event: toggle_password_visibility(event, password_entry))

login_button = ttk.Button(login_frame, text="Login", command=verify_login)
login_button.grid(row=3, column=0, columnspan=2, pady=10)

tk.Label(login_frame, text="Register", font=("Helvetica", 14, "bold"), bg="#F4F7FB").grid(row=0, column=3, columnspan=2, padx=20, pady=10)

tk.Label(login_frame, text="Username:", font=("Helvetica", 12), bg="#F4F7FB").grid(row=1, column=3, padx=10, pady=5, sticky="e")
reg_username_entry = ttk.Entry(login_frame, style="TEntry")
reg_username_entry.grid(row=1, column=4, padx=10, pady=5)

tk.Label(login_frame, text="Password:", font=("Helvetica", 12), bg="#F4F7FB").grid(row=2, column=3, padx=10, pady=5, sticky="e")
reg_password_entry = ttk.Entry(login_frame, style="TEntry", show="*")
reg_password_entry.grid(row=2, column=4, padx=10, pady=5)

reg_password_entry.bind("<Double-3>", lambda event: toggle_password_visibility(event, reg_password_entry))

tk.Label(login_frame, text="Email:", font=("Helvetica", 12), bg="#F4F7FB").grid(row=3, column=3, padx=10, pady=5, sticky="e")
reg_email_entry = ttk.Entry(login_frame, style="TEntry")
reg_email_entry.grid(row=3, column=4, padx=10, pady=5)

register_button = ttk.Button(login_frame, text="Register", command=register_user)
register_button.grid(row=4, column=3, columnspan=2, pady=10)

login_frame.grid_columnconfigure(2, minsize=50)

current_user = tk.StringVar()

root.mainloop()
