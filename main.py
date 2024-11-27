from tkinter import *
from tkinter import messagebox
import base64

def encode(key, clear):
    enc = []
    for i in range (len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def save_and_encrypt_notes():
    title = title_entry.get()
    message = text_note.get("1.0", END)
    master_secret = key_entry.get()

    if len(title) == 0 or len(message) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        message_encrypted = encode(master_secret, message)

        try:
            with open("mysecretnotes.txt", "a") as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        except FileNotFoundError:
            with open("mysecretnotesçtxt", "w") as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        finally:
            title_entry.delete(0, END)
            key_entry.delete(0, END)
            text_note.delete("1.0", END)


def decrypt_notes():
    message_encrypted = text_note.get("1.0", END)
    master_secret = key_entry.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        try:
            decrypted_message = decode(master_secret,message_encrypted)
            text_note.delete("1.0", END)
            text_note.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Error!", message="Please make sure of encrypted info.")


tk = Tk()
tk.title("Note Encryptor")
tk.config(padx= 10, pady= 10)

canvas = Canvas(width=200, height=200)
img = PhotoImage(file="b.png")
canvas.create_image(100, 100, image = img)
canvas.pack()

title_label = Label(text="Enter your title:", pady=5, font=("Verdena",10,"normal"))
title_label.pack()
title_entry = Entry(width=35)
title_entry.pack()

text_label = Label(text="Enter your secret note:", pady=5, font=("Verdena",10,"normal"))
text_label.pack()
text_note = Text(width=50, height=25, padx=10)
text_note.pack()

key_label = Label(text="Enter your master key:", pady=5, font=("Verdena",10,"normal"))
key_label.pack()
key_entry = Entry(width=35)
key_entry.pack()

save_button = Button(text="Save & Encrypt", pady=5, command=save_and_encrypt_notes)
save_button.pack()

decrypt_button = Button(text="Decrypt", pady=5, command=decrypt_notes)
decrypt_button.pack()

tk.mainloop()