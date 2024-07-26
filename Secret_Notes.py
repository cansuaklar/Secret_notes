import os.path
import tkinter
from cryptography.fernet import Fernet
from tkinter import messagebox

screen = tkinter.Tk()
screen.title("Secret Notes")
screen.minsize(width=400, height=600)


#şifreleme fonksiyonu
def encrypter(x, key):
    secret = entry2.get(1.0, "end-1c")
    x = secret.encode()
    f = Fernet(key)
    encrypted_x = f.encrypt(x)
    return encrypted_x


#şifre kırma fonk
def decrypter(encrypted_x, key):
    f = Fernet(key)
    decrypted_x = f.decrypt(encrypted_x).decode()
    return decrypted_x


#Anahtar üretici
def generate_key():
    return Fernet.generate_key()


def save_and_encrypt(encrypted_secret=None, password=None):
    title = entry1.get()
    my_secret = entry2.get(1.0, "end-1c")
    password = master_key.get()

    key = generate_key()  #veriler için anahtar üret
    encrypted_secret = encrypter(my_secret, key)

    if not password:
        messagebox.showwarning('Please enter master key')  #parola girilmezse hata verir.
        return
    else:
        messagebox.showinfo('Success')

    with open("Secret_not.txt", "ab") as file:
        file.write(f'Title: {title}\n'.encode())  # Başlığı dosyaya ekleme
        file.write(encrypted_secret + b'\n')  # Şifreli veriyi dosyaya ekleme
        file.write(key + b'\n')  # Anahtar (gizli notun çözülmesi için)

    entry1.delete(0, 'end')  # Başlık alanını temizle
    entry2.delete(1.0, 'end')  # Gizli not alanını temizle
    master_key.delete(0, 'end')


# Şifre çözme ve gösterme fonksiyonu

def decrypt_text(encrypted_secret=None):
    title = entry1.get()
    password = master_key.get().encode()

    if not password:
        messagebox.showwarning('Please enter master key')
        return

    elif os.path.exists("Secret_not.txt"):
        with open('Secret_not.txt', 'rb') as file:
            lines = file.readlines()

        for i in range(0, len(lines), 3):
            if f'Title: {title}\n'.encode() == lines[i]:
                encrypted_secret = lines[i + 1].strip()
                key = lines[i + 2].strip()

                try:
                    decrypted_secret = decrypter(encrypted_secret, key)
                    messagebox.showinfo('Deşifrelenmiş not', decrypted_secret, )

                except Exception as e:
                    messagebox.showerror('Deşifre Yapılamadı')

    else:
        messagebox.showwarning("neden olmuyorsun yeter")


sign = tkinter.PhotoImage(file=r"C:\Users\cansu\OneDrive\Masaüstü\secret.png", width=350, height=170)

label_image = tkinter.Label(screen, image=sign)
label_image.place(x=70, y=10)

label1 = tkinter.Label(screen, text="Enter Your Title")
label1.place(x=160, y=200)

entry1 = tkinter.Entry(width=35)
entry1.place(x=100, y=220)

label2 = tkinter.Label(screen, text="Enter Your Secret")
label2.place(x=155, y=240)

entry2 = tkinter.Text(screen, width=30, height=10)
entry2.place(x=85, y=260)

label3 = tkinter.Label(screen, text="Enter Your MasterKey")
label3.place(x=145, y=440)

master_key = tkinter.Entry(width=35)
master_key.place(x=100, y=460)

button1 = tkinter.Button(screen, text="Save & Encrypt", command=save_and_encrypt)
button1.place(x=160, y=500)

button2 = tkinter.Button(screen, text=" Decrypt ", command=decrypt_text)
button2.place(x=175, y=540)

screen.mainloop()


