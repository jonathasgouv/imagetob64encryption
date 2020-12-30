from tkinter import *
from PIL import Image
from io import BytesIO
import base64
import math
from colorsys import hsv_to_rgb
import zlib, base64
import os
import tkinter as tk
from tkinter import filedialog
from tkinter import ttk as ttk
import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import sys

def printSomething():
    # if you want the button to disappear:
    # button.destroy() or button.pack_forget()
    label = Label(root, text= "Senha errada! Reinicie e tente de novo")
    #this creates a new label to the GUI
    label.pack()


# Pede o endereço da imagem em forma de texto
root = tk.Tk()
root.withdraw()
s=ttk.Style()
s.theme_use('clam')

file_path = filedialog.askopenfilename(initialdir = "/home/jonathasg",title = "Abrir texto a ser transformado em imagem",filetypes = (("arquivo txt","*.txt"),("arquivo jntsg","*.jntsg"),("todos os arquivos","*.*")))
caminho = file_path

while True:
    try:
        master = Tk()
        master.title("Senha")
        master.geometry("190x80+890+400")
        Label(master, text="Senha").grid(row=0)
        e1 = Entry(master)
        e1.grid(row=0, column=1)

        Button(master, text='Tudo certo!', command=master.quit).grid(row=3, column=1, sticky=W, pady=4)

        mainloop( )

        senha = e1.get()

        password_provided = senha # This is input in the form of a string
        password = password_provided.encode() # Convert to type bytes
        salt = b'salt_' # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
)
        key = base64.urlsafe_b64encode(kdf.derive(password))

        f = open(caminho, 'r')
        encrypted2 = f.readline().split("'")
        f.close()

        encrypted3 = encrypted2[1]
        encrypted3 = encrypted3.encode()

        f = Fernet(key)
        decrypted = f.decrypt(encrypted3)

        break;
    except:
        root = Tk()
        root.geometry("290x80+890+400")
        root.title("Erro")

        button = Button(root, text="Senha errada! Clique aqui para fechar", command=sys.exit)
        button.pack()

        root.mainloop()

code = decrypted

# decode the encoded text
decoded_txt = zlib.decompress(base64.b64decode(code))
decoded_txt = str(decoded_txt)
f=open('decompressed.txt','w')
f.write(decoded_txt)
f.close()

f = open("decompressed.txt", 'r')
newjpgtxt = f.readline().split("'")
newjpgtxt1 = newjpgtxt[1]

f=open('finantesdeimg.txt','w')
f.write(str(newjpgtxt1))
f.close()

# Convert Base64 to Image
def b64_2_img(data):
    buff = BytesIO(base64.b64decode(data))
    return Image.open(buff)

f = open('finantesdeimg.txt', 'r')
newjpgtxt = f.readline().split("'")
newjpgtxt1 = newjpgtxt[0]


new_img = b64_2_img(newjpgtxt1)
file_path2 = filedialog.asksaveasfilename(initialdir = "/home/jonathasg",title = "Salvar imagem como texto",filetypes = (("arquivo jpg","*.jpg"),("arquivo png","*.png")))
caminhof = file_path2

new_img.save(caminhof)
new_img.show()

os.remove("decompressed.txt")
os.remove("finantesdeimg.txt")