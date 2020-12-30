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

# Get image address
root = tk.Tk()
root.withdraw()
s=ttk.Style()
s.theme_use('clam')

file_path = filedialog.askopenfilename(initialdir = "/home/jonathasg",title = "Abrir imagem a ser transformada em texto",filetypes = (("arquivo jpg","*.jpg"),("arquivo png","*.png"),("todos os arquivos","*.*")))
caminho = file_path

# Convert Image to Base64
def im_2_b64(image):
    buff = BytesIO()
    image.save(buff, format="JPEG")
    img_str = base64.b64encode(buff.getvalue())
    return img_str


img = Image.open(caminho)

img_b64 = im_2_b64(img)

master = Tk()
master.title("Digite a senha do arquivo")
master.geometry("190x80+890+400")
Label(master, text="Senha").grid(row=0)
e1 = Entry(master)
e1.grid(row=0, column=1)

Button(master, text='Tudo certo!', command=master.quit).grid(row=3, column=1, sticky=W, pady=4)

mainloop( )

senha = e1.get()

file_path2 = filedialog.asksaveasfilename(initialdir = "/home/jonathasg",title = "Salvar imagem como texto",filetypes = (("arquivo txt","*.txt"),("arquivo jntsg","*.jntsg")))
caminhof = file_path2

with open(caminhof, "a+") as myfile:
    myfile.write(str(img_b64))

# open uncompressed txt file and delete it
file = open(caminhof,'r')
text = file.read()
file.close()
os.remove(caminhof)

# encoding the text
code =  base64.b64encode(zlib.compress(text.encode('utf-8'),9))
code = code.decode('utf-8')


password_provided = senha # This is input in the form of a string
password = password_provided.encode() # Convert to type bytes
salt = b'salt_'
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(password))


message = code.encode()

f = Fernet(key)
encrypted = f.encrypt(message)

f=open(caminhof,'w')
f.write(str(encrypted))
f.close()