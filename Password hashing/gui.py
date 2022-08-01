from cgitb import text
from tkinter import *
import bcrypt


def validate(password):
    # thisismypassword
    hash = b'$2b$12$aup63kfXSp4N7stXTqPLhOfvQBVszQcYTizjapiUy4NUuTogtCN.G'

    password = bytes(password, encoding='utf-8')
    if bcrypt.checkpw(password, hash):
        print("Login successfull")

    else:
        print("invalid password")


root = Tk()

root.geometry('300x300')
# getting input
enter_password = Entry(root, text='enter password')
enter_password.pack()

button = Button(root, text='validate password',
                command=lambda: validate(enter_password.get()))
button.pack()

root.mainloop()
