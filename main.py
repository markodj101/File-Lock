import tkinter
import tkinter.filedialog
import customtkinter
from cryptography.fernet import Fernet
import base64

def main():
    customtkinter.set_appearance_mode("System")

    root = customtkinter.CTk()
    root.geometry("600x400")

    button_frame = customtkinter.CTkFrame(master=root)
    button_frame.pack(expand = True)

    button = customtkinter.CTkButton(master=button_frame,text="FILE LOCK",width=200,height=80, command=lambda:open_file_lock(root,button_frame))
    button.pack( side = "left", padx=10)

    button = customtkinter.CTkButton(master=button_frame,text="FILE UNLOCK",width=200,height=80, command=lambda:open_file_unlock(root,button_frame))
    button.pack( side = "left", padx=10)

   
    root.mainloop()


def open_file_lock(root,button_frame):
    print("Lock")
    root.filename = tkinter.filedialog.askopenfilename(title="Select a file to lock")
    if len(root.filename) != 0:
       button_frame.pack_forget()
       handle_file_lock_up(root,root.filename)

def open_file_unlock(root,button_frame):
    print("Unlock")
    root.filename = tkinter.filedialog.askopenfilename(title="Select a file to lock")
    if len(root.filename) != 0:
       button_frame.pack_forget()
       handle_file_unlock(root,root.filename)

def handle_file_lock_up(root,file):
    print("will do!")
    print(file)   
    key = Fernet.generate_key()
    url_safe_key = base64.urlsafe_b64encode(key)
    
    print(f"Fernet Key: {url_safe_key.decode()}")
    key_output= customtkinter.CTkLabel(master=root, text=f"Your key is : {url_safe_key.decode()}")
    key_output.pack()
    fernet = Fernet(key)

    with open(file,'rb') as fl:
        original = fl.read()
    
    encrypted = fernet.encrypt(original)

    with open(file, "wb") as encrypt:
        encrypt.write(encrypted)



def handle_file_unlock(root,file):
    print("will do unlcok!") 
    print(file)
    key = "bHN1N1VYa2FmZVp2Snd5MXp6QzVvNlRHR2hCUHhieUdieVdhYzJ2UzRxbz0="
    key = base64.urlsafe_b64decode(key)
    fernet = Fernet(key)

    with open(file, 'rb') as fl:
        encrypted = fl.read()
    
    decrypted = fernet.decrypt(encrypted)

    with open(file, 'wb') as dec:
        dec.write(decrypted)

if __name__ == "__main__":
    main()