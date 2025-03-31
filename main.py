import tkinter
import tkinter.filedialog
import customtkinter
from cryptography.fernet import Fernet
import base64


WRAP_PIXEL_WIDTH = 400


def main():
    customtkinter.set_appearance_mode("System")

    root = customtkinter.CTk()
    root.geometry("600x400")
    root.title("File Locker")
    button_frame = customtkinter.CTkFrame(master=root)
    button_frame.pack(expand = True)

    lock_frame = customtkinter.CTkFrame(master=root)

    unlock_frame = customtkinter.CTkFrame(master=root)

    button = customtkinter.CTkButton(master=button_frame,text="FILE LOCK",width=200,height=80, command=lambda:open_file_lock(root,button_frame,lock_frame))
    button.pack( side = "left", padx=10)

    button = customtkinter.CTkButton(master=button_frame,text="FILE UNLOCK",width=200,height=80, command=lambda:open_file_unlock(root,button_frame,unlock_frame))
    button.pack( side = "left", padx=10)

   
    root.mainloop()


def open_file_lock(root,button_frame,lock_frame):
    print("Lock")
    root.filename = tkinter.filedialog.askopenfilename(title="Select a file to lock")
    if len(root.filename) != 0:
       button_frame.pack_forget()
       lock_frame.pack(expand = True)
       handle_file_lock_up(root,root.filename,button_frame,lock_frame)

def open_file_unlock(root,button_frame,unlock_frame):
    print("Unlock")
    root.filename = tkinter.filedialog.askopenfilename(title="Select a file to lock")
    if len(root.filename) != 0:
       button_frame.pack_forget()
       unlock_frame.pack(expand = True)
       handle_file_unlock(root,root.filename,button_frame,unlock_frame)

def handle_file_lock_up(root,file,button_frame,lock_frame):
    
    print("will do!")
    print(file)   
    key = Fernet.generate_key()
    url_safe_key = base64.urlsafe_b64encode(key)
    
    print(f"Fernet Key: {url_safe_key.decode()}")
    key_output= customtkinter.CTkLabel(master=lock_frame, text=f"Your key is : \n{url_safe_key.decode()}",font=customtkinter.CTkFont(size=15,weight="bold"),wraplength=WRAP_PIXEL_WIDTH,  
    justify="center")
    copy_button = customtkinter.CTkButton(master=lock_frame, text="Copy to Clipboard", command=lambda:copy_to_clipboard(root, url_safe_key.decode(), lock_frame))
    key_output.pack(pady=10,padx=10)
    copy_button.pack(pady=10,padx=10)

    back_button = customtkinter.CTkButton(master=root, text="Go Back!", command=lambda:home_page(root,button_frame,lock_frame,back_button))
    back_button.pack(pady=10,padx=10)

    fernet = Fernet(key)

    with open(file,'rb') as fl:
        original = fl.read()
    
    encrypted = fernet.encrypt(original)

    with open(file, "wb") as encrypt:
        encrypt.write(encrypted)



def handle_file_unlock(root,file,button_frame,unlock_frame):
    
    back_button = customtkinter.CTkButton(master=root, text="Go Back!", command=lambda:home_page(root,button_frame,unlock_frame,back_button))
    back_button.pack(pady=10,padx=10)

    input = customtkinter.CTkEntry(master=unlock_frame,placeholder_text="Type in the key:")
    input.pack(pady=10,padx=10)

    
    key = "Tnl6dkVUeWVqYU56SWdOR0NIcTNITlk1X0xBV0hhVDBJaFNGcXdSRHFCMD0="
    key = base64.urlsafe_b64decode(key)
    fernet = Fernet(key)


    with open(file, 'rb') as fl:
        encrypted = fl.read()
    
    decrypted = fernet.decrypt(encrypted)

    with open(file, 'wb') as dec:
        dec.write(decrypted)

def copy_to_clipboard(root, key, lock_frame):
    
    print("copy_to_clipboard")
    root.clipboard_clear()
    root.clipboard_append(key)
    label = customtkinter.CTkLabel(master=lock_frame, text="Key copied to clipboard",font=customtkinter.CTkFont(),wraplength= WRAP_PIXEL_WIDTH,  
    justify="center")
    label.pack(padx=10,pady=10)

def home_page(root,button_frame,label_frame,back_button):
    clear_frame_widget(label_frame)
    label_frame.forget()
    button_frame.pack(expand= True)
    back_button.forget()

def clear_frame_widget(label_frame):
    for widget in label_frame.winfo_children():
        widget.destroy()

if __name__ == "__main__":
    main()