import tkinter
import tkinter.filedialog
import customtkinter


def main():
    customtkinter.set_appearance_mode("System")

    root = customtkinter.CTk()
    root.geometry("800x600")

    button_frame = customtkinter.CTkFrame(master=root)
    button_frame.pack(expand = True)

    button = customtkinter.CTkButton(master=button_frame,text="FILE UNLOCK",width=200,height=80, command=lambda:open_file_lock(root,button_frame))
    button.pack( side = "left", padx=10)

    button = customtkinter.CTkButton(master=button_frame,text="FILE LOCK",width=200,height=80, command=lambda:open_file_unlock(root,button_frame))
    button.pack( side = "left", padx=10)


    root.mainloop()


def open_file_lock(root,button_frame):
    print("Lock")
    button_frame.pack_forget()
    root.filename = tkinter.filedialog.askopenfilename(title="Select a file to lock")
    handle_file_lock_up(root,root.filename)

def open_file_unlock(root,button_frame):
    print("Unlock")
    button_frame.pack_forget()
    root.filename = tkinter.filedialog.askopenfilename(title="Select a file to lock")
    handle_file_unlock(root,root.filename)

def handle_file_lock_up(root,file):
    print("will do!")
    print(file)   

def handle_file_unlock(root,file):
    print("will do unlcok!") 
    print(file)

if __name__ == "__main__":
    main()