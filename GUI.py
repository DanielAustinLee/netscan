import tkinter


def hello():
    print("Hello")

top = tkinter.Tk()
top.geometry("300x300")
top.resizable(height = False, width = False)
top.title("netscan")

startAddress = tkinter.Entry(width = 20)
endAddress = tkinter.Entry(width = 20)
startPort = tkinter.Entry(width = 20)
endPort = tkinter.Entry(width = 20)

addressList = tkinter.Listbox()
portList = tkinter.Listbox()

scan = tkinter.Button(command=hello, text="Scan", width = 20)

startAddress.place(relx = .05, rely = .1)
endAddress.place(relx = .05, rely = .25)
startPort.place(relx = .55, rely = .1)
endPort.place(relx = .55, rely = .25)
scan.place(relx = .25, rely = .35)

addressList.place(relx = .05, rely = .45)
portList.place(relx = .55, rely = .45)

top.mainloop()