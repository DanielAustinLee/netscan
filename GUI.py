import tkinter


top = tkinter.Tk()
top.geometry("500x500")
top.resizable(height = False, width = False)

startAddress = tkinter.Entry()
endAddress = tkinter.Entry()
startPort = tkinter.Entry()
endPort = tkinter.Entry()

scan = tkinter.Button(width = 25)

startAddress.place(x = 100, y = 60)
endAddress.place(x = 100, y = 130)
startPort.place(x = 300, y = 60)
endPort.place(x = 300, y = 130)
scan.place(x = 175, y = 200)

top.mainloop()