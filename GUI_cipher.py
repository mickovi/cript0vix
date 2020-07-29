#!/usr/bin/env python
# coding: utf-8

# In[1]:


import tkinter as tk
from tkinter import ttk
from tkinter import font as tkFont
from tkinter import scrolledtext
from tkinter import Menu

from algCipher import *


# In[2]:


class setParams:
    def __init__(self):
        self.input1 = None
        self.input2 = None
        self.input3 = None
        self.type_cipher = 0
        self.input_text = None
        self.output_text = None
        
    def get_entry1(self):
        entry1['state']='normal'
        self.input1 = entry1.get()
        entry1['state']='disabled'
        
    def get_entry2(self):
        entry2['state']='normal'
        self.input2 = entry2.get()
        entry2['state']='disabled'
    
    def get_entry3(self):
        entry3['state']='normal'
        self.input3 = entry3.get()
        entry3['state']='disabled'
        
    def clear_entry1(self):
        entry1['state']='normal'
        entry1.delete('0', 'end')
        self.input1 = entry1.insert('0', ' ')
        
    def clear_entry2(self):
        entry2['state']='normal'
        entry2.delete('0', 'end')
        self.input2 = entry2.insert('0', ' ')
        
    def clear_entry3(self):
        entry3['state']='normal'
        entry3.delete('0', 'end')
        self.input3 = entry3.insert('0', ' ')
        
    def get_value_encrypt(self):
        self.type_cipher = encrypt_value.get()
    
    def get_text_input(self):
        self.input_text = scr_input.get('1.0', 'end-1c')
        self.set_algorithm()
    
    def clear_text_input(self):
        scr_input.delete('1.0', 'end')
        scr_output['state']='normal'
        scr_output.delete('1.0', 'end')
        scr_output['state']='disabled'
        
    def split_text(self, text):
        if len(text) % 8 != 0:
            res = len(text) % 8
            text = text + ' ' * (8 - res)
        return [text[i:i+8] for i in range(0,len(text), 8)]
        
    def set_algorithm(self):
        alg = algCipher(self.input_text)
        scr_output['state']='normal'
        if options_alg.get() == 'César':
            self.output = alg.caesar(self.input1, self.input2, self.type_cipher)
        if options_alg.get() == 'Vigenère':
            self.output = alg.vigenere(self.input1, self.input2, self.type_cipher)
        if options_alg.get() == 'Escítala':
            self.output = alg.scytale(self.input1, self.input2, self.type_cipher)
        if options_alg.get() == 'XOR':
            self.output = alg.xor(self.input1, self.type_cipher)    
        if options_alg.get() == 'RC4':
            key_stream, msg_output = alg.rc4(self.input1, self.type_cipher)
            # Desencriptar
            if self.type_cipher == 0:
                msg = 'Mensaje desencriptado:\n'
            # Encriptar
            if self.type_cipher == 1:
                msg = 'Mensaje encriptado:\n'
            self.output = msg + msg_output + '\nKey Stream:\n' + key_stream
                        
        if options_alg.get() == 'DES':
            if self.type_cipher == 0:
                self.output = alg.des(self.input1, self.type_cipher)
            if self.type_cipher == 1:
                text_8 = split_text(text)
                text_encrypt = ''
                for i in text_8:
                    alg = algCipher(i)
                    r = alg.des(self.input1, self.type_cipher)
                    text_encrypt += r
                self.output = text_encrypt
                #self.output = alg.des(self.input1, self.type_cipher)
        
        if options_alg.get() == 'Diffie-Hellman':
            if self.type_cipher == 0:
                self.output = "Solo se permite cifrar. Cambie la opción a 'Encriptar'"
            if self.type_cipher == 1:
                K_pub = alg.generate_public_key(self.input1, self.input2, self.input3)
                K = alg.get_K(self.input_text, self.input1, self.input3)
                self.output = 'Clave pública generada:\n' + K_pub + '\nClave para cifrado (K):\n' + K
                #self.output = '\nClave para cifrado (K):\n' + K
            
        if options_alg.get() == 'ElGamal':
            if self.type_cipher == 0:
                N1, N2 = self.input_text.split(',')
                N = alg.elgamal_decrypt(self.input1, self.input3, N1, N2)
                self.output = 'Mensaje descifrado:\n' + str(N)
            if self.type_cipher == 1:
                msg_number, public_key = self.input_text.split(',')
                N1, N2 = alg.elgamal_encrypt(self.input1, self.input2, self.input3, public_key, msg_number)
                self.output = 'Números generados:\nN1:\n' + str(N1) + '\nN2:\n' + str(N2)
        
        if options_alg.get() == 'RSA':
            if self.type_cipher == 0:
                msg_number = alg.rsa_decrypt(self.input1, self.input2, self.input3)
                self.output = 'Número descifrado:\n' + str(msg_number)
            if self.type_cipher == 1:
                C = alg.rsa_encrypt(self.input1, self.input2, self.input3)
                self.output = 'Criptograma:\n' + str(C)
                
        scr_output.insert(1.0, self.output)
        scr_output['state']='disabled'
            
    def copy_text_output(self):
        scr_output.clipboard_clear()
        text_copied = scr_output.get('1.0', 'end')
        scr_output.clipboard_append(text_copied)


# In[3]:


def clean_widgets(*widgets):
    
    for widget in widgets:
        widget.after(1, widget.grid_forget())
    #if options_alg.get() == 'Diffie-Hellman':
    #    decrypt_button.after(1, decrypt_button.grid_forget())
    #    encrypt_button.after(1, encrypt_button.grid_forget())


# In[4]:


def set_option(event):
    global option
    global entry1, entry2, entry3
    global label1, label2, label3
    global OK_button1, OK_button2, OK_button3
    global restart_button1, restart_button2, restart_button3
    
    if options_alg.get() != option and option != None:
        if option == 'César' or option == 'Vigenère' or option == 'Escítala':
            clean_widgets(label1, label2, entry1, entry2, 
                          OK_button1, OK_button2, restart_button1, restart_button2)
        if option == 'Diffie-Hellman':
            clean_widgets(label1, label2, label3, entry1, entry2, entry3,
                          OK_button1, OK_button2, OK_button3, restart_button1, restart_button2, restart_button3)
        else:
            clean_widgets(label1, entry1, OK_button1, restart_button1)
    
    if options_alg.get() == 'César' or options_alg.get() == 'Vigenère':
        option = options_alg.get()
        text_label1.set('Alfabeto:')
        entry1 = tk.Entry(panelFrame, width=50, textvariable=tk.StringVar())
        if options_alg.get() == 'César':
            text_label2.set('Rotación:')
            entry2 = tk.Entry(panelFrame, width=5, textvariable=tk.IntVar())
            OK_button2.grid(row=2, column=1, padx=45, sticky='W')
            restart_button2.grid(row=2, column=1, padx=75, sticky='W')
        else:
            text_label2.set('Clave:')
            entry2 = tk.Entry(panelFrame, width=15, textvariable=tk.StringVar())
            OK_button2.grid(row=2, column=1, padx=115, sticky='W')
            restart_button2.grid(row=2, column=1, padx=145, sticky='W')
        
        label1.grid(row=1, column=0, padx=20, pady=3, sticky='W')
        entry1.grid(row=1, column=1, sticky='W')
        
        OK_button1.grid(row=1, column=1, padx=(360,0), sticky='W')
        restart_button1.grid(row=1, column=1, padx=(390,0), sticky='W')
        
        label2.grid(row=2, column=0, padx=20, pady=3, sticky='W')
        entry2.grid(row=2, column=1, sticky='W')

        
    if options_alg.get() == 'Escítala':
        option = options_alg.get()
        text_label1.set('Caras:')
        text_label2.set('Orden:')
        entry1 = tk.Entry(panelFrame, width=5, textvariable=tk.IntVar())
        entry2 = tk.Entry(panelFrame, width=20, textvariable=tk.StringVar())
                
        label1.grid(row=1, column=0, padx=20, pady=3, sticky='W')
        entry1.grid(row=1, column=1, sticky='W')

        OK_button1.grid(row=1, column=1, padx=45, sticky='W')
        restart_button1.grid(row=1, column=1, padx=75, sticky='W')

        label2.grid(row=2, column=0, padx=20, pady=3, sticky='W')
        entry2.grid(row=2, column=1, sticky='W')

        OK_button2.grid(row=2, column=1, padx=(150,0), sticky='W')
        restart_button2.grid(row=2, column=1, padx=(180,0), sticky='W')
        
    if options_alg.get() == 'XOR' or options_alg.get() == 'RC4' or options_alg.get() == 'DES':
        option = options_alg.get()
        text_label1.set('Clave:')
        entry1 = tk.Entry(panelFrame, width=20, textvariable=tk.StringVar())
        
        label1.grid(row=1, column=0, padx=20, pady=3, sticky='W')
        entry1.grid(row=1, column=1, sticky='W')

        OK_button1.grid(row=1, column=1, padx=150, sticky='W')
        restart_button1.grid(row=1, column=1, padx=180, sticky='W')
    
    if options_alg.get() == 'Diffie-Hellman' or options_alg.get() == 'ElGamal' or options_alg.get() == 'RSA':
        option = options_alg.get()
        if options_alg.get() == 'RSA':
            text_label1.set('Primo p:')
            text_label2.set('Primo q:')
            text_label3.set('Clave pública/privada:')         
        else:
            text_label1.set('Primo grande:')
            text_label2.set('Generador:') #Raíz (alfa)
            text_label3.set('Clave privada:')
            
        entry1 = tk.Entry(panelFrame, width=20, textvariable=tk.StringVar())
        entry2 = tk.Entry(panelFrame, width=20, textvariable=tk.StringVar())
        entry3 = tk.Entry(panelFrame, width=20, textvariable=tk.StringVar())
        
        label1.grid(row=1, column=0, padx=20, pady=3, sticky='W')
        entry1.grid(row=1, column=1, sticky='W')
        label2.grid(row=2, column=0, padx=20, pady=3, sticky='W')
        entry2.grid(row=2, column=1, sticky='W')
        label3.grid(row=3, column=0, padx=20, pady=3, sticky='W')
        entry3.grid(row=3, column=1, sticky='W')
        
        OK_button1.grid(row=1, column=1, padx=150, sticky='W')
        restart_button1.grid(row=1, column=1, padx=180, sticky='W')
        OK_button2.grid(row=2, column=1, padx=150, sticky='W')
        restart_button2.grid(row=2, column=1, padx=180, sticky='W')
        OK_button3.grid(row=3, column=1, padx=150, sticky='W')
        restart_button3.grid(row=3, column=1, padx=180, sticky='W')


# In[5]:


root = tk.Tk()
root.title('Cript0vix')
root.resizable(True, True)
#root.geometry('650x650')

params = setParams()

global panelFrame
option = None

panelFrame = ttk.Frame(root)
panelFrame.pack()

label_options_alg = ttk.Label(panelFrame, 
                              text="Seleccione un algoritmo de encriptación:", 
                              font=('Robotto', 10))
options_alg = ttk.Combobox(panelFrame, 
                           font=('Robotto', 10), 
                           textvariable=tk.StringVar(), 
                           justify='center', 
                           state='readonly',
                           width=15)
options_alg['values'] = ('César', 'Vigenère', 'Escítala', 'XOR', 'RC4', 'DES', 'Diffie-Hellman', 'ElGamal', 'RSA')
options_alg.bind('<<ComboboxSelected>>', set_option)
    
text_label1 = tk.StringVar()
label1 = tk.Label(panelFrame, textvariable=text_label1, font=('Robotto', 10))

OK_icon = tk.PhotoImage(file=r'icons/check.png').subsample(3, 3)
restart_icon = tk.PhotoImage(file=r'icons/restart.png').subsample(3, 3)

OK_button1 = ttk.Button(panelFrame, image=OK_icon, command=params.get_entry1)
restart_button1 = ttk.Button(panelFrame, image=restart_icon, command=params.clear_entry1)

text_label2 = tk.StringVar()
label2 = tk.Label(panelFrame, textvariable=text_label2, font=('Robotto', 10))

OK_button2 = ttk.Button(panelFrame, image=OK_icon, command=params.get_entry2)
restart_button2 = ttk.Button(panelFrame, image=restart_icon, command=params.clear_entry2)

text_label3 = tk.StringVar()
label3 = tk.Label(panelFrame, textvariable=text_label3, font=('Robotto', 10))

OK_button3 = ttk.Button(panelFrame, image=OK_icon, command=params.get_entry3)
restart_button3 = ttk.Button(panelFrame, image=restart_icon, command=params.clear_entry3)

encrypt_value = tk.IntVar()
decrypt_button = tk.Radiobutton(panelFrame, text='Desencriptar', font=('Robotto', 10), 
                                variable=encrypt_value, value=0, command=params.get_value_encrypt)
encrypt_button = tk.Radiobutton(panelFrame, text='Encriptar', font=('Robotto', 10), 
                                variable=encrypt_value, value=1, command=params.get_value_encrypt)

input_text_label = ttk.Label(panelFrame, text='Texto:', font=('Robotto', 12))
scr_input = scrolledtext.ScrolledText(panelFrame, font=('Robotto', 11), width=80, height=10, wrap=tk.WORD)

calc_button = ttk.Button(panelFrame, text='Calcular', command=params.get_text_input)
clean_text_button = ttk.Button(panelFrame, text='Limpiar texto', command=params.clear_text_input)

output_text_label = ttk.Label(panelFrame, text='Resultado:', font=('Robotto', 12))
scr_output = scrolledtext.ScrolledText(panelFrame, font=('Robotto', 11), state='disabled', width=80, height=10, wrap=tk.WORD)

copy_output_button = ttk.Button(panelFrame, text='Copiar resultado', state='normal', command=params.copy_text_output)
exit_program_button = ttk.Button(panelFrame, text='Salir', command=root.destroy)

# Definición de las posiciones de los widgets
label_options_alg.grid(row=0, column=0, padx=20, pady=10, sticky='W')
options_alg.grid(row=0, column=1, sticky='W')

encrypt_button.grid(row=4, column=0, padx=20, pady=3, sticky='W')
decrypt_button.grid(row=4, column=0, padx=20)

input_text_label.grid(row=6, column=0, sticky='W', padx=15, pady=10)
scr_input.grid(row=7, column=0, sticky='WE', columnspan=3, padx=15)

calc_button.grid(row=8, column=0, padx=(80,0), pady=15, sticky='E')
clean_text_button.grid(row=8, column=1, padx=80, pady=15, sticky='W')

output_text_label.grid(row=9, column=0, sticky='W', padx=15)
scr_output.grid(row=10, column=0, sticky='WE', columnspan=3, padx=15, pady=10)

copy_output_button.grid(row=11, column=0, padx=(80,0), pady=15, sticky='E')
exit_program_button.grid(row=11, column=1, padx=80, pady=15, sticky='W')

root.mainloop()

