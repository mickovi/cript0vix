import numpy as np
import sympy

class algCipher:
    def __init__(self, message_input):
        self.message_input = message_input
    
    ########## CÉSAR ##########
    
    def caesar(self, alphabet, rotation, type_cipher):
        #print('tipo:',type(rotation))
        message_output = ''
        for letter in self.message_input:
            if letter in alphabet:
                letter_inx = alphabet.find(letter)
                # Desencriptar 
                if type_cipher == 0:
                    letter_cipher = letter_inx - int(rotation)
                # Encriptar
                elif type_cipher == 1:
                    letter_cipher = letter_inx + int(rotation)

                # Evitar el desborde de índice de las letras
                letter_cipher %= len(alphabet)

                message_output = message_output + alphabet[letter_cipher]

            # Si una letra no se encuentra en el alphabet no se encripta
            else:
                message_output = message_output + letter

        return message_output
    
    ########## VIGENERE ##########
    
    def vigenere(self, alphabet, key, type_cipher):
        message_output = ''
        i = 0
        for letter in self.message_input:
            if letter in alphabet:
                letter_inx = alphabet.find(letter)
                # Desencriptar
                if type_cipher == 0:
                    letter_cipher = letter_inx - alphabet.index(key[i])
                # Encriptar
                elif type_cipher == 1:
                    letter_cipher = letter_inx + alphabet.index(key[i])
                # Evitar el desborde de índice de las letras
                letter_cipher %= len(alphabet)
                    
                i += 1
                # Reseteo del índice de la key 
                if i == len(key):
                    i = 0

                message_output = message_output + alphabet[letter_cipher]

            # Si una letra no se encuentra en el alphabet no se encripta
            else:
                message_output = message_output + letter

        return message_output
    
    ########## ESCÍTALA ##########
    
    def scytale(self, faces, places_faces, type_cipher):
        faces = int(faces)
        length = faces
        message_output = ''
        if faces*length > len(self.message_input):
            places = places_faces.split() # Crea una lista de string, p.e ["3", "2", "1", "4"]
            permutation = list(map(int, places)) # Convertir a lista de enteros
            permutation = [element - 1 for element in permutation] # Restamos 1 a todos los índices para que empiece en 0
            idx = np.empty_like(permutation) # Arreglo vacio del dimesión igual a permutation
            idx[permutation] = np.arange(len(permutation)) # idx es un arreglo de los índices
            
            # Desencriptar
            if type_cipher == 0:
                permutation.sort()
                matriz = np.array(list(self.message_input.ljust(faces*length, ' '))).reshape(faces, length).T
                matriz = matriz[idx, :] # Cambiamos el orden de las filas según permutation
                lista_columna =  [''.join(faces) for faces in matriz]

            # Encriptar
            elif type_cipher == 1:
                matriz = np.array(list(self.message_input.ljust(faces*length, ' '))).reshape(faces, length)
                matriz = matriz[idx, :] # Cambiamos el orden de las filas según permutation
                lista_columna =  [''.join(faces) for faces in matriz.T]
        
            message_output = ''.join(lista_columna).strip() # Quitamos los espacios sobrantes de la matriz
        
        else:
            print('ERROR. El mensaje es muy largo para la dimensión de la escítala')
            print('dim = ', faces*length)
            print('longuitud del texto = ', len(self.message_input))
        
        return message_output
    
    
    ########## XOR ##########
    
    def xor(self, clave, tipo):
        mensaje = self.message_input
        clave = list(clave)
        
        if len(clave) < len(mensaje):
            diff = len(mensaje) - len(clave)
            j = 0
            for i in range(diff):
                if i == len(clave) - 1:
                    j = 0
                clave.append(clave[j])
                j = j + 1

        # Desencriptar
        if tipo == 0:
            mensaje = [int(mensaje[i:i+2], 16) for i in range(0, len(mensaje), 2)]
            xor_dec = [i ^ ord(j) for i, j in zip(mensaje, clave)]
            xor_res = [chr(i) for i in xor_dec]
            return ''.join(xor_res)

        # Encriptar
        if tipo == 1:
            xor_dec = [ord(i) ^ ord(j) for i, j in zip(mensaje, clave)]
            xor_res = [chr(i) for i in xor_dec]
            xor_hex = ['{:X}'.format(ord(i)) for i in xor_res]

            for i in range(len(xor_hex)):
                if len(xor_hex[i]) == 1:
                    xor_hex[i] = '0' + xor_hex[i]
            return ''.join(xor_hex)
        
    ########## RC4 ##########
    
    def __init__(self, message_input):
        self.message_input = message_input
        
    def text_to_bytes(text):
        return [ord(i) for i in text]

    def bytes_to_text(byteList):
        text_plain = [chr(byte) for byte in byteList]
        return ''.join(text_plain)

    def bytes_to_hex(byteList):
        hexList = []
        [hexList.append('{:X}'.format(i)) for i in byteList]
        return ''.join(hexList)
    
    def hex_to_bytes(text):
        return [int(text[i:i+2], 16) for i in range(0, len(text), 2)]

    # KSA
    def rc4_ksa(keyBytes):
        keyLen = len(keyBytes)

        S = list(range(256))

        j = 0
        for i in range(256):
            j = (j + S[i] + keyBytes[i % keyLen]) % 256
            S[i], S[j] = S[j], S[i]

        return S

    # PRGA
    def rc4_prga(plainBytes, keyBytes, tipo):
        S = algCipher.rc4_ksa(keyBytes)
        
        keystreamList = []
        cipherList = []

        plainLen = len(plainBytes)

        i = 0
        j = 0
        S = S[65:] # Descarte de los primeros 8 bytes
        for m in range(plainLen):
            i = (i + 1) % 192#256
            j = (j + S[i]) % 192#256
            S[i], S[j] = S[j], S[i]
            k = S[(S[i] + S[j]) % 192]#256]
            keystreamList.append(k)
            cipherList.append(k ^ plainBytes[m])
        
        key_stream = algCipher.bytes_to_hex(keystreamList)
        if tipo == 0:
            msg_cipher = algCipher.bytes_to_text(cipherList)
        if tipo == 1:
            msg_cipher = algCipher.bytes_to_hex(cipherList)

        return key_stream, msg_cipher
    
    def rc4(self, clave, tipo):
        if tipo == 0:
            plainBytes = algCipher.hex_to_bytes(self.message_input)
        if tipo == 1:
            plainBytes = algCipher.text_to_bytes(self.message_input)
        keyBytes = algCipher.text_to_bytes(clave)
        
        return algCipher.rc4_prga(plainBytes, keyBytes, tipo)

    
    ########## DES ##########
    
    global PI, CP_1, CP_2, E, S_BOX, P, PI_1, SHIFT
    
    #Initial permut matrix for the datas
    PI = [58, 50, 42, 34, 26, 18, 10, 2,
          60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6,
          64, 56, 48, 40, 32, 24, 16, 8,
          57, 49, 41, 33, 25, 17, 9, 1,
          59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5,
          63, 55, 47, 39, 31, 23, 15, 7]

    #Initial permut made on the key
    CP_1 = [57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4]

    #Permut applied on shifted key to get Ki+1
    CP_2 = [14, 17, 11, 24, 1, 5, 3, 28,
            15, 6, 21, 10, 23, 19, 12, 4,
            26, 8, 16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55, 30, 40,
            51, 45, 33, 48, 44, 49, 39, 56,
            34, 53, 46, 42, 50, 36, 29, 32]

    #Expand matrix to get a 48bits matrix of datas to apply the xor with Ki
    E = [32, 1, 2, 3, 4, 5,
         4, 5, 6, 7, 8, 9,
         8, 9, 10, 11, 12, 13,
         12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21,
         20, 21, 22, 23, 24, 25,
         24, 25, 26, 27, 28, 29,
         28, 29, 30, 31, 32, 1]

    #SBOX
    S_BOX = [

    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],

    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],

    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],

    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],  

    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ], 

    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ], 

    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],

    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ]
    ]

    #Permut made after each SBox substitution for each round
    P = [16, 7, 20, 21, 29, 12, 28, 17,
         1, 15, 23, 26, 5, 18, 31, 10,
         2, 8, 24, 14, 32, 27, 3, 9,
         19, 13, 30, 6, 22, 11, 4, 25]

    #Final permut for datas after the 16 rounds
    PI_1 = [40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25]

    #Matrix that determine the shift for each round of keys
    SHIFT = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

    # Convierte un string a una lista de bits
    def string_to_bit_array(text):
        array = list()
        for char in text:
            binval = algCipher.binvalue(char, 8) # Convierte un caracter a byte
            array.extend([int(x) for x in list(binval)])
        return array
    
    # Desplazamiento de bits para cada subclave
    def shift(key_left, key_right, n):
        return key_left[n:] + key_left[:n], key_right[n:] + key_right[:n]
    
    # Divide ina lista en sublistas de tamaño n
    def nsplit(s, n):
        return [s[k:k+n] for k in range(0, len(s), n)]
    
    # Devuelve un string a partir de un array de bits
    def bit_array_to_string(array):
        text = ''
        for _bytes in algCipher.nsplit(array,8):
            to_bin = ''.join([str(x) for x in _bytes])
            text += ''.join(chr(int(to_bin, 2)))

        return text
    
    # Retorna el número binario de un caracter
    def binvalue(val, bitsize):
        binval = bin(val)[2:] if isinstance(val, int) else bin(ord(val))[2:]
        if len(binval) > bitsize:
            raise "binary value larger than the expected size"
        while len(binval) < bitsize:
            binval = "0" + binval # Agrega los ceros necesarios
        return binval
    
    # Sustitución de bytes usando S-BOX
    def substitute(sub_block_48_bit):
        subblocks = algCipher.nsplit(sub_block_48_bit, 6) # Divide en bloques 6 bits que pasan a las S-Boxs
        result = list()
        for i in range(len(subblocks)):
            block = subblocks[i]
            row = int(str(block[0]) + str(block[5]), 2) # Se define una fila tomando el primer y último bit
            column = int(''.join([str(x) for x in block[1:][:-1]]), 2) #Las columnas son los bits de las posiciones 2, 3, 4, 5
            val = S_BOX[i][row][column] # Toma el valor correspondiente de la S-Box para la ronda i
            bin = algCipher.binvalue(val, 4) # Convierte el valor a un binario de 4 bits
            result += [int(x) for x in bin]
        return result

    def permut(block, table):
        return [block[x-1] for x in table]

    def expand(block, table):
        return [block[x-1] for x in table]
    
    def xor_operation(t1, t2):
        return [x ^ y for x, y in zip(t1, t2)]
    
    # Genera todas las claves
    def generatekeys(subkeys, key):
        key_bits = algCipher.string_to_bit_array(key)
        key_permut = algCipher.permut(key_bits, CP_1) # Aplica la permutación inicial a la clave
        key_left, key_right = algCipher.nsplit(key_permut, 28) # Divide la clave en dos subclaves de 20 bits cada una
        # Apply the 16 rounds
        for i in range(16):
            key_left, key_right = algCipher.shift(key_left, key_right, SHIFT[i]) # Desplazamientos de bits
            tmp = key_left + key_right
            subkeys.append(algCipher.permut(tmp, CP_2)) # Aplica una permutación para generar una subclave
        return subkeys
        
    def des(self, key, type_cipher):
        # GENERACIÓN DE CLAVES
        subkeys = []
        keys = algCipher.generatekeys(subkeys, key)
        
        # DIVISIÓN DEL TEXTO EN BLOQUES DE 32 BITS
        text_blocks = algCipher.nsplit(self.message_input, 8) # Divide el texto en una lista de 8 bytes (64 bits)
        PF = list()
        for block in text_blocks: # Bucle sobre todos los bloques de datos (8)
            block = algCipher.string_to_bit_array(block)
            block = algCipher.permut(block, PI) # Aplica permutación inicial sobre el bloque
            text_left, text_right = algCipher.nsplit(block, 32) # El texto se convierte en dos bloques de 32 bits: g(LEFT), d(RIGHT)
            tmp = None
            
            # FUNCIÓN DE FEISTEL
            for i in range(16): # 16 rondas
                sub_block_48_bit = algCipher.expand(text_right, E) # Expansión (32 a 48 bits)
                
                # Mezcla
                if type_cipher == 1:
                    tmp = algCipher.xor_operation(keys[i], sub_block_48_bit)
                if type_cipher == 0:
                    tmp = algCipher.xor_operation(keys[15-i], sub_block_48_bit) # Empieza desde la última clave
                
                # S-BOX
                feistel_output = algCipher.substitute(tmp) # Sustitución
                feistel_output = algCipher.permut(tmp, P) # Permutación
                
                xor_output = algCipher.xor_operation(text_left, feistel_output)
                
                # CRUZAMIENTO
                text_left = text_right
                text_right = xor_output
                
            # PERMUTACIÓN FINAL    
            PF = algCipher.permut(text_right + text_left, PI_1) # Permutación final y se apila el resultado parcial
            
        final_res = algCipher.bit_array_to_string(PF)
        
        return final_res
    
    ########## Diffie-Hellman ##########
    
    def generate_public_key(self, p, alpha, beta):
        alpha = int(alpha)
        beta = int(beta)
        x = (alpha ** beta) % int(p, 16)
        return '{:X}'.format(x)
    
    def get_K(self, K_pub, p, beta):
        beta = int(beta)
        #K = (int(K_pub, 16) ** beta) % int(p, 16)
        K = pow(int(K_pub, 16), beta, int(p, 16))
        return '{:X}'.format(K)
    
    ########## ElGamal ##########
    def elgamal_encrypt(self, p, alpha, priv_key, beta, N):
        alpha = int(alpha)
        beta = int(beta, 16)
        u = int(priv_key)
        N = int(N)
        N1 = (alpha ** u) % int(p, 16)
        N2 = N * (beta ** u) % int(p, 16)
        return N1, N2
    
    def elgamal_decrypt(self, p, priv_key, N1, N2):
        p = int(p,16)
        b = int(priv_key)
        N1 = int(N1)
        N2 = int(N2)
        N3 = (N1 ** b) % p
        N4 = sympy.mod_inverse(N3, p)
        N = (N2 * N4) % p
        return N
    
    ########## RSA ##########
    def mcd(a, b):
        if b == 0:
            return a
        else:
            return algCipher.mcd(b, a % b)
        
    def rsa_encrypt(self, p_b, q_b, e_b):
        p_b = int(p_b)
        q_b = int(q_b)
        e_b = int(e_b)
        N = int(self.message_input)
        n_b = p_b * q_b
        # Indicador de Euler
        phi_b = (p_b - 1) * (q_b - 1)
        mcd_output = algCipher.mcd(phi_b, e_b)
        if mcd_output == 1:
            C = (N ** e_b) % n_b
            return C
        else:
            return 'Error, la clave pública no debe ser divisor de' + str(phi_b)
    
    def rsa_decrypt(self, p_b, q_b, d_b):
        p_b = int(p_b)
        q_b = int(q_b)
        d_b = int(d_b)
        C = int(self.message_input)
        n_b = p_b * q_b
        msg = (C ** d_b) % n_b
        return msg