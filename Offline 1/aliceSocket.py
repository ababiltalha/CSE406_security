import aes128 as aes
import diffieHellman as dh
import socket

HOST = '127.0.0.1'
PORT = 12345	
		
# Alice is the client (sender)

# Diffie-Hellman key exchange, produce p, g, A(g^a mod p)
def initDH(k = 128):
    p = dh.genPrime(k)
    g = dh.genPrimitiveRoot(p)
    a, b = dh.genSecretPrivateKeys(k)
    A, B = dh.genPublicKeys(p, g, a, b)
    # will only send p, g, A
    return p, g, A, a

# Calculate shared key s
def calculateSharedKey(p, B, a):
    s = dh.genSharedSecretKey(p, B, a)
    return s

# AES key schedule
def keySchedule(sharedKey):
    # generate round keys
    sharedKey = aes.convertIntToString(sharedKey)
    keyMatrix = aes.createByteMatrix(sharedKey)
    roundKeys = aes.genRoundKeys(keyMatrix)
    return roundKeys

# AES encryption and decryption
def encrypt(message, roundKeys):
    # process plaintext
    plainTextBlocks = aes.divideIntoBlocks(message)
    plainTextStateMatrices = aes.createStateMatrix(plainTextBlocks)

    # encryotion
    cipherText = aes.encryption(plainTextStateMatrices, roundKeys)
    return cipherText
    
def decrypt(cipherText, roundKeys):
    # process ciphertext
    cipherTextBlocks = aes.divideIntoBlocks(cipherText)
    cipherTextStateMatrices = aes.createStateMatrix(cipherTextBlocks)

    # decryption
    decipheredText = aes.decryption(cipherTextStateMatrices, roundKeys)
    return decipheredText

def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))
    
    # send p, g, and g^a by concating them
    p, g, A, a = initDH()
    pgA = str(p) + " " + str(g) + " " + str(A)
    # print("Sending p g A: " + pgA)
    client.sendall(str(len(pgA)).encode())
    client.sendall(pgA.encode())
    
    # receive g^b
    B = client.recv(1024).decode()
    # print("Received B: " + B + "type: " + str(type(B)))
    B = int(B)
    
    # calculate and store shared key, key schedule
    sharedKey = calculateSharedKey(p, B, a)
    # print("Shared key: ", sharedKey)
    roundKeys = keySchedule(sharedKey)

    while True:
        # send message
        message = input("Alice: ")
        
        cipherText = encrypt(message, roundKeys)
        print("Sending cipher: " + cipherText)
        client.sendall(cipherText.encode())

        if message == 'end':
            break	
        
        # receive message
        receivedMessage = client.recv(1024).decode()
        plainText = decrypt(receivedMessage, roundKeys)
        
        if plainText == 'end':
            break
        
        print("Received cipher: " + receivedMessage)
        print("Bob: " + plainText)
    client.close()
        
if __name__ == '__main__':
    main()