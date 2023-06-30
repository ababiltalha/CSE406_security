import aes128 as aes
import diffieHellman as dh
import socket

HOST = '127.0.0.1'
PORT = 12345	
	
# Bob is the server (receiver)

# Diffie-Hellman key exchange, produce B(g^b mod p)
def initDH(p, g, k = 128):
    a, b = dh.genSecretPrivateKeys(k)
    A, B = dh.genPublicKeys(p, g, a, b)
    # will only send B
    return B, b

def calculateSharedKey(p, B, a):
    s = dh.genSharedSecretKey(p, B, a)
    return s

def keySchedule(sharedKey):
    # generate round keys
    sharedKey = aes.convertIntToString(sharedKey)
    keyMatrix = aes.createByteMatrix(sharedKey)
    roundKeys = aes.genRoundKeys(keyMatrix)
    return roundKeys

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
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # server.close()
    server.bind((HOST, PORT))
    server.listen(1)
    
    client, addr = server.accept()
    print("\nAlice wants to text you.\n")
    
    # receive length of concat string of p, g, and g^a
    length = client.recv(1024).decode()
    # receive p, g, and g^a
    pgA = client.recv(int(length)).decode()
    # print("Received p g A: " + pgA)
    p, g, A = int(pgA.split()[0]), int(pgA.split()[1]), int(pgA.split()[2])
    
    # send g^b
    B, b = initDH(p, g)
    # print("Sending B: ", B)
    client.sendall(str(B).encode())
    
    # calculate shared key
    sharedKey = calculateSharedKey(p, A, b)
    # print("Shared key:", sharedKey)
    roundKeys = keySchedule(sharedKey)
    
    while True:
        #receive message
        receivedMessage = client.recv(1024).decode()
        plainText = decrypt(receivedMessage, roundKeys)

        if plainText == 'end':
            break
        
        print("Received cipher: " + receivedMessage)
        print("Alice: " + plainText)
        
        # send message
        message = input("Bob: ")
        
        cipherText = encrypt(message, roundKeys)
        print("Sending cipher: " + cipherText)
        client.send(cipherText.encode())

        if message == 'end':
            break	
    client.close()
    server.close() 
        
if __name__ == "__main__":
    main()
