import numpy as np
from BitVector import *
import time

sbox = np.array([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
                 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
                 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
                 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
                 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
                 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
                 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
                 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
                 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
                 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
                 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
                 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
                 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
                 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
                 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
                 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16], dtype=np.uint8)

invSbox = np.array([0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
                        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
                        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
                        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
                        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
                        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
                        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
                        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
                        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
                        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
                        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
                        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
                        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
                        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
                        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
                        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d], dtype=np.uint8)

rcon = np.array([0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36], dtype=np.uint8)

fixedMatrix = np.array([[0x02, 0x03, 0x01, 0x01],
                        [0x01, 0x02, 0x03, 0x01],
                        [0x01, 0x01, 0x02, 0x03],
                        [0x03, 0x01, 0x01, 0x02]], dtype=np.uint8)

AES_modulus = BitVector(bitstring='100011011')

invFixedMatrix = np.array([[0x0e, 0x0b, 0x0d, 0x09],
                           [0x09, 0x0e, 0x0b, 0x0d],
                           [0x0d, 0x09, 0x0e, 0x0b],
                           [0x0b, 0x0d, 0x09, 0x0e]], dtype=np.uint8)
                
def convertToHex(asciiString):
    hexString = ""
    for char in asciiString:
        hexString += hex(ord(char))[2:]
    return hexString
    
def convertToAscii(hexString):
    asciiString = ""
    for i in range(0, len(hexString), 2):
        asciiString += chr(int(hexString[i:i+2], 16))
    return asciiString

def divideIntoBlocks(data, blockSize = 16):
    blocks = []
    for i in range(0, len(data), blockSize):
        blocks.append(data[i:i+blockSize])
    return blocks
    
def createByteMatrix(data):
    if len(data) < 16:
        # padding
        data += "0" * (16 - len(data))

    data = data[:16]

    byteMatrix = np.zeros((4, 4), dtype=np.uint8)

    # column major
    for col in range(4):
        for row in range(4):
            byteMatrix[row][col] = ord(data[col * 4 + row])

    return byteMatrix


    

def createStateMatrix(blocks):
    for i in range(len(blocks)):
        blocks[i] = createByteMatrix(blocks[i])
    return blocks

def printMatrixInHex(matrix):
    for row in range(4):
        for col in range(4):
            print(hex(matrix[row][col])[2:].zfill(2), end=" ")
        print()
    print()
    
def printListInHex(list):
    for i in range(len(list)):
        print(hex(list[i])[2:].zfill(2), end=" ")
    print()
                
def g(lastCol, rconIndex):
    # rotate
    lastCol = np.roll(lastCol, -1)
    # substitute
    for i in range(4):
        lastCol[i] = sbox[lastCol[i]]
    # xor with round constant
    lastCol[0] ^= rcon[rconIndex]
    return lastCol

def genRoundKeys(keyMatrix):
    roundKeys = np.zeros((11, 4, 4), dtype=np.uint8)
    roundKeys[0] = keyMatrix
    
    for i in range(1, 11):
        prevMatrix = roundKeys[i-1]
        # last column of previous matrix
        lastCol = prevMatrix[:, 3]
        for k in range(4):
            if k == 0:
                roundKeys[i][:, k] = np.bitwise_xor(g(lastCol, i), prevMatrix[:, k])
            else:
                roundKeys[i][:, k] = np.bitwise_xor(roundKeys[i][:, k-1], prevMatrix[:, k])
    
    #array of 11 round key matrices
    return roundKeys

def addRoundKey(stateMatrix, keyMatrix):
    for col in range(4):
        for row in range(4):
            stateMatrix[row][col] ^= keyMatrix[row][col]
    return stateMatrix

def subBytes(stateMatrix):
    for col in range(4):
        for row in range(4):
            stateMatrix[row][col] = sbox[stateMatrix[row][col]]
    return stateMatrix

def shiftRows(stateMatrix):
    for row in range(1, 4):
        stateMatrix[row] = np.roll(stateMatrix[row], -row)
    return stateMatrix

def mixColumns(stateMatrix):
    tempMatrix = np.zeros((4, 4), dtype=np.uint8)
    for row in range(4):
        for col in range(4):
            for i in range(4):
                bv1 = BitVector(intVal=fixedMatrix[row][i], size=8)
                bv2 = BitVector(intVal=stateMatrix[i][col], size=8)
                bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
                tempMatrix[row][col] ^= bv3.intValue()
    return tempMatrix
                                
def encryption(stateMatrices, roundKeys):
    cipherText = ""
    for stateMatrix in stateMatrices:
        # round 0
        stateMatrix = addRoundKey(stateMatrix, roundKeys[0])
        for i in range(1, 11):
            stateMatrix = subBytes(stateMatrix)
            stateMatrix = shiftRows(stateMatrix)
            # no mix columns in last round
            if i != 10:
                stateMatrix = mixColumns(stateMatrix)
            stateMatrix = addRoundKey(stateMatrix, roundKeys[i])
        # printMatrixInHex(stateMatrix)
        cipherText += (''.join([chr(stateMatrix[row][col]) for col in range(4) for row in range(4)]))
    return cipherText

def invShiftRows(stateMatrix):
    for row in range(1, 4):
        stateMatrix[row] = np.roll(stateMatrix[row], row)
    return stateMatrix

def invSubBytes(stateMatrix):
    for col in range(4):
        for row in range(4):
            stateMatrix[row][col] = invSbox[stateMatrix[row][col]]
    return stateMatrix

def invMixColumns(stateMatrix):
    tempMatrix = np.zeros((4, 4), dtype=np.uint8)
    for row in range(4):
        for col in range(4):
            for i in range(4):
                bv1 = BitVector(intVal=invFixedMatrix[row][i], size=8)
                bv2 = BitVector(intVal=stateMatrix[i][col], size=8)
                bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
                tempMatrix[row][col] ^= bv3.intValue()
    return tempMatrix

def decryption(stateMatrices, roundKeys):
    decipheredText = ""
    for stateMatrix in stateMatrices:
        # round 0
        stateMatrix = addRoundKey(stateMatrix, roundKeys[10])
        for i in range(9, -1, -1):
            stateMatrix = invShiftRows(stateMatrix)
            stateMatrix = invSubBytes(stateMatrix)
            stateMatrix = addRoundKey(stateMatrix, roundKeys[i])
            # no mix columns in last round (round 10, roundkey 0)
            if i != 0:
                stateMatrix = invMixColumns(stateMatrix)
        decipheredText += (''.join([chr(stateMatrix[row][col]) for col in range(4) for row in range(4)]))
    return decipheredText

def main():
    # input key and plaintext
    # initialKey = input("Enter the secret key: ")
    # plainText = input("Enter the plain text: ")
    initialKey = "BUET CSE18 Batch"
    plainText = "Can They Do This"

    print()
    print("Plain Text:\nIn ASCII: " + plainText + "\nIn Hex: " + convertToHex(plainText) + "\n")
    print("Key:\nIn ASCII: " + initialKey + "\nIn Hex: " + convertToHex(initialKey) + "\n")

    # initial key matrix
    keyMatrix = createByteMatrix(initialKey)

    # generate round keys
    keySchedStart = time.time()
    roundKeys = genRoundKeys(keyMatrix)
    keySchedEnd = time.time()

    # process plaintext
    plainTextBlocks = divideIntoBlocks(plainText)
    plainTextStateMatrices = createStateMatrix(plainTextBlocks)

    # encryotion
    encryptionStart = time.time()
    cipherText = encryption(plainTextStateMatrices, roundKeys)
    encryptionEnd = time.time()
    print("Cipher Text:\nIn Hex: " + convertToHex(cipherText) + "\nIn ASCII: " + cipherText + "\n")

    # process ciphertext
    cipherTextBlocks = divideIntoBlocks(cipherText)
    cipherTextStateMatrices = createStateMatrix(cipherTextBlocks)

    # decryption
    decryptionStart = time.time()
    decipheredText = decryption(cipherTextStateMatrices, roundKeys)
    decryptionEnd = time.time()
    print("Deciphered Text:\nIn Hex: " + convertToHex(decipheredText) + "\nIn ASCII: " + decipheredText + "\n")

    # print exec time details
    print("Key Scheduling: " + str(keySchedEnd - keySchedStart) + " seconds")
    print("Encryption: " + str(encryptionEnd - encryptionStart) + " seconds")
    print("Decryption: " + str(decryptionEnd - decryptionStart) + " seconds")
    print()

if __name__ == "__main__":
    main()