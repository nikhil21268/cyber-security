


# Global Vars for verification

firstEncrypted = []
fourteenthEncrypted = []
fifteenthDecrypted = []
secondDecrypted = []

# Initial and final permutations
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

# Permutation P
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

# Initial permutation for keys
PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

# Permutation for generating subkeys
PC2 = [14, 17, 11, 24, 1, 5, 3, 28,
       15, 6, 21, 10, 23, 19, 12, 4,
       26, 8, 16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55, 30, 40,
       51, 45, 33, 48, 44, 49, 39, 56,
       34, 53, 46, 42, 50, 36, 29, 32]

# Number of left shifts made in various rounds to get subkeys
SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
# E Bit Selection Table that Expands the input from 32 bit to 48 bit which will then be XORed with Key
EXPAND = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

# Substitution Boxes
# Referred to as primitive functions in the FIPS standard (Page 22)
S_BOXES = [

    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],

    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],

    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],

    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],

    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],

    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],

    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],

    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ]
]

def bits_to_char(ciphertext):
    # take every 8 bits and combine them to form a character
    sum=0
    finalList = []
    # 10100100 
    p=2**7
    
    for i in range(len(ciphertext)):
        if i%8==0 and i!=0:
            finalList.append(chr(sum))
            p=2**7
            sum=ciphertext[i]*p
        else:
            sum+=ciphertext[i]*p
        p=p//2
    finalList.append(chr(sum))
    return ''.join([str(c) for c in finalList])


def generate_subkeys(key):
    key = permute(key, PC1)
    subkeys = []

    for i in range(16):
        key = rotate_left(key[:28], 1) + rotate_left(key[28:], 1)
        subkey = permute(key, PC2)
        subkeys.append(subkey)

    return subkeys

def feistel_network(right_half, subkey):
    expanded = expansion_permutation(right_half)
    xor_result = xor(expanded, subkey)
    substituted = substitute(xor_result)
    permuted = permute(substituted, P)
    return xor(permuted, right_half)

def des_encrypt(plaintext, key):
    global firstEncrypted, fourteenthEncrypted
    # Initial permutation
    block = permute(plaintext, IP)
    # print("plaintext is",plaintext)
    # print("block is",len(block))

    left_half, right_half = block[:32], block[32:]
    subkeys = generate_subkeys(key)
    myList = []
    # print(subkeys.__len__() == 16)
    # 16 rounds of Feistel network
    for i in range(16):
        
        temp = right_half
        right_half = xor(left_half, feistel_network(right_half, subkeys[i]))
        left_half = temp

        myList.append((left_half, right_half))
        # if i == 1:
        #     firstEncrypted = right_half + left_half

        # elif i == 15:
        #     fourteenthEncrypted = right_half + left_half


    # Combine left and right halves
    block = right_half + left_half

    # Final permutation
    ciphertext = permute(block, FP)

    return ciphertext, myList

def des_decrypt(ciphertext, key):
    global secondDecrypted, fifteenthDecrypted
    # Initial permutation
    block = permute(ciphertext, IP)

    # Split block into left and right halves
    left_half, right_half = block[:32], block[32:]

    # Generate subkeys
    subkeys = generate_subkeys(key)

    myList = []

    # 16 rounds of Feistel network in reverse order
    for i in range(15, -1, -1):
        temp = right_half
        right_half = xor(left_half, feistel_network(right_half, subkeys[i]))
        left_half = temp

        myList.append((right_half, left_half))
        # if i == 14:
        #     fifteenthDecrypted = right_half + left_half
            
        # elif i == 1:
        #     secondDecrypted = right_half + left_half


    # Combine left and right halves
    block = right_half + left_half

    # Final permutation
    plaintext = permute(block, FP)

    return plaintext, myList

# Utility functions
def permute(data, permutation):
    # print(len(data))
    l=[]
    for i in permutation:
        # try:
            l.append(data[i - 1])
        # return [data[i - 1] for i in permutation]
        # except IndexError:
        #     print(i)
        #     exit(1)
    return l

def rotate_left(data, count):
    return data[count:] + data[:count]

def xor(a, b):
    return [i ^ j for i, j in zip(a, b)]

def expansion_permutation(block):
    return permute(block, [32, 1, 2, 3, 4, 5, 4, 5,
                           6, 7, 8, 9, 8, 9, 10, 11,
                           12, 13, 12, 13, 14, 15, 16, 17,
                           16, 17, 18, 19, 20, 21, 20, 21,
                           22, 23, 24, 25, 24, 25, 26, 27,
                           28, 29, 28, 29, 30, 31, 32, 1])

def substitute(data):
    output = []
    for i in range(0, 48, 6):
        block = data[i:i + 6]
        row = (block[0] << 1) + block[5]
        col = (block[1] << 3) + (block[2] << 2) + (block[3] << 1) + block[4]
        value = S_BOXES[i // 6][row][col]
        output.extend([(value >> 3) & 1, (value >> 2) & 1, (value >> 1) & 1, value & 1])
    return output


# Example usage
def input_to_8_bit_string(s):
    # returns a list of 0s and 1s representing the input string
    # convert every character into 8 bits and append every bit in final list
    l=[]
    for c in s:
        l.append(format(ord(c), '08b'))
    return l

def convert_to_56_bit_key(key):
    # Convert key to 56 bit binary string
    key = input_to_8_bit_string(key)
    # dicard every 8th bit
    key = key[:7] + key[8:15] + key[16:23] + key[24:31] + key[32:39] + key[40:47] + key[48:55]
    return key


def hex_to_bits(hex_number):
    # s=str(hex_number)
    # Convert the hexadecimal number to binary string and remove the '0b' prefix

    binary_string = bin(hex_number)[2:]
    print(binary_string)
    # Ensure the binary string is padded with leading zeros to make it a multiple of 4
    binary_string = binary_string.zfill((len(binary_string) + 3) // 4 * 4)
    # Convert each character of the binary string to integers and create a list
    bits_list = [int(bit) for bit in binary_string]
    
    return bits_list

def listOfBits(key, plaintext):
    # Convert the key and plaintext to a list of bits
    key = [int(c) for c in key]
    plaintext = [int(c) for c in plaintext]
    return key, plaintext

# plaintext consits of 8 characters
# We feed 64-bit values to the DES Black Box
orlist=["AbhinavU","Firewall", "A123B453", "Encrypts", "Decipher"]
keylist=["NikhilSu", "Vaulting","A123B453", "Securing","Decipher"]


for i in range(len(orlist)):
    print("Test Case", i+1, "starting...")
    originaltext = orlist[i]
    key = keylist[i]
    plaintext=originaltext
    print("\nPlaintext is -", plaintext)
    print("Key is -", key, "\n")

    # converted to 64 bit string
    plaintext = input_to_8_bit_string(plaintext)
    key = input_to_8_bit_string(key)
    key=''.join(key)
    plaintext=''.join(plaintext)

    key, plaintext = listOfBits(key, plaintext)

    # encryption of plaintext
    print("Starting encryption of plaintext...")
    ciphertext, myList1 = des_encrypt(plaintext, key)
    print("Encryption of plaintext done!")
    print("Encrypted plaintext:", bits_to_char(ciphertext),"\n")

    # decryption of ciphertext
    print("Starting decryption of ciphertext..")
    decrypted_plaintext, myList2 = des_decrypt(ciphertext, key)
    print("Decryption of ciphertext done!")
    print("Decrypted ciphertext:", bits_to_char(decrypted_plaintext))

    # print("Plaintext:", bits_to_char(plaintext))
    # print("Encrypted ciphertext:", bits_to_char(ciphertext))

    # recent additions
    for j in range(16):
        LE, RE = myList1[j]
        RD, LD = myList2[j]
        print(f"Round {j+1} -\tLE{j+1}: {bits_to_char(LE)}  \tRE{j+1}: {bits_to_char(RE)}  \tLD{j+1}: {bits_to_char(LD)}  \tRD{j+1}: {bits_to_char(RD)}")
        # print(len(LE), len(RE), len(LD), len(RD ))
        # print("Round", j+1, "\nL", j+1, ":", LE, "\nR", j+1, ":", RE, "\nL", 16-j, ":", LD, "\nR", 16-j, ":", RD)
        # assert LE == RD and RE == LD, f"Failed at round {j+1}"

    print()
    print("Verification process starting...")
    print()
    if plaintext == decrypted_plaintext:
        print("Decrypted ciphertext is"+ "\033[1m" + " same as "+"\033[0m" +"original Plaintext")
    else:
        print("Decrypted ciphertext is"+ "\033[1m" + " not same as "+"\033[0m" +"original Plaintext")

    if myList1[0] == myList2[14]:
        print("Output of the 1st encryption round is"+ "\033[1m" + " same as "+"\033[0m" +"output of the 15th decryption round -",end=" ")
        print(bits_to_char(list(myList1[0][0]+myList1[0][1])), " [ length of string = ",len(bits_to_char(list(myList1[0][0]+myList1[0][1]))),"]")
    else:
        print("Failed to verify the output of the 1st encryption round and output of the 15th decryption round")
        print("Output of the 1st encryption round is - ",bits_to_char(list(myList1[0][0]+myList1[0][1]))," [ length of string = ",len(bits_to_char(list(myList1[0][0]+myList1[0][1]))),"]")
        print("Output of the 15th decryption round is - ",bits_to_char(list(myList2[14][0]+myList2[14][1])), " [ length of string = ",len(bits_to_char(list(myList2[14][0]+myList2[14][1]))),"]")

    if myList1[13] == myList2[1]:
        print("Output of the 14th encryption round is"+ "\033[1m" + " same as "+"\033[0m" +"output of the 2nd decryption round -",end=" ")
        # print(fourteenthEncrypted)
        print(bits_to_char(list(myList1[13][0]+myList1[13][1])), " [ length of string = ",len(bits_to_char(list(myList1[13][0]+myList1[13][1]))),"]")
    else:
        print("Failed to verify the output of the 14th encryption round and output of the 2nd decryption round : ")
        print("Output of the 14th encryption round is - ",bits_to_char(list(myList1[13][0]+myList1[13][1])), " [ length of string = ",len(bits_to_char(list(myList1[13][0]+myList1[13][1]))),"]")
        print("Output of the 2nd decryption round is - ",bits_to_char(list(myList2[1][0]+myList2[1][1])), " [ length of string = ",len(bits_to_char(list(myList2[1][0]+myList2[1][1]))),"]")

    print("---------------------------------------------")
    # remove the break statement to run all the test cases
    # break
