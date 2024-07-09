from tqdm import tqdm
import random
from itertools import permutations
tempvar=0
def create_tables():
    # manual input of key
    encryption_table = {
        'AB': 'BC',
        'AC': 'CB',
        'BA': 'CA',
        'BC': 'CC',
        'CA': 'BB',
        'CB': 'AA',
        'AA': 'AB',
        'BB': 'AC',
        'CC': 'BA',
    }
    decryption_table = {v: k for k, v in encryption_table.items()}
    return encryption_table, decryption_table

bits_in_hash=16

def binary_xor(str1, str2):
    result = ''.join('1' if bit1 != bit2 else '0' for bit1, bit2 in zip(str1, str2))
    return result

def hash_function(data):
    current_hash = '0'*bits_in_hash
    data_blocks=[data[i:i+bits_in_hash] for i in range(0,len(data),bits_in_hash)]
    for block in data_blocks:
        t=current_hash[1:]+current_hash[0]
        current_hash=t
        current_hash = binary_xor(current_hash, block)
    # print(current_hash)
    return current_hash

def encrypt(plainText, encryption_table):
    cipherText = ''
    for i in range(0, len(plainText), 2):
        pair = plainText[i:i+2]
        cipherText += encryption_table[pair]
    
    return cipherText

def convertToBin(cipherText):
    """Convert string to binary"""
    ans=""
    for c in cipherText:
        # print(c)
        ans+=('0'+bin(ord(c))[2:])      # 8 - bits
    return ans

def decrypt(cipherText, decryption_table):
    # hash_len=bits_in_hash//2
    plaintext = ''
    for i in range(0, len(cipherText), 2):
        pair = cipherText[i:i+2]
        plaintext += decryption_table[pair]
    return plaintext

def generate_permutations(arr, start=0):
    if start == len(arr) - 1:
        return [tuple(arr)]
    else:
        all_permutations = []
        for i in range(start, len(arr)):
            arr[start], arr[i] = arr[i], arr[start]
            all_permutations.extend(generate_permutations(arr, start + 1))
            # swap again to backtrack
            arr[start], arr[i] = arr[i], arr[start]
        return all_permutations


def brute_force_attack(cipherListData):
    """
    1) Assume "cipherText" is a string concatenation of encrypted data and the hash(originalText)
    2) Generate all possible substitution tables
    """

    cipherText = cipherListData[0]
    
    result_list = ['AB','AC','BC','AA','BB','CC','CB','CA','BA']
    # permutations_list = list(permutations(result_list))
    permutations_list = generate_permutations(result_list)
    
    # for randomising the list
    # random.shuffle(permutations_list)
    
    decrypted_plaintext=['','','','','']
    for perm in tqdm(permutations_list):
    # for perm in permutations_list:
        encryption_table = dict(zip(['AB','AC','BC','AA','BB','CC','CB','CA','BA'], perm))
        decryption_table = {v:k for k,v in encryption_table.items()}
        
        hash_len=bits_in_hash
        ct = decrypt(cipherText, decryption_table)
        # 'ct' is the candidate PlainText
        decrypted_plaintext[0]=ct[:-hash_len]
        hashValue=ct[-hash_len:]
        Flag = 1
        if is_recognizable(decrypted_plaintext[0],hashValue):
            counter=0
            for anyCipherText in cipherListData[1:]:
                counter+=1
                ct=decrypt(anyCipherText, decryption_table)
                hashValue=ct[-hash_len:]
                if is_recognizable(ct[:-hash_len], hashValue):
                    decrypted_plaintext[counter]=ct[:-hash_len]
                    continue
                else:
                    Flag=0
                    break
        else:
            Flag=0
        if Flag == 1:
            return [decrypted_plaintext,encryption_table]

def is_recognizable(candidate,h):
    """Validate hash value"""
    # hashValue=convertHashToString(hash_function(candidate))
    # if h==hashValue:
    if convertHashToString(hash_function(convertToBin(candidate)))==h:
        return True
    else:
        return False

def convertHashToString(hashVal):
    """Mapping hash contaning 0s and 1s to A and B"""
    d={
        # mapping 0 to A and 1 to B, length of hash remains the same
        "0":"A",
        "1":"B",
    }
    s=''.join(d[hashVal[i]] for i in range(0,len(hashVal)))
    return s

decrypted_plaintext = []
plainTexts = []
encryptedListData = []
brute_force=False

print()
characters = 'ABC'
string_length=64

for i in range(5):
    plainTexts.append(''.join(random.choice(characters) for _ in range(string_length)))

encryption_table, tempvar = create_tables()
it=0

for plainText in plainTexts:
    h=hash_function(convertToBin(plainText))
    h=convertHashToString(h)
    print(f"Random String {it+1}    :",plainText)
    print(f"Generated Hash {it+1}   :",h)
    e=encrypt(plainText+h,encryption_table)
    encryptedListData.append(e)
    print(f"Encrypted String {it+1} :",e)
    print()
    it+=1

print("\nDoing brute force attack on ciphertexts...")
result = brute_force_attack(encryptedListData)

if result:
    candidate_plaintext, candidate_table = result
    print("\nBrute-Force Attack Successful!")
    brute_force=True
    print("\nDiscovered Key:", candidate_table)
    print("Key that was used:",encryption_table)
    print("Keys equal: \n",candidate_table==encryption_table)
    ct=1
    for originalText in candidate_plaintext:
        print(f"Decrypted String {ct} using discovered key:", originalText)
        ct+=1
    
else:
    print("\nBrute-Force Attack Failed. Unable to find a recognizable plaintext.")

print("\n\nDecryption Key w/o hacking = ",tempvar)

it=0
for cipherText in encryptedListData:
    it+=1
    e=decrypt(cipherText[:string_length],tempvar)
    print("Ciphertext is: ",cipherText[:string_length])
    print(f"Decrypted String {it} w/o Hacking :",e)
    decrypted_plaintext.append(e)


print("\nStarting Validation....\n")
ct=1
for i,j in zip(plainTexts,decrypted_plaintext):
    if (i==j):
        print(f"String {ct} - Matching successful! \u279C  {i}")
        ct+=1
    else:
        break
else:
    if brute_force:
        print("Succesfully decrypted all strings and succesful brute force attack as well !!")
    else:
        print("Succesfully decrypted all strings!!")