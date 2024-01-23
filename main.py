import math
import time
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
import requests
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import re
import json

API_URL = 'http://harpoon1.sabanciuniv.edu:9999/'

stuID = 28198 # Enter your student ID
stuIDB = 18007

def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y

def modinv(a, m):
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m

def Setup():
    global E
    E = Curve.get_curve('secp256k1')
    return E

def KeyGen(E, seed=None):
    n = E.order
    P = E.generator
    if seed:
        random.seed(seed)
    else:
        random.seed(121)
    sA = randint(1,n-1)
    QA = sA*P
    return sA, QA

def SignGen(message, E, sA):
    n = E.order
    P = E.generator
    k = 1748178 #randint(0,n-2)
    R = k * P
    r = R.x % n
    h = int.from_bytes(SHA3_256.new(r.to_bytes((r.bit_length()+7)//8, byteorder='big')+message).digest(), byteorder='big')%n
    s = (k - sA*h) % n
    return h, s

def SignVer(message, h, s, E, QA):
    n = E.order
    P = E.generator
    V = s*P + h*QA
    v = V.x%n
    h_ = int.from_bytes(SHA3_256.new(v.to_bytes((v.bit_length()+7)//8, byteorder='big')+message).digest(), byteorder='big')%n
    if h_ == h:
        return True
    else:
        return False



def IKRegReq(h,s,x,y):
    mes = {'ID': stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		
    if((response.ok) == False): print(response.json())

def IKRegVerify(code):
    mes = {'ID': stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    print(response.json())

def SPKReg(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json = mes)
    print(response.json())

def OTKReg(keyID,x,y,hmac):
    mes = {'ID': stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True


def ResetIK(rcode):
    mes = {'ID': stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetSPK(h,s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetOTK(h,s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json=mes)
    print(response.json())



############## The new functions of phase 2 ###############

E = Setup()
P, n = E.generator, E.order

#server's Identity public key
IKey_Ser = Point(13235124847535533099468356850397783155412919701096209585248805345836420638441, 93192522080143207888898588123297137412359674872998361245305696362578896786687, E)

def PseudoSendMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsg"), json = mes)
    print(response.json())


#Get your messages. server will send 1 message from your inbox
def ReqMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)
    print(response.json())
    if((response.ok) == True):
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["IK.X"], res["IK.Y"], res["EK.X"], res["EK.Y"]


#Get the list of the deleted messages' ids.
def ReqDelMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqDelMsgs"), json = mes)
    print(response.json())
    if((response.ok) == True):
        res = response.json()
        return res["MSGID"]

#If you decrypted the message, send back the plaintext for checking
def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {'IDA':stuID, 'IDB':stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)
    print(response.json())

def generateHMACKey(SPK_Pr, IKey_Ser):
    T = SPK_Pr * IKey_Ser
    U = b'TheHMACKeyToSuccess' + long_to_bytes(T.y) + long_to_bytes(T.x)
    hasher = SHA3_256.new()
    hasher.update(data=U)
    return hasher.digest()

def signWithHMAC(message, hmac_k):
    hasher = HMAC.new(key=hmac_k, digestmod=SHA256)
    hasher.update(msg=long_to_bytes(message))
    return hasher.hexdigest()


############## The new functions of phase 3 ###############

#Pseudo-client will send you 5 messages to your inbox via server when you call this function
def PseudoSendMsgPH3(h,s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsgPH3"), json=mes)
    print(response.json())

# Send a message to client idB
def SendMsg(idA, idB, otkID, msgid, msg, ikx, iky, ekx, eky):
    mes = {"IDA": idA, "IDB": idB, "OTKID": int(otkID), "MSGID": msgid, "MSG": msg, "IK.X": ikx, "IK.Y": iky, "EK.X": ekx, "EK.Y": eky}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SendMSG"), json=mes)
    print(response.json())    


# Receive KeyBundle of the client stuIDB
def reqKeyBundle(stuID, stuIDB, h, s):
    key_bundle_msg = {'IDA': stuID, 'IDB':stuIDB, 'S': s, 'H': h}
    print("Requesting party B's Key Bundle ...")
    response = requests.get('{}/{}'.format(API_URL, "ReqKeyBundle"), json=key_bundle_msg)
    print(response.json())
    if((response.ok) == True):
        print(response.json()) 
        res = response.json()
        return res['KEYID'], res['IK.X'], res['IK.Y'], res['SPK.X'], res['SPK.Y'], res['SPK.H'], res['SPK.s'], res['OTK.X'], res['OTK.Y']
        
    else:
        return -1, 0, 0, 0, 0, 0, 0, 0, 0


#Status control. Returns #of messages and remained OTKs
def Status(stuID, h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "Status"), json=mes)
    print(response.json())
    if (response.ok == True):
        res = response.json()
        return res['numMSG'], res['numOTK'], res['StatusMSG']


############## The new functions of BONUS ###############

# Exchange partial keys with users 2 and 4
def ExchangePartialKeys(stuID, z1x, z1y, h, s):
    request_msg = {'ID': stuID, 'z1.x': z1x, 'z1.y': z1y, 'H': h, 'S': s}
    print("Sending your PK (z) and receiving others ...")
    response = requests.get('{}/{}'.format(API_URL, "ExchangePartialKeys"), json=request_msg)
    if ((response.ok) == True):
        print(response.json())
        res = response.json()
        return res['z2.x'], res['z2.y'], res['z4.x'], res['z4.y']
    else:
        print(response.json())
        return 0, 0, 0, 0


# Exchange partial keys with user 3
def ExchangeXs(stuID, x1x, x1y, h, s):
    request_msg = {'ID': stuID, 'x1.x': x1x, 'x1.y': x1y, 'H': h, 'S': s}
    print("Sending your x and receiving others ...")
    response = requests.get('{}/{}'.format(API_URL, "ExchangeXs"), json=request_msg)
    if ((response.ok) == True):
        print(response.json())
        res = response.json()
        return res['x2.x'], res['x2.y'], res['x3.x'], res['x3.y'], res['x4.x'], res['x4.y']
    else:
        print(response.json())
        return 0, 0, 0, 0, 0, 0

# Check if your conference key is correct
def BonusChecker(stuID, Kx, Ky):
    mes = {'ID': stuID, 'K.x': Kx, 'K.y': Ky}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "BonusChecker"), json=mes)
    print(response.json())


# - PROJECT STEP 1 -
print("\n\n=========Step-1========")
#Registering the IK of Receiver
IK_Pr, IK_P = KeyGen(E)
h, s = SignGen(long_to_bytes(stuID), E, IK_Pr)
#IKRegReq(h, s, IK_P.x, IK_P.y)
CODE = 870932
IKRegVerify(CODE)
RCODE = 549103
#ResetIK(RCODE)

#Registering the SPK of Receiver
SPK_Pr, SPK_P = KeyGen(E)
spk_msg = long_to_bytes(SPK_P.x) + long_to_bytes(SPK_P.y)
h_spk, s_spk = SignGen(spk_msg, E, IK_Pr)
SPKReg(h_spk, s_spk, SPK_P.x, SPK_P.y)
#ResetSPK(h_spk, s_spk)

#Registering the OTKs of the Receiver

OTK_List = []
K_hmac = generateHMACKey(SPK_Pr, IKey_Ser) #Generating HMAC key for signing OTKs
for i in range(10):
    OTK_Pr, OTK_P = KeyGen(E, seed=i)
    OTK_List.append((OTK_Pr, OTK_P))
    otk_msg = int.from_bytes(long_to_bytes(OTK_P.x) + long_to_bytes(OTK_P.y), byteorder='big')
    HMAC_i = signWithHMAC(otk_msg, K_hmac)
    OTKReg(i, OTK_P.x, OTK_P.y, HMAC_i)


#ResetOTK(h, s)

# - PROJECT STEP 2 -
print("\n\n=========Step-2========")
def generateSessionKey(IK_P_b, SPK_Pr_a, EK_P_b, Ik_Pr_a, OTK_Pr_a):
    print("Generating session key / Phase 3...")
    T1 = IK_P_b * SPK_Pr_a
    T2 = EK_P_b * Ik_Pr_a
    T3 = EK_P_b * SPK_Pr_a
    T4 = EK_P_b * OTK_Pr_a
    U = long_to_bytes(T1.x) + long_to_bytes(T1.y) + long_to_bytes(T2.x) + long_to_bytes(T2.y) \
        + long_to_bytes(T3.x) + long_to_bytes(T3.y) + long_to_bytes(T4.x) + long_to_bytes(T4.y) + b'WhatsUpDoc'
    print(f"U is: {U} ")
    hasher = SHA3_256.new()
    hasher.update(data=U)
    K_s = hasher.digest()
    return K_s

def keyDerivationFunction(K_kdf):
    hasher = SHA3_256.new()
    hasher.update(data=(K_kdf + b'JustKeepSwimming'))
    K_enc = hasher.digest()

    hasher = SHA3_256.new()
    hasher.update(data=(K_kdf + K_enc + b'HakunaMatata'))
    K_HMAC = hasher.digest()

    hasher = SHA3_256.new()
    hasher.update(data=(K_enc + K_HMAC + b'OhanaMeansFamily'))
    K_kdf_next = hasher.digest()
    return K_enc, K_HMAC, K_kdf_next

def regenerateOTK(num_otk):
    missing_num = 10 - num_otk
    print(f"{missing_num} OTKs are re-generated!")
    for i in range(missing_num):
        OTK_Pr, OTK_P = KeyGen(E, seed=i)
        otk_msg = int.from_bytes(long_to_bytes(OTK_P.x) + long_to_bytes(OTK_P.y), byteorder='big')
        HMAC_i = signWithHMAC(otk_msg, K_hmac)
        OTKReg(i, OTK_P.x, OTK_P.y, HMAC_i)

print("Checking the inbox for incoming messages")

PseudoSendMsgPH3(h, s)
counter = 0
K_kdf = None
successful_messages = []
for i in range(5):
    print("***************************************************")
    ID_b, OTK_ID, MSGID, MSG, IK_X_b, IK_Y_b, EK_X_b, EK_Y_b = ReqMsg(h, s)
    IK_P_b = Point(IK_X_b, IK_Y_b, E)
    EK_P_b = Point(EK_X_b, EK_Y_b, E)
    print(f"I got this from client {ID_b}\n{MSG}\n")
    print("Converting message to bytes to decrypt it...\n")
    msg_bytes = long_to_bytes(MSG)
    print("Converted message is:", msg_bytes)

    print("Generating the key Ks, Kenc, & Khmac and then the HMAC value...")
    #def generateSessionKey(IK_P_b, SPK_Pr_a, EK_P_b, Ik_Pr_a, OTK_Pr_a):
    K_s = generateSessionKey(IK_P_b, SPK_Pr, EK_P_b, IK_Pr, OTK_List[0][OTK_ID])
    K_enc, K_hmac, K_kdf_next = keyDerivationFunction(K_s if counter == 0 else K_kdf)

    #msg = nonce∥ciphertext∥MAC
    nonce = msg_bytes[:8]
    cipher_text = msg_bytes[8:-32]
    MAC = msg_bytes[-32:]

    hmac = HMAC.new(key=K_hmac, msg=cipher_text, digestmod=SHA256).digest()
    print("hmac is:", hmac)
    if hmac == MAC:
        print("Hmac value is verified")
        AES_obj = AES.new(key=K_enc, mode=AES.MODE_CTR, nonce=nonce)
        plain_text = str(AES_obj.decrypt(cipher_text), "utf-8")
        print("The collected plaintext:", plain_text)
        Checker(stuID, stuIDB, MSGID, plain_text)
        successful_messages.append((MSGID, plain_text))
    else:
        print("Hmac value couldn't be verified")
        Checker(stuID, stuIDB, MSGID, "INVALIDHMAC")

    print("***************************************************\n\n")
    K_kdf = K_kdf_next
    counter += 1

deleted_messages = ReqDelMsg(h, s)
print("Checking whether there were some deleted messages!!")
print("==========================================")
for msg_id, plain_text in sorted(successful_messages):
    if msg_id in deleted_messages:
        print(f"Message {msg_id} - Was deleted by sender - X")
    else:
        print(f"Message {msg_id} - {plain_text} - Read")

# - PROJECT STEP 3 -
print("\n\n=========Step-3========")
print("I've already registered my IK, SPK, and OTKs in Step 1.")
print("I've already got 5 messages from pseudo-client in Step 2.")
print("=================================================")
print("Signing The stuIDB of party B with my private IK")
h_b, s_b = SignGen(long_to_bytes(stuIDB), E, IK_Pr)
print(f"h={h_b}")
print(f"s={s_b}")

#Requesting Pre-key bundle of the receiver
otk_id, IK_X_b, IK_Y_b, SPK_X_b, SPK_Y_b, h_spk_b, s_spk_b, OTK_X_b, OTK_Y_b = reqKeyBundle(stuID, stuIDB, h_b, s_b)

print("Verifying the server's SPK...")
SPK_msg_b = long_to_bytes(SPK_X_b) + long_to_bytes(SPK_Y_b)
IK_P_b = Point(IK_X_b, IK_Y_b, E) #Public Identity key of Client B
isSPKVerified = SignVer(SPK_msg_b, h_spk_b, s_spk_b, E, IK_P_b)
print(f"Is SPK verified? {isSPKVerified}")
if not isSPKVerified:
    sys.exit(-1)

OTK_P_b = Point(OTK_X_b, OTK_Y_b, E)
print("The other party's OTK public key is acquired from the server ...")

print("Signing my stuID with my private IK")
h, s = SignGen(long_to_bytes(stuID), E, IK_Pr)

K_kdf = None
counter = 0
for msg_id, message in successful_messages:
    EK_Pr, EK_P = KeyGen(E) #Ephemeral Key-pair
    print("Generating the KDF chain for the encryption and the MAC value generation")
    K_s = generateSessionKey(IK_P_b, SPK_Pr, EK_P, IK_Pr, EK_Pr)

    K_enc, K_HMAC, K_kdf_next = keyDerivationFunction(K_s if counter == 0 else K_kdf)
    cipher = AES.new(key=K_enc, mode=AES.MODE_CTR)
    nonce = cipher.nonce
    cipher_text = cipher.encrypt(message.encode("utf-8"))
    hmac = HMAC.new(key=K_HMAC, msg=cipher_text, digestmod=SHA256).digest()
    encrypted_msg = int.from_bytes(nonce + cipher_text + hmac, byteorder='big')
    print("Sending the message to the server, so it would deliver it to pseudo-client/user whenever it is active ...")
    SendMsg(stuID, stuIDB, otk_id, msg_id, encrypted_msg, IK_P.x, IK_P.y, EK_P.x, EK_P.y)
    K_kdf = K_kdf_next
    counter += 1
    print("\n")

K_hmac = generateHMACKey(SPK_Pr, IKey_Ser)
num_msg, num_otk, status_msg = Status(stuID, h, s)
print(status_msg)

regenerateOTK(num_otk)

print("Trying to delete OTKs...")
ResetOTK(h, s)

print("Trying to delete OTKs but sending wrong signatures...")
random_h, random_s = SignGen(long_to_bytes(11111), E, IK_Pr)
ResetOTK(random_h, random_s)
#regenerateOTK(0)

print("Trying to deleted SPK...")
ResetSPK(h, s)

print("Trying to delete Identity Key...")
ResetIK(0)









