
import paho.mqtt.client as mqtt
import time
import pyDH
import random
import hashlib
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA 
from Crypto.Signature import pkcs1_15

#Author : Saksham Kaushik

#the code for publish and subscriber is inspired from the below git repo.
#https://github.com/amankanwar/PAHO-MQTT.git
#AES encryption and RSA Digital signature implementation has been inspired by:
#https://www.youtube.com/watch?v=SoeeCg04-FA&ab_channel=PracticalPythonSolutions-ByPaulMahon
#https://cryptobook.nakov.com/digital-signatures/rsa-sign-verify-examples
#https://www.youtube.com/watch?v=z-EnysBSstA&ab_channel=BaliCoding 

client      =   mqtt.Client()
topicName   =   "saksh/test"
QOS         =   2


#AES encryption with 256bit key
#create hash of a password and use as encryption key 
password = "mypass".encode()
#key is 32bytes/256 bits
cipher_key = hashlib.sha256(password).digest() 
mode = AES.MODE_CBC    #cipherblockchain mode
init_vector = bytes('this ist my proj','utf-8') 


    

# connection callback
def on_connect(pvtClient,userdata,flags,ret_code):


    if(ret_code == 0):  #successful connection
        print("Connected to client! Return Code:"+str(ret_code)) 
        res = client.subscribe(topicName, QOS)  #gets the result from the callback
        

    elif(ret_code == 1): # in case of connection failure
        print("Authentication Error! Return Code: "+str(ret_code))  
        client.disconnect()

#this is a decrypt message function that can be called in the on_message outcall
#returns the decrypted text
def decrypt_message(msg,cipher_key,init_vector):
    
    cipher = AES.new(cipher_key,mode,init_vector)
    dec_message = cipher.decrypt(msg)
    return dec_message.strip() #this is to remove the excess padding

#this method reads the public key
def read_key():
    keyfile = open('C:\\Users\\saksh\\OneDrive\\Desktop\\Project\\mqtt\\pub.pem','r')
    pub = keyfile.readlines()[1:-1]
    pub_key = ""
    for x in pub:
        pub_key += x
    
    return bytes(pub_key,'utf-8')
    


#message callback runs when a message is published
def on_message(pvtClient, userdata, msg):
    
    print("\n+-------------------------------------------+")
    print("This is the recieved message---> ",msg.payload[:10])
    #verify the signature process
    #if the signature verification fails, the client is disconnected
    try:
        print('checking signature.....')
        pubkey = RSA.import_key(open('pub.txt').read())
        signdoc = open("sign_final.pem","rb")
        s = signdoc.read()
        signdoc.close()
        hash2 = SHA256.new(msg.payload)
        pkcs1_15.new(pubkey).verify(hash2,s)
    except:
        print("invalid signature")
        client.disconnect

    print('<<<<<valid signature>>>>>')
    #once signature is verified, decrypt the message
    decrypted_message = decrypt_message(msg.payload,cipher_key,init_vector)
    print("Decrypted payload: ",decrypted_message)
    print("Qos of message: "+str(msg.qos))
    print("Message Topic : "+str(msg.topic))
    print("Message retain: "+ str(msg.retain))
    print("+---------------------------------------------+\n")

    if(decrypted_message == "quit" ):
            client.disconnect()

#callback to generate the logs
def on_log(topic, userdata, level, log):
    print("Logs: "+str(log))



#set the callbacks
client.on_connect   =   on_connect
client.on_message   =   on_message
client.on_log       =   on_log

#setting up the  connection 
#host        = "broker.hivemq.com"
host = "localhost"
port        = 1883
keepAlive   = 60

#connect the client
client.connect(host,port,keepAlive) 

time.sleep(3)               


#we use this to make the client run indefinitely,until error
client.loop_forever() 


