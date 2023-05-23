import paho.mqtt.client as mqtt
import time 
import pyDH 
import random
import hashlib
import base64
import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Hash import SHA512
from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA 
from hashlib import sha512
import rsa
from Crypto.Signature import pkcs1_15

# Author : Saksham Kaushik 

#the code and set up for publish and subscriber is inspired from the below git repo.
#https://github.com/amankanwar/PAHO-MQTT.git
#AES encryption and Digital signature implementation has been inspired by:
#https://www.youtube.com/watch?v=SoeeCg04-FA&ab_channel=PracticalPythonSolutions-ByPaulMahon
#https://cryptobook.nakov.com/digital-signatures/rsa-sign-verify-examples
#https://www.youtube.com/watch?v=z-EnysBSstA&ab_channel=BaliCoding 






#create the client 
client = mqtt.Client()

#AES encryption with 256bit key
#create hash of a password and use as encryption key 
password = "mypass".encode()
#key is 32bytes/256 bits
cipher_key = hashlib.sha256(password).digest() 
mode = AES.MODE_CBC    #cipherblockchain mode
init_vector = bytes('this ist my proj','utf-8') 



#create the public-private key pair 
#.d and .n are the private key
#key_pair object contains the public and private key
key_pair= RSA.generate(bits = 2048)
#write the private key to a file 
priv_key = key_pair.export_key('PEM')
key_file = open('priv.bin','wb')
key_file.write(priv_key)
key_file.close()



#write the public key to a file
#.e and .n are the public key
p = key_pair.e
pub_key = key_pair.public_key().export_key("PEM")
pub_file = open('pub.txt','wb')
pub_file.write(pub_key)
pub_file.close()

exit = True


#generate a digital signature,
#returns a 128 bytes signature written to a file
def sign_message(message):
    key = RSA.import_key(open('priv.bin').read())
    hash = SHA256.new(message)
    sign = pkcs1_15.new(key).sign(hash)
    sign_file = open('sign_final.pem','wb')
    sign_file.write(sign)
    sign_file.close()
    return sign


#pad the message to fit the block size for AES-256
def message_pad(message):
    pad = b" "
    while len(message)%16 != 0:
        message = message + pad
    return message


#The method below should return an excrypted payload
def encrypt_payload(payload, enc_key,iv):
    cipher = AES.new(enc_key,mode,iv)
    padded_msg = message_pad(payload) 
    cipher_text = cipher.encrypt(padded_msg)
    return cipher_text
    

#this is the callback for data that has been published
def on_publish(client, userdata, message_id):
    print("payload published: ", str(message_id))


#the callback that confirms the connection to host
def on_connect(pvtClient,userdata,flags,ret_code):   # call back for the connection acknowledgement
    global disconnect

    if(ret_code == 0):  # on successful connection
        print("publisher Connected")  # printing the data
        print("Connection to client established!") 
        disconnect = False


    elif(ret_code ==1): #if connection fails
        print("Connection Error!")  
        client.disconnect()
        disconnect = True


#call back for the logs generation
def on_log(client, userdata, level, log):   
    print("Logs: "+str(log))                
                                            

#callback for disconnect
def on_disconnect(pvtClient, userdata, rc): 
    print("disconnecting reason  " +str(rc))
    client.disconnect()



#setting the callbacks
client.on_publish       = on_publish
client.on_connect       = on_connect
client.on_log           = on_log
client.on_disconnect    = on_disconnect


#localhost is the mosquitto broker
host       = "localhost"
#host = "broker.hivemq.com"
port       = 1883
keepAlive  = 60

#connect the client with the host (broker)
client.connect(host,port,keepAlive)


#starting the client loop, it will also activate the required callbacks
client.loop_start();       
#this gives a bit of time to setup our connection 
time.sleep(3)               


#details for the connection
topic_name = "saksh/test"
QOS        = 2                 
retain     = True


#upon successful connection, we run the loop which publishes the message 
#after encrypting and generating digital signature
while(disconnect == False):   
    time.sleep(.8)          
     
    cur_time = datetime.datetime.now()
    payload = input("\nMessage: ")

    #the msg. is being encrypted
    payload_bytes = bytes(payload, 'utf-8')
    out_msg = encrypt_payload(payload_bytes,cipher_key,init_vector)

    #the message is signed 
    signature = sign_message(out_msg)

    # publishing the message (payload)
    client.publish(topic_name,out_msg,QOS,retain)  

    #printing the time for measurements
    print("-------time------->",cur_time)
    print('------------------')
    print("this is the encrypted message------> ",out_msg)
    print('------------------')
    
    #if user enters "quit", then disconnect the client 
    if(payload == "quit"):   
        client.disconnect()

#stops the client loop 
client.loop_stop()  
