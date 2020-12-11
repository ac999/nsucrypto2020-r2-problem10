#!/usr/bin/python3

#https://nsucrypto.nsu.ru/archive/2020/round/2/task/10

import struct
import os
from collections import defaultdict

def find_Collision_On_Dictionary(_dictionary):
    dd = defaultdict(set)

    for k, v in _dictionary.items():
        dd[v].add(k)

    dd = {k : v for k , v in dd.items() if len(v)>1}
    try:
        return dd
    except TypeError:
        print("[find_Collision_On_Dictionary] No collisions found on the provid\
        ed dictionary.")
        return dd

def byte_xor(a, b):
    return bytes([_a ^ _b for _a, _b in zip(a, b)])

def get_payload_size(filepath):
    return os.path.getsize(filepath)-36

class Message():
    def __init__(self, filepath, task3 = False):
        try:
            if (task3):
                with open(filepath, 'br') as FileObject:
                    self.name        = os.path.basename(filepath)
                    self.header      = FileObject.read(8)
                    self.iv          = FileObject.read(12)
                    self.X           = FileObject.read(8)
                    self.en_payload  = FileObject.read(get_payload_size(
                    filepath) - 8)
                    self.auth_tag    = FileObject.read(16)
            else:
                with open(filepath, 'br') as FileObject:
                    self.name        = os.path.basename(filepath)
                    self.header      = FileObject.read(8)
                    self.iv          = FileObject.read(12)
                    self.X           = None
                    self.en_payload  = FileObject.read(get_payload_size(
                    filepath) )
                    self.auth_tag    = FileObject.read(16)

        except Exception as e:
            print("[Message:__init__]: {}".format(e))
            self.name       = None
            self.header     = None
            self.iv         = None
            self.X          = None
            self.en_payload = None
            self.auth_tag   = None

    def print(self):
        if not self.X:
            print("File {}:\nHeader: {}\nIV: {}\nPayload: {}\nTag: {}\n"
            .format(self.name, self.header, self.iv, self.en_payload,
            self.auth_tag))
        else:
            print("File {}:\nHeader: {}\nIV: {}\nX: {}\nPayload: {}\nTag: {}\n"
            .format(self.name, self.header, self.iv, self.X, self.en_payload,
            self.auth_tag))

def task1():
    print("Task1\n")

    DIRPATH     = "./AES-GCM-Task_1/"
    FILENAME0   = "0.message"
    FILENAMES   = os.listdir(DIRPATH)

    dict_iv = dict()

    for FILENAME in FILENAMES:
        message             = Message(DIRPATH+FILENAME)
        dict_iv[FILENAME]   = message.iv

#Replaced "Hello, Bob! How’s everything?" with "Hello, Bob! How's everything?"
    message0_plain_payload  = "Hello, Bob! How's everything?".encode("utf-8")
    message0                = Message(os.path.join(DIRPATH, FILENAME0))
    known_stream        = byte_xor(message0_plain_payload, message0.en_payload)

    #list of messages that use the same iv as 0.message
    possible_attack = [os.path.join(DIRPATH, k) for k, v in dict_iv.items() if
    v==dict_iv['0.message'] and k != '0.message']
    #only messages with payload smaller or equal than 0.message's payload
    possible_attack = [k for k in possible_attack if get_payload_size(k) <=\
    get_payload_size(os.path.join(DIRPATH, '0.message') ) ]
    #recover the messages by xoring the encrypted payload with the known_stream
    for message in possible_attack:
        _message            = Message(message)
        decrypted_payload   = byte_xor(_message.en_payload, known_stream)\
        .decode("utf-8")

        print("\'{}\': \'{}\'".format(_message.name, decrypted_payload))


def split_in_blocks(payload):
    for i in range(len(payload)/16):
        print(i)

def task2():
    print("\nTask2\n")

    DIRPATH     = "./AES-GCM-Task_2/"
    FILENAMES   = os.listdir(DIRPATH)

    dict_iv = dict()

    for FILENAME in FILENAMES:
        message = Message(os.path.join(DIRPATH, FILENAME))
        dict_iv[os.path.join(DIRPATH, FILENAME)] = message.iv
        print("{} has blocks:".format(message.name))
        split_in_blocks(message.en_payload)

    #Find IV collisions on the messages from Task_2
    dict_iv = find_Collision_On_Dictionary(dict_iv)

    iv_reuse = [tuple(value) for key, value in dict_iv.items()]

    for pair in iv_reuse:
        msg1 = Message(pair[0])
        msg2 = Message(pair[1])
        print("Same IV on \'{}\' and \'{}\'".format(msg1.name, msg2.name))
        # Compute H
        # Compute S
        # Create tag for wanted criphertext

task1()

task2()

# print("\nTask3\n")
#
# DIRPATH     = "./AES-GCM-Task_3/"
# FILENAMES   = os.listdir(DIRPATH)
# x = dict()
#
# for FILENAME in FILENAMES:
#     message = Message(DIRPATH+FILENAME, task3 = True)
#     dict_header[FILENAME]   = message.header
#     dict_iv[FILENAME]       = message.iv
#     dict_auth_tag[FILENAME] = message.auth_tag
#     x[FILENAME]             = message.X
#
# print("HEADER collisions: {}".format(find_Collision_On_Dictionary(dict_header)))
# print("IV collisions: {}".format(find_Collision_On_Dictionary(dict_iv)))
# print("AUTH_TAG collisions: {}".format(find_Collision_On_Dictionary(dict_auth_tag)))
# print("X collisions: {}".format(find_Collision_On_Dictionary(x)))
