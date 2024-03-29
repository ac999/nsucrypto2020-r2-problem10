#!/usr/bin/python3

#https://nsucrypto.nsu.ru/archive/2020/round/2/task/10

import struct
import os
from collections import defaultdict

BYTE_ORDER = 'big'

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
            self.iv         = Noneresult.append(polynomial)
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

    message0_plain_payload  = "Hello, Bob! How's everything?".encode("utf-8")
    message0                = Message(os.path.join(DIRPATH, FILENAME0))
    known_stream        = byte_xor(message0_plain_payload, message0.en_payload)
    '''Replaced "Hello, Bob! How’s everything?"
        with    "Hello, Bob! How's everything?'''
    '''list of messages that use the same iv as 0.message'''
    possible_attack = [os.path.join(DIRPATH, k) for k, v in dict_iv.items() if
    v==dict_iv['0.message'] and k != '0.message']
    '''only messages with payload smaller or equal than 0.message's payload'''
    possible_attack = [k for k in possible_attack if get_payload_size(k) <=\
    get_payload_size(os.path.join(DIRPATH, '0.message') ) ]
    '''recover the messages by xoring the encrypted payload with the known_stream'''
    for message in possible_attack:
        _message            = Message(message)
        decrypted_payload   = byte_xor(_message.en_payload, known_stream)\
        .decode("utf-8")

        print("\'{}\': \'{}\'".format(_message.name, decrypted_payload))

def split_in_blocks(payload):
    return [int.from_bytes(payload[i:i+16], BYTE_ORDER)
    for i in range(0, len(payload), 16)]

def int_to_bytes(x: int):
    return x.to_bytes((x.bit_length() + 7) // 8, BYTE_ORDER)

def zip_longest(iter1, iter2, fillValue = 0):

    for i in range(max(len(iter1), len(iter2))):
        if i >= len(iter1):
            yield (fillValue, iter2[i])
        elif i>= len(iter2):
            yield (iter1[i], fillValue)
        else:
            yield (iter1[i], iter2[i])

class Polynomial():

    def __init__(self):
        self.coefficients = list()

    def __repr__(self):
        '''Return the canonical string representation of the polynomial'''
        return "Polynomial {}".format(str(self.coefficients))

    def __call__(self, X):
        result = 0
        for coeff in self.coefficients:
            # in GF(2), * is considered 'and'
            # in GF(2), + is considered 'XOR'
            result = result & X ^ coeff
        return result

    def degree(self):
        return len(self.coefficients)

    def __add__(self, polynomial):

        c1 = self.coefficients[::-1]
        c2 = polynomial.coefficients[::-1]
        # in GF(2), + is considered 'XOR'
        result = list(map(lambda x: x[0] ^ x[1], zip_longest(c1, c2)))
        return PolynomialCoefficients(result[::-1])

    def addInteger(self, x: int):
        self.coefficients.append(x)

    def derivative(self):
        derived_coeffs = []
        exponent = len(self.coefficients) - 1
        for i in range(len(self.coefficients)-1):
            derived_coeffs.append(self.coefficients[i] & exponent)
            exponent -= 1
        return PolynomialCoefficients(derived_coeffs)

    def __str__(self):
        res = ""
        degree = len(self.coefficients) - 1
        res += str(self.coefficients[0]) + "x^" + str(degree)
        for i in range(1, len(self.coefficients)-1):
            coeff = self.coefficients[i]
            if coeff < 0:
                res += " - " +  str(-coeff) + "x^" + str(degree - i)
            else:
                res += " + " +  str(coeff) + "x^" + str(degree - i)

        if self.coefficients[-1] < 0:
            res += " - " + str(-self.coefficients[-1])
        else:
            res += " + " + str(self.coefficients[-1])

        return res

class PolynomialCoefficients(Polynomial):

    def __init__(self, coefficients):
        self.coefficients = coefficients

class PolynomialMessage(Polynomial):

    def __init__(self, msg: Message):
        '''Create the polynom based on the message'''
        self.L = int_to_bytes(len(msg.header)) +\
        int_to_bytes(len(msg.en_payload))
        self.L = split_in_blocks(self.L)[0]
        self.coefficients = split_in_blocks(msg.en_payload)
        self.A1 = split_in_blocks(msg.header)[0]
        self.A2 = split_in_blocks(msg.iv)[0]
        self.coefficients.insert(0, self.A2)
        self.coefficients.insert(0, self.A1)
        self.coefficients.append(self.L)

EPSILON = 0.0001

# https://gist.github.com/unc0mm0n/117617351ecd67cea8b3ac81fa0e02a8
# Recursively calculates the gcd of two polynomials in given finite field p
# (for prime p)
# Polynomials are given by a list of coefficients from largest to smallest.
# When p=0 tries to calculate the gcd in R, percision makes this difficult,
# and is not reliable.
def gcd(f, g, p=2, verbose=False):
    if (len(f)<len(g)):
        return gcd(g,f,p, verbose)

    r = [0]*len(f)
    r_mult = reciprocal(g[0], p) * f[0]

    for i in range(len(f)):
        if (i < len(g)):
            r[i] = f[i] - g[i]*r_mult
        else:
            r[i] = f[i]
        if (p != 0):
            r[i] %= p

    if(verbose):
        print(f,'by',g,'got',r)

    while (abs(r[0])<EPSILON):
        r.pop(0)
        if (len(r) == 0):
            return g

    return gcd(r, g, p, verbose)

# returns reciprocal of n in finite field of prime p, if p=0 returns 1/n#
def reciprocal(n, p=2):
    if (p == 0):
        return 1/n
    for i in range(p):
        if (n*i)%p == 1:
            return i
    return None


def berlekamp(poly: Polynomial, c: int):
    # check if f is square free:
    gcd()
    pass

def task2():
    print("\nTask2\n")

    DIRPATH     = "./AES-GCM-Task_2/"
    FILENAMES   = os.listdir(DIRPATH)

    dict_iv = dict()

    for FILENAME in FILENAMES:
        message = Message(os.path.join(DIRPATH, FILENAME))
        dict_iv[os.path.join(DIRPATH, FILENAME)] = message.iv

    #Find IV collisions on the messages from Task_2
    dict_iv = find_Collision_On_Dictionary(dict_iv)

    iv_reuse = [tuple(value) for key, value in dict_iv.items()]

    for pair in iv_reuse:
        msg1 = Message(pair[0])
        msg2 = Message(pair[1])
        print("Same IV on \'{}\' and \'{}\'".format(msg1.name, msg2.name))
        P1 = PolynomialMessage(msg1)
        P2 = PolynomialMessage(msg2)

        tag1 = split_in_blocks(msg1.auth_tag)[0]
        tag2 = split_in_blocks(msg2.auth_tag)[0]
        P = Polynomial()
        P = P1 + P2
        P.addInteger(tag1+tag2)
        # print(P)
        # print(gcd(P.coefficients, P.derivative().coefficients), verbose = True)
        # Compute H by finding root of
        # P1(X) + P2(X) + tag1 + tag2

        # After finding H,
        # Compute S by the following relation
        # S = P1(H) + tag1

        # Create tag for wanted criphertext

def task3():
    print("\nTask3\n")

    DIRPATH     = "./AES-GCM-Task_3/"
    FILENAMES   = os.listdir(DIRPATH)
    dict_header = dict()
    dict_iv = dict()
    dict_auth_tag = dict()
    dict_payload_len = dict()
    x = dict()

    for FILENAME in FILENAMES:
        message = Message(DIRPATH+FILENAME, task3 = True)
        dict_header[FILENAME]   = message.header
        dict_iv[FILENAME]       = message.iv
        dict_auth_tag[FILENAME] = message.auth_tag
        dict_payload_len[FILENAME]= len(message.en_payload)
        x[FILENAME]             = message.X

    print("HEADER collisions: {}".format(find_Collision_On_Dictionary(dict_header)))
    print("IV collisions: {}".format(find_Collision_On_Dictionary(dict_iv)))
    print("AUTH_TAG collisions: {}".format(find_Collision_On_Dictionary(dict_auth_tag)))
    print("X collisions: {}".format(find_Collision_On_Dictionary(x)))
    print("Payload of same length: {}".format(find_Collision_On_Dictionary(dict_payload_len)))

task1()

task2()

task3()
