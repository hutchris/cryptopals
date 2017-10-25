from cryptopals import CryptoBase
from base64 import b64encode,b64decode

class Ex1(CryptoBase):
    def __init__(self):
        self.get_inputs('exercise1')

    def do(self):
        bts = self.conv_hex_to_b64(self.input)
        self.result = bts.decode('ascii')

class Ex2(CryptoBase):
    def __init__(self):
        self.get_inputs('exercise2')

    def do(self):
        self.result = self.perf_xor_hex(self.input[0],self.input[1])

class Ex3(CryptoBase):
    def __init__(self):
        self.get_inputs('exercise3')

    def do(self):
        inputBts = self.conv_hex_to_bytes(self.input)
        best = self.find_single_key_xor(inputBts)
        self.result = [best['text'].decode(),best['key']]

class Ex4(CryptoBase):
    def __init__(self):
        self.get_inputs('exercise4')

    def do(self):
        bests = []
        for i in self.input:
            inputBts = self.conv_hex_to_bytes(i)
            bests.append(self.find_single_key_xor(inputBts))
        best = self.find_best_england(bests)
        self.result = [best['text'].decode(),best['key']]

class Ex5(CryptoBase):
    def __init__(self):
        self.get_inputs('exercise5')

    def do(self):
        key = self.conv_str_to_bytes(self.input['key'])
        textB = self.conv_str_to_bytes(self.input['text'])
        longKey = self.make_long_key(key,len(textB))
        outB = self.perf_xor_bytes(textB,longKey)
        self.result = self.conv_bytes_to_hex(outB)

class Ex6(CryptoBase):
    def __init__(self):
        self.get_inputs('exercise6')

    def do(self):
        inputB = b64decode(self.input)
        keySize = self.find_xor_keysize(inputB)
        tranList = self.perf_transpose(inputB,keySize)
        key = bytes()
        for l in tranList:
            xorResult = self.find_single_key_xor(l)
            key += bytes([xorResult['key']])
        longKey = self.make_long_key(key,len(inputB))
        outB = self.perf_xor_bytes(longKey,inputB)
        self.result = [key.decode(),outB.decode()]



            
