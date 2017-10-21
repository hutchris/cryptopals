from cryptopals import CryptoBase

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




            
