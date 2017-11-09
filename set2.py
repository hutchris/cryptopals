from cryptopals import CryptoBase
from base64 import b64encode,b64decode

class Ex9(CryptoBase):
    def __init__(self):
        self.get_inputs('exercise9')

    def do(self):
        inputB = self.conv_str_to_bytes(self.input)
        out = self.pad_bytes(inputB,20)
        self.result = b64encode(out).decode()

class Ex10(CryptoBase):
    def __init__(self):
        self.get_inputs('exercise10')

    def do(self):
        inputB = b64decode(self.input['text'])
        key = self.input['key'].encode()
        raw = self.aes.cbc_dec(key=key,b=inputB,iv=bytes([0]*16))
        self.result = raw.decode()

class Ex11(CryptoBase):
    def __init__(self):
        self.get_inputs('exercise11')

    def do(self):
        count = 0
        for i in range(20):
            b = self.input.encode()
            c = self.aes.rand_enc(b)
            if self.aes.mode_oracle(c) == "ECB":
                count += 1
        if count in range(5,15):
            self.result = True
        else:
            self.result = False

class Ex12(CryptoBase):
    def __init__(self):
        self.get_inputs('exercise12')
        self.key = self.gen_rand(16)

    def do(self):
        unknown = b64decode(self.input)
        #find block size:
        possSizes = [16,32,64]
        noPlain = self.aes.rand_enc_append(b'',unknown,self.key)
        for i in possSizes:
            c = self.aes.rand_enc_append(b'A'*i,unknown,self.key)
            cChunks = self.conv_bytes_to_chunks(c,i)
            noPlainChunks = self.conv_bytes_to_chunks(noPlain,i)
            if noPlainChunks[0] == cChunks[1]:
                self.blockSize = i
                break
        #detect ecb
        largePlain = self.get_other_input('exercise11').encode()
        if self.aes.mode_oracle(self.aes.rand_enc_append(largePlain,unknown,self.key)) == 'ECB':
            self.ecb = True
        #Discover unknown text:
        known = b'A'*(len(self.pad_to_mod(unknown,self.blockSize)))
        for i in range(len(unknown)):
            known = known[1:]
            cipher = self.aes.rand_enc_append(known,unknown,self.key)
            knownBlock = cipher[:len(known)+1]
            for i in range(255):
                tempknown = known+bytes([i])



