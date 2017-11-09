import yaml
import random
from base64 import b64encode,b64decode
from Crypto.Cipher import AES

class Converters(object):
    def conv_hex_to_bytes(self,h,bitLength=8):
        if not isinstance(h,str):
            raise(Exception("Need inputs in string"))
        ch = self.conv_str_to_chunks(h,int(bitLength/4))
        temp = []
        for c in ch:
            temp.append(int(c,16))
        bts = bytes(temp)
        return(bts)

    def conv_bytes_to_hex(self,b):
        if not isinstance(b,bytes):
            raise(Exception("Need input as bytes plz"))
        out = ''
        for c in b:
            out += hex(c)[2:].zfill(2)
        return(out)

    def conv_str_to_bytes(self,s,form='ascii'):
        if not isinstance(s,str):
            raise(Exception("Need inputs in string"))
        bts = s.encode(form)
        return(bts)

    def conv_hex_to_b64(self,h):
        if isinstance(h,str):
            bts = bytes.fromhex(h)
        elif isinstance(h,hex):
            s = h[2:]
            bts = bytes.fromhex(s)
        else:
            raise(Exception("Need input as string or hex plz"))
        b64 = b64encode(bts)
        return(b64)

    def conv_str_to_chunks(self,s,size):
        if not isinstance(s,str):
            raise(Exception("Need inputs in string"))
        out = [s[i:i+size] for i in range(0,len(s),size)]
        return(out)

    def conv_bytes_to_chunks(self,b,size):
        if not isinstance(b,bytes):
            raise(Exception("Need input as bytes plz"))
        out = [b[i:i+size] for i in range(0,len(b),size)]
        return(out)

    def conv_hex_to_ascii(self,h):
        if not isinstance(h,str):
            raise(Exception("Need inputs in string"))
        ch = self.conv_str_to_chunks(h,2)
        bts = "".join([chr(int(x,16)) for x in ch])
        return(bts)

    def conv_int_to_bin(self,i,bitLength=8):
        if not isinstance(i,int):
            raise(Exception("Need input in int"))
        out = bin(i)[2:].zfill(8)
        return(out)

    def conv_bytes_to_bin(self,b):
        if not isinstance(b,bytes):
            raise(Exception("Need input as bytes plz"))
        out = ''
        for i in b:
            out += self.conv_int_to_bin(i)
        return(out)

class Finders():
    def find_english_ratio(self,b):
        if not isinstance(b,bytes):
            raise(Exception("Need input as bytes plz"))
        o = [c for c in b if c in self.commonLettersBts]
        return(len(o)/len(b))

    def find_best_england(self,cipherList):
        #cipherList is list of dicts. Minimum: {'text':'ciphertextinbytes'}
        #Other keys are reserved
        if not isinstance(cipherList,list):
            raise(Exception("Need input as list plz"))
        max = 0
        for cipher in cipherList:
            cipher['ratio'] = self.find_english_ratio(cipher['text'])
            if cipher['ratio'] > max:
                out = cipher
                max = cipher['ratio']
        return(out)

    def find_single_key_xor(self,cipherBytes):
        if not isinstance(cipherBytes,bytes):
            raise(Exception("Need input as bytes plz"))
        possibles = []
        for i in range(255):
            xorKey = bytes([i] * len(cipherBytes))
            possibles.append({'text':self.perf_xor_bytes(cipherBytes,xorKey),'key':i})
        best = self.find_best_england(possibles)
        return(best)

    def find_hamming_dist(self,b_1,b_2):
        if not isinstance(b_1,bytes) or not isinstance(b_2,bytes):
            raise(Exception("Need inputs in bytes"))
        if len(b_1) != len(b_2):
            raise(Exception("Bytes not the same length"))
        bin_1 = self.conv_bytes_to_bin(b_1)
        bin_2 = self.conv_bytes_to_bin(b_2)
        count = 0
        for x,y in zip(bin_1,bin_2):
            if x != y:
                count += 1
        dist = count / len(bin_1)
        return(dist)

    def find_xor_keysize(self,b,sizeRange=range(2,40)):
        if not isinstance(b,bytes):
            raise(Exception("Need input as bytes plz"))
        low = 1
        for size in sizeRange:
            chunks = self.conv_bytes_to_chunks(b,size)
            goodChunks = [c for c in chunks if len(c) == len(chunks[0])]
            nChunks = len(goodChunks)
            dist = 0
            for i in range(0,nChunks-1):
                dist += self.find_hamming_dist(goodChunks[i],goodChunks[i+1])
            distAv = dist/nChunks
            if distAv < low:
                best = size
                low = distAv
        return(best)


class Functions():
    def perf_xor_hex(self,h_1,h_2):
        if not isinstance(h_1,str) or not isinstance(h_2,str):
            raise(Exception("Need inputs in string"))
        n_1 = int(h_1,16)
        n_2 = int(h_2,16)
        x = n_1 ^ n_2
        return(hex(x)[2:])

    def perf_xor_bytes(self,b_1,b_2):
        if not isinstance(b_1,bytes) or not isinstance(b_2,bytes):
            raise(Exception("Need inputs in bytes"))
        if len(b_1) != len(b_2):
            raise(Exception("Bytes not the same length"))
        temp = []
        for a,b in zip(b_1,b_2):
            temp.append(a^b)
        bts = bytes(temp)
        return(bts)

    def make_long_key(self,key,length):
        if not isinstance(key,bytes):
            raise(Exception("Need input as bytes plz"))
        if not  isinstance(length,int):
            raise(Exception("Need length as int plz"))
        newKey = key
        while len(newKey) < length:
            newKey += key
        newKey = newKey[:length]
        return(newKey)

    def perf_rpt_xor_bytes(self,b,key):
        if not isinstance(b,bytes) or not isinstance(key,bytes):
            raise(Exception("Need input and key as bytes plz"))
        longKey = self.make_long_key(key,len(b))
        out = self.perf_xor_bytes(b,longKey)
        return(out)

    def perf_transpose(self,b,length):
        if not isinstance(b,bytes):
            raise(Exception("Need b as bytes plz"))
        if not  isinstance(length,int):
            raise(Exception("Need length as int plz"))
        chunks = self.conv_bytes_to_chunks(b,length)
        out = []
        for i in range(length):
            out.append(bytes([c[i] for c in chunks if len(c) >= i + 1]))
        return(out)

    def gen_rand(self,length):
        if not isinstance(length,int):
            raise(Exception("Need length as int plz"))
        out = b''
        for i in range(length):
            out += bytes([random.randint(0,255)])
        return(out)

    def append_padding(self,b,frLen=None,baLen=None):
        if not isinstance(b,bytes):
            raise(Exception("Need b as bytes plz"))
        if frLen is None:
            frLen = random.randint(5,10)
        if baLen is None:
            baLen = random.randint(5,10)
        front = self.gen_rand(frLen)
        back = self.gen_rand(baLen)
        out = front + b + back
        return(out)

    def pad_bytes(self,b,length):
        if not isinstance(b,bytes):
            raise(Exception("Need b as bytes plz"))
        pad_char = bytes([length - len(b)])
        while len(b) < length:
            b += pad_char
        return(b)

    def pad_to_mod(self,b,modLen):
        if not isinstance(b,bytes):
            raise(Exception("Need b as bytes plz"))
        if not isinstance(modLen,int):
            raise(Exception("Need mod length as int plz"))
        diff = modLen - (len(b) % modLen)
        if diff != 16:
            b = self.pad_bytes(b,len(b)+diff)
        return(b)


class AESFunctions(Converters,Finders,Functions):
    def ecb_dec(self,key,b):
        if not isinstance(b,bytes) or not isinstance(key,bytes):
            raise(Exception("Need b and key as bytes plz"))
        cipher = AES.new(key=key,mode=AES.MODE_ECB)
        raw = cipher.decrypt(b)
        return(raw)

    def ecb_enc(self,key,b):
        if not isinstance(b,bytes) or not isinstance(key,bytes):
            raise(Exception("Need b and key as bytes plz"))
        b = self.pad_to_mod(b,len(key))
        cipher = AES.new(key=key,mode=AES.MODE_ECB)
        raw = cipher.encrypt(b)
        return(raw)

    def cbc_dec(self,key,b,iv):
        if not isinstance(b,bytes) or not isinstance(key,bytes) or not isinstance(iv,bytes):
            raise(Exception("Need b and key and iv as bytes plz"))
        chunks = self.conv_bytes_to_chunks(b,len(key))
        out = b''
        for index,chunk in enumerate(chunks):
            if index == 0:
                prevChunk = iv
            else:
                prevChunk = chunks[index-1]
            raw = self.ecb_dec(b=chunk,key=key)
            out += self.perf_xor_bytes(raw,prevChunk)
        return(out)

    def cbc_enc(self,key,b,iv):
        if not isinstance(b,bytes) or not isinstance(key,bytes) or not isinstance(iv,bytes):
            raise(Exception("Need b and key and iv as bytes plz"))
        chunks = self.conv_bytes_to_chunks(b,len(key))
        if len(chunks[-1]) < len(key):
            chunks[-1] = self.pad_bytes(chunks[-1],len(key))
        out = b''
        prevChunk = iv
        for index,chunk in enumerate(chunks):
            toEnc = self.perf_xor_bytes(chunk,prevChunk)
            prevChunk = self.ecb_enc(b=toEnc,key=key)
            out += prevChunk
        return(out)

    def detect_ecb(self,b):
        chunks = self.conv_bytes_to_chunks(b,16)
        ecb = False
        for chunk in chunks:
            if chunks.count(chunk) > 1:
                ecb = True
        return(ecb)

    def rand_enc(self,plainBytes,length=16):
        if not isinstance(plainBytes,bytes):
            raise(Exception("Need plaintext as bytes plz"))
        key = self.gen_rand(length)
        iv = self.gen_rand(length)
        mode = random.randint(0,1)
        plainBytes = self.append_padding(plainBytes)
        if mode == 0:
            out = self.ecb_enc(key,plainBytes)
        else:
            out = self.cbc_enc(key,plainBytes,iv)
        return(out)

    def rand_enc_append(self,plainBytes,unknownBytes,key=None):
        if not isinstance(plainBytes,bytes) or not isinstance(unknownBytes,bytes):
            raise(Exception("Need plaintext and key as bytes plz"))
        if key is None:
            key = self.key
        toEnc = plainBytes+unknownBytes
        out = self.ecb_enc(key,toEnc)
        return(out)

    def mode_oracle(self,cipherBytes):
        if not isinstance(cipherBytes,bytes):
            raise(Exception("Need ciphertext as bytes plz"))
        if self.detect_ecb(cipherBytes):
            return("ECB")
        else:
            return("CBC")


class CryptoBase(Converters,Finders,Functions):
    commonLetters = 'ETAOIN SHRDLUetaoinshrdlu'
    commonLettersBts = commonLetters.encode()
    engStrRatio = 0.66
    aes = AESFunctions()

    def get_inputs(self,exercise):
        with open('inputs.yaml','r') as inputsFile:
            inputs = yaml.load(inputsFile)
        self.input = inputs[exercise]['input']
        self.expected = inputs[exercise]['expected']
        if self.expected is None:
            self.outputType = inputs[exercise]['outputType']

    def get_other_input(self,exercise):
        with open('inputs.yaml','r') as inputsFile:
            inputs = yaml.load(inputsFile)
        return(inputs[exercise]['input'])

    def do(self):
        pass

    def check_result(self):
        self.do()
        success = False
        report = {'input':self.input,'result': self.result,'expected result':self.expected}
        if self.result == self.expected:
            success = True
        return(report,success)

    

