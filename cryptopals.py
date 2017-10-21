import yaml
from base64 import b64encode,b64decode

class CryptoBase(object):
    commonLetters = 'ETAOIN SHRDLUetaoinshrdlu'
    commonLettersBts = commonLetters.encode()
    engStrRatio = 0.66

    def get_inputs(self,exercise):
        inputs = yaml.load(open('inputs.yaml','r').read())
        self.input = inputs[exercise]['input']
        self.expected = inputs[exercise]['expected']
        if self.expected is None:
            self.outputType = inputs[exercise]['outputType']

    def do(self):
        pass

    def check_result(self):
        self.do()
        success = False
        report = "Input: {i}\nResult: {r}\nExpected Result: {er}".format(i=self.input,r=self.result,er=self.expected)
        if self.result == self.expected:
            success = True
        return(report,success)

    def conv_hex_to_bytes(self,h,bitLength=8):
        if not isinstance(h,str):
            raise(Exception("Need inputs in string"))
        ch = self.conv_str_to_chunks(h,int(bitLength/4))
        temp = []
        for c in ch:
            temp.append(int(c,16))
        bts = bytes(temp)
        return(bts)

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

    def conv_str_to_chunks(self,s,size):
        out = [s[i:i+size] for i in range(0,len(s),size)]
        return(out)

    def conv_hex_to_ascii(self,h):
        if not isinstance(h,str):
            raise(Exception("Need inputs in string"))
        ch = self.conv_str_to_chunks(h,2)
        bts = "".join([chr(int(x,16)) for x in ch])
        return(bts)

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
