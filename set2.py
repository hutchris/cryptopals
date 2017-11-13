from random import choice
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
        AABlock = b'A'*(len(self.pad_to_mod(unknown,self.blockSize)))
        self.unknownPlain = b''
        for i in range(len(unknown)):
            smallAABlock = AABlock[i+1:]
            cipher = self.aes.rand_enc_append(smallAABlock,unknown,self.key)
            knownBlock = cipher[:len(AABlock)]
            knownPlain = smallAABlock + self.unknownPlain
            for n in range(255):
                tempKnown = knownPlain + bytes([n])
                tempCipher = self.aes.rand_enc_append(tempKnown,unknown,self.key)
                tempKnownBlock = tempCipher[:len(AABlock)]
                if tempKnownBlock == knownBlock:
                    self.unknownPlain += bytes([n])
                    break
        self.result = [self.blockSize,self.ecb,self.unknownPlain.decode()]

class Ex13(CryptoBase):
    def __init__(self):
        self.get_inputs('exercise13') 
        self.key = self.gen_rand(16)

    def do(self):
        #detect ecb and key length
        emailInput = "A"*256
        cipherText = self.enc_profile(emailInput,self.key)
        for i in [16,32,64]:
            chunks = self.conv_bytes_to_chunks(cipherText,i)
            doubles = [ch for ch in chunks if chunks.count(ch) > 1]
            if len(doubles) > 0:
                self.blockSize = i
                break
        #find how much text before our input
        chunks = self.conv_bytes_to_chunks(cipherText,self.blockSize)
        doubles = [ch for ch in chunks if chunks.count(ch) > 1]
        firstBlock = chunks.index(doubles[0])-1
        firstMixedBlock = chunks[firstBlock]
        for i in range(self.blockSize):
            emailInput = "A"*i
            cipherText = self.enc_profile(emailInput,self.key)
            tempChunks = self.conv_bytes_to_chunks(cipherText,self.blockSize)
            tempChunk = tempChunks[firstBlock]
            if tempChunk == firstMixedBlock:
                self.offset = i
                self.minChunks = len(tempChunks)
                break
        #find ciphertext to inject at end of ciphertext
        emailInput = (b"A"*self.offset + self.pad_to_mod(b'admin',self.blockSize)).decode()
        cipherText = self.enc_profile(emailInput,self.key)
        chunks = self.conv_bytes_to_chunks(cipherText,self.blockSize)
        inject = chunks[firstBlock+1]
        #find input length that results in no padding
        for i in range(self.offset,self.offset+self.blockSize+1):
            emailInput = "A"*i
            cipherText = self.enc_profile(emailInput,self.key)
            tempChunks = self.conv_bytes_to_chunks(cipherText,self.blockSize)
            if len(tempChunks) > self.minChunks:
                self.goodLen = i + len('user') - 1
                break
        #inject evil block to end of legit ciphertext
        user = ''
        for i in range(self.goodLen - len('@gmail.com')):
            user += bytes([choice(range(96,122))]).decode()
        emailInput = user + '@gmail.com'
        cipherText = self.enc_profile(emailInput,self.key)
        chunks = self.conv_bytes_to_chunks(cipherText,self.blockSize)
        chunks[-1] = inject
        evilCipherText = b''.join(chunks)
        self.profile = self.dec_profile(evilCipherText,self.key)
        self.result = self.profile['role']




