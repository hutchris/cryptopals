from cryptopals import CryptoBase
from base64 import b64encode,b64decode

class Ex9(CryptoBase):
    def __init__(self):
        self.get_inputs('exercise9')

    def do(self):
        inputB = self.conv_str_to_bytes(self.input)
        out = self.aes.pad_bytes(inputB,20)
        self.result = b64encode(out).decode()

class Ex10(CryptoBase):
    def __init__(self):
        self.get_inputs('exercise10')

    def do(self):
        self.result = "placeholder"