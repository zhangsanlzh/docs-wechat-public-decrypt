from base64 import b64encode
from base64 import b64decode
from Crypto.Cipher import AES
from enum import Enum

class EncryptMode(Enum):
    CBC = AES.MODE_CBC
    ECB = AES.MODE_ECB

encrypt_mode = EncryptMode.CBC

class Encrypt:
    def __init__(self, key, iv = ''):
        self.key = self.padding_pkcs5(key).encode('utf-8')
        if encrypt_mode == EncryptMode.CBC:
            self.iv = self.padding_zero(iv[:16], 16).encode('utf-8')

    def padding_zero(self, text, length:int):
        '''padding with \0'''
        while len(text) % length != 0:
            text += '\0'
        return str(text)

    # @staticmethod
    def padding_pkcs7(self, text, block_size:int = 16):
        """
        明文使用PKCS7填充
        """
        length = len(text)
        bytes_length = len(text.encode('utf-8'))
        padding_size = length if (bytes_length == length) else bytes_length
        padding = block_size - padding_size % block_size
        padding_text = chr(padding) * padding
        self.coding = chr(padding)
        return text + padding_text
    
    def padding_pkcs5(self, text):
        '''padding with pkcs5'''
        return self.padding_pkcs7(text, 16)

    def aes_encrypt(self, content):
        """
        AES加密
        """
        if encrypt_mode == EncryptMode.CBC:
            cipher = AES.new(self.key, encrypt_mode.value, self.iv)
        elif encrypt_mode == EncryptMode.ECB:
            cipher = AES.new(self.key, encrypt_mode.value)
        
        # 处理明文
        content_padding = self.padding_pkcs5(content)
        # 加密
        encrypt_bytes = cipher.encrypt(content_padding.encode('utf-8'))
        # 重新编码
        result = str(b64encode(encrypt_bytes), encoding='utf-8')
        return result
        
    def aes_decrypt(self, content):
        """                
        AES解密
        """
        if encrypt_mode == EncryptMode.CBC:
            cipher = AES.new(self.key, encrypt_mode.value, self.iv)
        elif encrypt_mode == EncryptMode.ECB:
            cipher = AES.new(self.key, encrypt_mode.value)
        content = b64decode(content)
        text = cipher.decrypt(content).decode('utf-8')
        return text.rstrip(self.coding)

def readFile(path:str):
    result = ""
    with open(path, encoding='utf-8') as f:
        lines = f.readlines()
    for item in lines:
        result += str(item)
    return result

def writeOutput(fileName, content):
    with open(fileName, 'w', encoding='utf-8') as f:
        f.writelines(content)

if __name__ == '__main__':

    # 密钥，可以是任意的字符
    key = "mykey"

    # 长度可以超过 16，构造函数截取前 16 个字符作为 iv，不够也会补位
    iv = '20230717'

    if encrypt_mode == EncryptMode.CBC:
        a = Encrypt(key=key, iv=iv)
    elif encrypt_mode == EncryptMode.ECB:
        a = Encrypt(key=key)

    content = readFile('docs.txt')
    print(content)

    e = a.aes_encrypt(content)
    d = a.aes_decrypt(e)
    # print("加密:\n", e)
    # print("解密:\n", d)
    writeOutput('encrypt.txt', e)
    writeOutput('output.txt', d)