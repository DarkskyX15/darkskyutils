# -*- coding: UTF-8 -*-
r'''
对RSA和AES的进一步封装, 以及一些有用的对象
#### 依赖第三方库`pycryptodome`
#### 避免在多个线程/进程中调用同一个实例
'''
from Crypto.Cipher import AES as _AES
from Crypto.Util.Padding import pad as _pad
from Crypto.Util.Padding import unpad as _unpad
from Crypto.PublicKey import RSA as _RSA
from Crypto.Cipher import PKCS1_v1_5 as _PKCS1
from Crypto import Random as _Random
from random import randint as _randint
from typing import Literal as _Literal, Any as _Any, Union as _Union, Dict as _Dict, Tuple as _Tuple, List as _List
from sky_lib.logger import LoggerWrapper as _LogW


class KeyPairError(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)

class RSAError(Exception):
    def __init__(self, msg: str, args: _Tuple) -> None:
        arg_str = ', '.join([str(arg) for arg in args])
        self.e_str = msg + arg_str
        super().__init__(msg + arg_str)
    
    def __repr__(self) -> str:
        return self.e_str
    
    def __str__(self) -> str:
        return self.e_str

class AESError(Exception):
    def __init__(self, msg: str, args: _Tuple) -> None:
        arg_str = ', '.join([str(arg) for arg in args])
        self.e_str = msg + arg_str
        super().__init__(msg + arg_str)
    
    def __repr__(self) -> str:
        return self.e_str
    
    def __str__(self) -> str:
        return self.e_str


class CLikeRandom:
    r'''仿C++/C的随机数生成器, 初始化参数:

    - `seed`: 指定随机数种子, 应为正整数, 相同随机数种子生成的随机数序列相同.
    未指定时随机生成'''
    def __init__(self, seed: int = None) -> None:
        if seed == None: self.seed = _randint(0, 32767)
        else: self.seed = seed
        self.t_rand = seed
    

    def rand(self, lt_bnd: int = 0, rt_bnd: int = 32768) -> int:
        r'''获取`[lt_bnd, rt_bnd]`范围内的随机数.
        
        `lt_bnd`限制`>= 0`, `rt_bnd`限制`<= 32768`'''
        if lt_bnd < 0:
            lt_bnd = 0
        if rt_bnd > 32768:
            rt_bnd = 32768
        self.t_rand = (self.t_rand * 64 + 13) % 1000000007
        output_r = self.t_rand % (rt_bnd - lt_bnd + 1) + lt_bnd
        return output_r

class RandomStr:
    r'''随机产生字符串, 初始化将自动生成一次字符串,`seed`应为正整数

    可以通过`regenerateStr`方法用新的`seed`重新生成字符串

    若未指定`seed`则使用`random.randint`生成随机字符串, 否则使用类 C/C++ 的`rand`方法生成随机字符串'''
    def __init__(self, length: int, seed: int = None) -> None:
        self.length = length
        self.seed = seed
        self.str_data = ''
        self.regenerateStr(length, seed)
    
    def __str__(self) -> str:
        return self.str_data


    def regenerateStr(self, length: int = None, seed: int = None) -> None:
        r'''根据`length`与`seed`重新生成随机字符串. 若值未给定, 默认为上次存储的值'''
        if length == None: length = self.length
        if seed == None: seed = self.seed
        self.seed, self.length = seed, length
        result = ''
        if seed == None:
            for i in range(length):
                result += chr(_randint(32, 126))
            self.str_data = result
        else:
            crand = CLikeRandom(seed)
            for i in range(length):
                result += chr(crand.rand(32, 126))
            self.str_data = result
    
    def exportToFile(self, file_path: str) -> None:
        r'''将字符串以`utf-8`编码导出至文件'''
        file = open(file_path, 'w', encoding = 'utf-8')
        file.write(self.str_data)
        file.close()

    def exportStr(self) -> str:
        r'''返回生成的随机字符串'''
        return self.str_data

class SimpleVertify:
    r'''简单的合法性验证, 在tcp模块中用于连接的验证'''
    def __init__(self, key: int, size: int = 16) -> None:
        self.core_key = key
        self.b_size = 16 if size < 16 else size
    
    def generateBytes(self) -> bytes:
        rint_l = []
        ckey = self.core_key
        for _ in range(self.b_size - 1):
            rint = _randint(0, 255)
            ckey ^= rint
            rint_l.append(rint)
        rint_l.append(ckey)
        return bytes(rint_l)

    def vertifyBytes(self, vbytes: bytes) -> bool:
        if len(vbytes) != self.b_size: return False
        ckey = vbytes[-1]
        for index in range(self.b_size - 2, -1, -1):
            ckey ^= vbytes[index]
        return (ckey == self.core_key)

class RSAKeyPair:
    r'''对RSA密钥对的进一步包装, 初始化时可以指定密钥'''
    def __init__(self, public_key: bytes = b'', private_key: bytes = b'') -> None:
        self.private_key = private_key
        self.public_key = public_key
    

    def randomGenerate(self, bits: int = 2048) -> None:
        r'''重新生成一对密钥, 长度为`bits`(以bit记)'''
        bits = max(1024, bits)
        self.pair = _RSA.generate(bits)
        self.public_key = self.pair.publickey().export_key()
        self.private_key = self.pair.export_key()

    def getPublicKey(self) -> bytes:
        return self.public_key
    
    def getPrivateKey(self) -> bytes:
        return self.private_key
    
    def copy(self) -> _Any:
        '''返回密钥对的副本'''
        return RSAKeyPair(self.public_key, self.private_key)

class RSA:
    r'''
    对RSA的进一步包装, 初始化参数:
    - `key_pair`: RSA密钥对.
    - `error`: 错误处理类型, 默认为`'strict'`, `'strict'`时遇异常会抛出, 否则直接输出错误内容.
    - `logw`(可选): 日志接口, 被指定时将把错误内容通过其输出, 否则直接使用`print`
    
    使用`encrypt`加密内容, 用`decrypt`解密内容
    #### 首次加密解密成功后使用的密钥不再改变
    '''
    def __init__(self, key_pair: RSAKeyPair, error: _Literal['strict', 'loose'] = 'strict', logw: _LogW = None) -> None:        
        self.key_pair = key_pair
        self.encrypter = None
        self.decrypter = None
        self.error: _Literal['strict', 'loose'] = error
        self.logw_put = True if logw != None else False
        self.logw = logw


    def encrypt(self, data: bytes) -> _Union[bytes, None]:
        r'''
        用RSA加密数据, `data`为`bytes`类型的数据
        
        若错误处理类型为`'strict'`, 则异常时抛出错误, 否则输出详细错误内容.

        密钥对中不存在公钥时, 抛出`KeyPairError`. 加密过程出错时抛出`RSAError`
        #### 无论错误处理类型, 遇异常时返回值为None
        '''
        try:
            if self.encrypter == None:
                # Check Key
                if self.key_pair.public_key == b'':
                    e_str = f'Can not encrypt using RSA: no public key in key_pair_object({self.key_pair})'
                    if self.error == 'strict':
                        raise KeyPairError(e_str)
                    else:
                        e_str = '[KeyPairError]' + e_str
                        if self.logw_put: self.logw.error(e_str)
                        else: print(e_str)
                    return None
                self.encrypter = _PKCS1.new(_RSA.import_key(self.key_pair.public_key))
            encrypted_data = self.encrypter.encrypt(data)
        except ValueError as e:
            e_str = f'Can not encrypt using RSA: '
            if self.error == 'strict':
                raise RSAError(e_str, e.args)
            else:
                e_str = '[RSAError]' + e_str
                err = RSAError(e_str, e.args)
                if self.logw_put: self.logw.error(err)
                else: print(err)
            return None
        else:
            return encrypted_data

    def decrypt(self, data: bytes) -> _Union[bytes, None]:
        r'''
        用RSA解密数据, `data`为`bytes`类型的数据
        
        若错误处理类型为`'strict'`, 则异常时抛出错误, 否则输出详细错误内容.

        密钥对中不存在私钥时, 抛出`KeyPairError`. 解密过程出错时抛出`RSAError`
        #### 无论错误处理类型, 遇异常时返回值为None
        '''
        try:
            if self.decrypter == None:
                # Check Key
                if self.key_pair.private_key == b'':
                    e_str = f'Can not decrypt using RSA: no private key in key_pair_object({self.key_pair})'
                    if self.error == 'strict':
                        raise KeyPairError(e_str)
                    else:
                        e_str = '[KeyPairError]' + e_str
                        if self.logw_put: self.logw.error(e_str)
                        else: print(e_str)
                    return None
                self.decrypter = _PKCS1.new(_RSA.import_key(self.key_pair.private_key))
            decrypted_data = self.decrypter.decrypt(data, _Random.new().read)
        except ValueError as e:
            e_str = f'Can not decrypt using RSA: '
            if self.error == 'strict':
                raise RSAError(e_str, e.args)
            else:
                e_str = '[RSAError]' + e_str
                err = RSAError(e_str, e.args)
                if self.logw_put: self.logw.error(err)
                else: print(err)
            return None
        else:
            return decrypted_data

class AES:
    r'''
    对AES的进一步包装, 初始化参数:
    - `key`: 加密用的密钥, 长度为`16`
    - `iv`: 默认的初始向量 (留空时随机生成), 
    - `error`: 指定错误处理类型, 默认为`'strict'`, 将默认抛出错误
    - `logw`: 传入`LoggerWrapper`实例以便将错误信息输出到日志
    #### 出于安全性考虑请勿用同一个实例(相同的`key`和`iv`)一次性加密大量数据
    '''
    def __init__(self, key: bytes, iv: bytes = None, error: _Literal['strict', 'loose'] = 'strict', logw: _LogW = None) -> None:
        rand_s = RandomStr(16)
        self._key_pt = _randint(0, 100)
        self._keys: _Dict[int, bytes] = {}
        for i in range(10):
            self._keys[_randint(0, 100)] = bytes(rand_s.exportStr(), 'utf-8')
            rand_s.regenerateStr()
        if len(key) > 16: key = key[:17]
        self._keys[self._key_pt] = key
        del key
        if iv == None:
            rand_s.regenerateStr()
            iv = bytes(rand_s.exportStr(), 'utf-8')
        self._default_iv = iv
        self._encrypter = _AES.new(self._keys[self._key_pt], _AES.MODE_CBC, iv)
        self._decrypter = _AES.new(self._keys[self._key_pt], _AES.MODE_CBC, iv)
        self._error: _Literal['strict', 'loose'] = error
        self._logw = logw
        self._use_logw = True if logw != None else False
    

    def exportIv(self) -> bytes:
        return self._default_iv

    def changeIv(self, iv: bytes) -> None:
        '''更改默认`iv`'''
        self._default_iv = iv
        self._encrypter = _AES.new(self._keys[self._key_pt], _AES.MODE_CBC, iv)
        self._decrypter = _AES.new(self._keys[self._key_pt], _AES.MODE_CBC, iv)

    def encrypt(self, data: bytes, iv: bytes = None) -> _Union[_Tuple[bytes, bytes], _Tuple[None, None]]:
        r'''
        将`data`通过AES加密, 若`iv`未被指定, 则使用初始化时的默认`iv`

        返回由加密过后的数据与`iv`组成的元组: `(encrypted, iv)`

        若错误处理类型为`'strict'`, 则抛出错误, 否则根据所给的方式直接输出, 同时返回`(None, None)`
        '''
        need_new = False if iv == None else True
        iv = iv if iv != None else self._default_iv
        try:
            padded_data = _pad(data, 16, 'pkcs7')
            if need_new:
                temp_en = _AES.new(self._keys[self._key_pt], _AES.MODE_CBC, iv)
                encrypted_data = temp_en.encrypt(padded_data)
            else:
                encrypted_data = self._encrypter.encrypt(padded_data)
        except ValueError as e:
            e_str = f'Can not encrypt using AES: '
            if self._error == 'strict':
                raise AESError(e_str, e.args)
            else:
                e_str = '[AESError]' + e_str
                err = AESError(e_str, e.args)
                if self._use_logw: self._logw.error(err)
                else: print(err)
            return None, None
        else:
            return (encrypted_data, iv)
    
    def decrypt(self, data: bytes, iv: bytes = None) -> _Union[_Tuple[bytes, bytes], _Tuple[None, None]]:
        r'''参数说明与`encrypt`完全相同, 但是`decrypt`对`data`进行解密'''
        need_new = True if iv != None else False
        iv = iv if iv != None else self._default_iv
        try:
            if need_new:
                temp_de = _AES.new(self._keys[self._key_pt], _AES.MODE_CBC, iv)
                decrypted_data = temp_de.decrypt(data)
            else:
                decrypted_data = self._decrypter.decrypt(data)
            unpadded_text = _unpad(decrypted_data, 16, 'pkcs7')
        except ValueError as e:
            e_str = f'Can not decrypt using AES: '
            if self._error == 'strict':
                raise AESError(e_str, e.args)
            else:
                e_str = '[AESError]' + e_str
                err = AESError(e_str, e.args)
                if self._use_logw: self._logw.error(err)
                else: print(err)
            return None, None
        else:
            return (unpadded_text, iv)

class ExAES:
    r'''
    为大量数据设计的AES加密类, 在指定数量的加密后会自动更换`iv`, 参数说明:
    - `key`: 加密用的密钥
    - `error`: 错误处理类型
    - `logw`: 日志输出的`LoggerWrapper`实例
    '''
    def __init__(self, key: bytes, error: _Literal['strict', 'loose'] = 'strict', logw: _LogW = None) -> None:
        self._aes = AES(key, None, error, logw)
        self._logw = logw
        self._error: _Literal['strict', 'loose'] = error
        self._use_logw = True if logw != None else False
    
    def encrypt(self, path: str, save_path: str, block_size: int = 512) -> _Union[_Tuple[_List[bytes], int], _Tuple[None, None]]:
        r'''
        从文件加密数据, 参数如下:
        - `path`: 需要加密的文件
        - `save_path`: 加密后数据写入的文件位置
        - `block_size`: 更换`iv`的块大小, 建议为`16`的倍数

        返回加密使用的`iv`的列表与块大小构成的元组, 遇到异常时返回值为`(None, None)`
        '''
        iv_list: _List[bytes] = []
        rand_s = RandomStr(16)
        block_size -= 1
        _iv = b''

        try:
            file = open(path, 'rb')
            save = open(save_path, 'wb')
        except Exception as e:
            e_str = f'Can not open\save file during encryption: '
            if self._error == 'strict': raise AESError(e_str, e.args)
            else:
                e_str = '[AESError]' + e_str
                err = AESError(e_str, e.args)
                if self._use_logw: self._logw.error(err)
                else: print(err)
            return None
        
        try:
            final_size = 0
            block = file.read(block_size)
            while block:
                _iv = bytes(rand_s.exportStr(), 'utf-8')
                coded = self._aes.encrypt(block, _iv)
                iv_list.append(_iv)
                final_size = max(final_size, len(coded[0]))
                save.write(coded[0])
                rand_s.regenerateStr()
                block = file.read(block_size)
        except Exception as e:
            e_str = f'Can not encrypt file using AES: '
            if self._error == 'strict': raise AESError(e_str, e.args)
            else:
                e_str = '[AESError]' + e_str
                err = AESError(e_str, e.args)
                if self._use_logw: self._logw.error(err)
                else: print(err)
            return None
        
        file.close()
        save.close()
        return iv_list, final_size
    
    def decrypt(self, path: str, save_path: str, args: _Tuple[_List[bytes], int]) -> bool:
        r'''
        从文件解密数据, 参数如下:
        - `path`: 需要解密的文件
        - `save_path`: 解密后数据写入的文件位置
        - `args`: 解密参数, 为`encrypt`方法的返回值

        返回是否成功执行, 遇异常时返回`False`
        '''
        iv_list = args[0]
        block_size = args[1]

        try:
            file = open(path, 'rb')
            save = open(save_path, 'wb')
        except Exception as e:
            e_str = f'Can not open/save file during decryption: '
            if self._error == 'strict': raise AESError(e_str, e.args)
            else:
                e_str = '[AESError]' + e_str
                err = AESError(e_str, e.args)
                if self._use_logw: self._logw.error(err)
                else: print(err)
            return False
        
        try:
            iv_pt = 0
            block = file.read(block_size)
            while block:
                decoded = self._aes.decrypt(block, iv_list[iv_pt])
                save.write(decoded[0])
                iv_pt += 1
                block = file.read(block_size)
        except Exception as e:
            e_str = f'Can not decrypt file using AES: '
            if self._error == 'strict': raise AESError(e_str, e.args)
            else:
                e_str = '[AESError]' + e_str
                err = AESError(e_str, e.args)
                if self._use_logw: self._logw.error(err)
                else: print(err)
            return False
        
        file.close()
        save.close()
        return True
    