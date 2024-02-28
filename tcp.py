# -*- coding: UTF-8 -*-
r'''TCP相关的工具'''
from pickle import loads as _ploads, dumps as _pdumps
from time import sleep as _slp, perf_counter as _pfcnt
from typing import Literal as _Literal, Any as _Any, Union as _Union, Tuple as _Tuple, List as _List, Dict as _Dict
from json import dumps as _dumps, loads as _loads
from skyutils.encrypt import AES as _AES, RSA as _RSA, RSAKeyPair as _KeyPair, SimpleVertify as _SV, RandomStr as _RS
from skyutils.logger import LoggerWrapper as _LogW, ProcessLogger as _PL
from skyutils.config import Config
from socket import socket as _socket, AF_INET, AF_INET6, SOCK_STREAM
from base64 import b64decode as _b64de, b64encode as _b64en
from multiprocessing import Process, Queue, Value, Lock as _PLock
from threading import Thread as _Thread, Lock as _Lock
from queue import Empty, Queue as ThreadQueue

SERVING_SIDE = _Literal['server', 'client']
SYS_SIGN = _Literal['sockend', 'socketcell', 'sockethub', 'ctunnel', 'apps', 'server']

class PacketError(Exception):
    r'''在`Packeter`类的方法执行过程中遇错误默认抛出的错误类型'''
    def __init__(self, msg: str, args: _Tuple[object]) -> None:
        err_s = ', '.join([str(arg) for arg in args])
        self.estr = msg + err_s
        super().__init__(self.estr)
    
    def __str__(self) -> str:
        return self.estr
    
    def __repr__(self) -> str:
        return self.estr

class Coder:
    r'''
    Packeter加密所用的加密器的基类, 默认进行base64加密.

    继承并重写其中的`encrypt`和`decrypt`方法来实现自定义的加密器.

    正确的`encrypt`和`decrypt`方法接受`data`和`key`, 返回加密或解密后的数据(以`bytes`的形式).

    重写`__init__`方法时必须指定属性`self.name`(以`str`类型指定加密器的名字), 否则遇异常处理会出现错误.
    '''
    name = 'Default'
    def __init__(self, *args) -> None:
        self.name = 'Default'

    def encrypt(self, data: bytes, key: bytes = None) -> _Union[bytes, None]:
        return _b64en(data)

    def decrypt(self, data: bytes, key: bytes = None) -> _Union[bytes, None]:
        return _b64de(data)

class AESCoder(Coder):
    r'''
    预置的AES加密器
    '''
    name = 'AESCoder'
    def __init__(self, key: bytes, iv: bytes = None) -> None:
        self.aes = _AES(key, iv)
        self.name = 'AESCoder'

    def decrypt(self, data: bytes, key: bytes = None) -> _Union[bytes, None]:
        return self.aes.decrypt(data, key)[0]

    def encrypt(self, data: bytes, key: bytes = None) -> _Union[bytes, None]:
        return self.aes.encrypt(data, key)[0]

class RSACoder(Coder):
    r'''
    预置的RSA加密器
    '''
    name = 'RSACoder'
    def __init__(self, _key_pair: _KeyPair) -> None:
        self.rsa = _RSA(_key_pair)
        self.name = 'RSACoder'
    
    def decrypt(self, data: bytes, key: bytes = None) -> _Union[bytes, None]:
        return self.rsa.decrypt(data)
    
    def encrypt(self, data: bytes, key: bytes = None) -> _Union[bytes, None]:
        return self.rsa.encrypt(data)

class MsgBag:
    r'''
    TCP传输时传递的消息包
    '''
    def __init__(self, tags: _List[str] = [], val: _Any = None, sys_sign: SYS_SIGN = None, navigate: int = -1):
        self._tags = {}
        self._val = val
        self.sys_sign: SYS_SIGN = sys_sign
        self.navigate = navigate
        for tag in tags:
            self._tags[tag] = True
    def __str__(self) -> str:
        return 'Tags:{} Value:{} SYS:{} NVG:{}'.format(tuple(self._tags.keys()), self._val, self.sys_sign, self.navigate)

    def getValue(self) -> _Any:
        return self._val

    def addTag(self, tag: str) -> None:
        self._tags[tag] = True

    def checkTag(self, tag: str) -> bool:
        return self._tags.get(tag, False)

    def removeTag(self, tag: str) -> None:
        if self._tags.get(tag, False):
            self._tags[tag] = False

    def clearTag(self) -> None:
        self._tags.clear()


class Packeter:
    r'''
    自定义的包装类, 一定程度上解决TCP的粘包问题.

    初始化参数说明:
    - `encoder`: 包装器所用的加密器对象
    - `error`: 错误处理类型(`loose`或`strict`)
    - `logger`: 可选传入的LoggerWrapper对象
    '''
    def __init__(self, encoder: Coder, error: _Literal['strict', 'loose'] = 'strict', logger: _LogW = None) -> None:
        self._encoder = encoder
        self._error: _Literal['strict', 'loose'] = error
        self._use_logger = False if logger == None else True
        self._logw = logger


    def sendPacket(self, client: _socket, obj: object, key: bytes = None, pickle: bool = False) -> bool:
        r'''
        将`obj`通过`client`发送.
        参数说明:
        - `client`: TCP链接的`socket`对象
        - `obj`: 需要发送的对象
        - `key`: 加密时使用的密钥
        - `pickle`: 若为真，将`obj`序列化后发送，否则使用json转换对象
        '''
        if not pickle:
            try: send_data = _dumps(obj).encode('utf-8')
            except Exception as e:
                if self._error == 'strict': raise PacketError('Fail JSON', e.args)
                else:
                    err = PacketError('Fail JSON', e.args)
                    if self._use_logger: self._logw.error(err)
                    else: print(err)
                return False
        else: send_data = _pdumps(obj, fix_imports = False)
        try: coded = self._encoder.encrypt(send_data, key)
        except Exception as e:
            e_str = f'Can not encode data with \'{self._encoder.name}\' while sending packet: '
            if self._error == 'strict': raise PacketError(e_str, e.args)
            else:
                e_str = '[TCPPacketErr]' + e_str
                err = PacketError(e_str, e.args)
                if self._use_logger: self._logw.error(err)
                else: print(err)
            return False
        
        if len(coded) >= 65536:
            e_str = f'Packet is too big: {len(coded)}Bytes'
            if self._error == 'strict': raise PacketError(e_str, ())
            else:
                e_str = '[TCPPacketErr]' + e_str
                err = PacketError(e_str, ())
                if self._use_logger: self._logw.error(err)
                else: print(err)
            return False

        try:
            pack_size = len(coded)
            pack_header = pack_size.to_bytes(2, 'big')
            client.sendall(pack_header)
            send_data_size = pack_size
            send_data_pointer = 0
            while True:
                if send_data_size <= 1024:
                    client.sendall(coded[send_data_pointer:])
                    break
                client.sendall(coded[send_data_pointer, send_data_pointer + 1024])
                send_data_size -= 1024
                send_data_pointer += 1024
            return True
        except Exception as e:
            e_str = 'Error occurred during sending process: '
            if self._error == 'strict': raise PacketError(e_str, e.args)
            else:
                e_str = '[TCPPacketErr]' + e_str
                err = PacketError(e_str, e.args)
                if self._use_logger: self._logw.error(err)
                else: print(err)
            return False

    def recvPacket(self, client: _socket, key: bytes = None, pickle: bool = False) -> _Any:
        r'''
        通过`client`接收信息.
        参数说明:
        - `client`: TCP链接的`socket`对象
        - `key`: 解密时使用的密钥
        - `pickle`: 若为真，将接收数据反序列化，否则使用json复原对象
        '''
        try:
            size = 0
            pack_header = b''
            while size < 2:
                data = client.recv(2 - size)
                if not data: raise ConnectionError('peer closed.')
                else: 
                    pack_header += data
                    size = len(pack_header)
            
            size = 0
            pack_size = int.from_bytes(pack_header, 'big')
            pack_ = b''
            while size < pack_size:
                recv_size = pack_size - size
                if recv_size > 1024:
                    recv_size = 1024
                pack_ += client.recv(recv_size)
                size = len(pack_)
        except Exception as e:
            e_str = 'Error occurred during recv process: '
            if self._error == 'strict': raise PacketError(e_str, e.args)
            else:
                e_str = '[TCPPacketErr]' + e_str
                err = PacketError(e_str, e.args)
                if self._use_logger: self._logw.error(err)
                else: print(err)
            return None
        
        try: decoded = self._encoder.decrypt(pack_, key)
        except Exception as e:
            e_str = f'Can not decode packet with \'{self._encoder.name}\' while recving: '
            if self._error == 'strict': raise PacketError(e_str, e.args)
            else:
                e_str = '[TCPPacketErr]' + e_str
                err = PacketError(e_str, e.args)
                if self._use_logger: self._logw.error(err)
                else: print(err)
            return None
        else:
            if not pickle:
                try: obj = _loads(decoded.decode('utf-8'))
                except Exception as e:
                    if self._error == 'strict': raise PacketError('Fail JSON', e.args)
                    else:
                        err = PacketError('Fail JSON', e.args)
                        if self._use_logger: self._logw.error(err)
                        else: print(err)
                    return None
            else: obj = _ploads(decoded, fix_imports = False)
            return obj


class Connection:
    def __init__(self, socket: _socket, side: _Literal['send', 'recv', 'server'],
                 sid: int = None, addr: _Tuple[str, int] = None, encoder: _Any = None, pk: bool = False) -> None:
        self._socket = socket
        self._sid = sid
        if sid != None: self._sign = 'CONNECT{}'.format(sid)
        self._addr = addr
        self._packter = None
        self._coder = None
        self._codeclass = AESCoder if encoder == None else encoder
        self._working_thread = None
        self._vertify_thread = None
        self._side: _Literal['ssend', 'srecv', 'server', 'recv', 'send'] = side
        self._msgq: ThreadQueue = None
        self._bkq: ThreadQueue = None
        self._workq: ThreadQueue = None
        self._status: _Literal['CLOSED', 'BAD', 'VERTIFY', 'NORM', 'ERR'] = 'BAD'
        self._status_lock = _Lock()
        self._working_flg = False
        self._work_lock = _Lock()
        self._allowpk = pk
    
    def _vertifySocketAsServer(self) -> bool:
        try: self._socket.sendall(b'----VERITIFY----')
        except Exception:
            self._socket.close()
            return False
        self._socket.settimeout(5.0)
        try: pkey = self._socket.recv(2048)
        except TimeoutError:
            self._socket.close()
            return False
        else:
            self._socket.settimeout(None)
            rsakp = _KeyPair(pkey)
            rsacod = _RSA(rsakp, 'loose')
            rands = _RS(16)
            aesk = bytes(rands.exportStr(), 'utf-8')
            rands.regenerateStr()
            iv = bytes(rands.exportStr(), 'utf-8')
            try: self._socket.sendall(rsacod.encrypt(aesk + iv))
            except Exception:
                self._socket.close()
                return False
            else:
                self._coder = self._codeclass(aesk, iv)
                self._packter = Packeter(self._coder, 'strict')
                self._packter.sendPacket(self._socket, [self._sid, self._addr])
                self._side = self._packter.recvPacket(self._socket)
                self._side = 'srecv' if self._side == 'send' else 'ssend'
        return True

    def _vertifySocketAsClient(self) -> bool:
        try: sign = self._socket.recv(16)
        except Exception:
            self._socket.close()
            return False
        if sign != b'----VERITIFY----':
            self._socket.close()
            return False
        rsap = _KeyPair()
        rsap.randomGenerate()
        try: self._socket.sendall(rsap.getPublicKey())
        except Exception:
            self._socket.close()
            return False
        rsacod = _RSA(rsap, 'loose')
        try: aes_r = self._socket.recv(256)
        except Exception:
            self._socket.close()
            return False
        else:
            if len(aes_r) != 256:
                self._socket.close()
                return False
        aes_r = rsacod.decrypt(aes_r)
        self._coder = self._codeclass(aes_r[:16], aes_r[16:])
        self._packter = Packeter(self._coder, 'strict')
        cdata = self._packter.recvPacket(self._socket)
        self._sid = cdata[0]
        self._sign = 'CONNECT{}'.format(self._sid)
        self._addr = cdata[1]
        self._packter.sendPacket(self._socket, self._side)
        return True
    
    def _vertify(self) -> None:
        with self._status_lock: self._status = 'VERTIFY'
        if self._side == 'server': res = self._vertifySocketAsServer()
        else: res = self._vertifySocketAsClient()
        if res:
            with self._status_lock: self._status = 'NORM'
            self._msgq.put(MsgBag(['VERTIFIED'], self._side, sys_sign = 'sockend', navigate = self._sid))
        else:
            self._socket.close()
            with self._status_lock: self._status = 'CLOSED'
            self._msgq.put(MsgBag(['CLOSED'], self._side, sys_sign = 'sockend', navigate = self._sid))

    def _work_as_recv(self) -> None:
        self._socket.settimeout(5.0)
        while True:
            with self._work_lock:
                if not self._working_flg:
                    self._socket.close()
                    with self._status_lock: self._status = 'CLOSED'
                    self._workq.put(MsgBag(['S_CLOSE'], None, sys_sign = 'sockend', navigate = self._sid))
                    break
            try: msg = self._packter.recvPacket(self._socket, pickle = self._allowpk)
            except Exception:
                self._socket.close()
                with self._status_lock: self._status = 'ERR'
                self._workq.put(MsgBag(['ERR'], None, sys_sign = 'sockend', navigate = self._sid))
                break
            else:
                if isinstance(msg, str):
                    if msg == 'HEARTBEAT': pass
                    if msg == 'CLOSE':
                        self._socket.close()
                        with self._status_lock: self._status = 'CLOSED'
                        self._workq.put(MsgBag(['C_CLOSE'], None, sys_sign = 'sockend', navigate = self._sid))
                        break
                elif isinstance(msg, list):
                    self._workq.put(MsgBag([msg[0]], msg[1], sys_sign = 'apps', navigate = self._sid))

    def _work_as_send(self) -> None:
        self._socket.settimeout(5.0)
        while True:
            with self._work_lock:
                if not self._working_flg:
                    self._socket.close()
                    with self._status_lock: self._status = 'CLOSED'
                    self._bkq.put(MsgBag(['S_CLOSE'], None, sys_sign = 'sockend', navigate = self._sid))
                    break
            try: pbag: MsgBag = self._workq.get(True, 3.0)
            except Empty:
                try: self._packter.sendPacket(self._socket, 'HEARTBEAT')
                except Exception:
                    self._socket.close()
                    with self._status_lock: self._status = 'ERR'
                    self._bkq.put(MsgBag(['ERR'], None, sys_sign = 'sockend', navigate = self._sid))
                    break
            else:
                try: self._packter.sendPacket(self._socket, pbag.getValue(), pickle = self._allowpk)
                except Exception:
                    self._socket.close()
                    with self._status_lock: self._status = 'ERR'
                    self._bkq.put(MsgBag(['ERR'], None, sys_sign = 'sockend', navigate = self._sid))
                    break
                if pbag.checkTag('CMD') and pbag.getValue() == 'CLOSE':
                    self._socket.close()
                    with self._status_lock: self._status = 'CLOSED'
                    self._bkq.put(MsgBag(['C_CLOSE'], self._sid, sys_sign = 'sockend', navigate = self._sid))
                    break

    def work(self, msgQ: _Union[ThreadQueue, Queue], bkQ: _Union[ThreadQueue, Queue] = None) -> None:
        self._workq = msgQ
        self._bkq = bkQ
        if self._side == 'srecv' or self._side == 'recv':
            self._working_thread = _Thread(target = self._work_as_recv)
        elif self._side == 'ssend' or self._side == 'send':
            self._working_thread = _Thread(target = self._work_as_send)
        with self._work_lock: self._working_flg = True
        self._working_thread.start()

    def stopWork(self) -> None:
        with self._work_lock: self._working_flg = False

    def getStatus(self) -> None:
        with self._status_lock: return self._status

    def vertify(self, do_async: bool, msgQ: ThreadQueue):
        self._msgq = msgQ
        if do_async:
            self._vertify_thread = _Thread(target = self._vertify)
            self._vertify_thread.start()
        else:
            self._vertify()

class ConnectionTunnel:
    def __init__(self, bind_addr: _Tuple[str, int], core_key: int, key_len: int, logger: _LogW, ipv6: bool = False) -> None:
        if not ipv6: self._acc_sock = _socket(AF_INET, SOCK_STREAM)
        else: self._acc_sock = _socket(AF_INET6, SOCK_STREAM)
        self._acc_sock.bind(bind_addr)
        self._acc_sock.listen(5)
        self._acc_sock.settimeout(2.0)
        self._main_loop = None
        self._still_accepting = False
        self._vertifying_socks = 0
        self._retsock_queue = None
        self._ban_lock = _Lock()
        self._check_lock = _Lock()
        self._flg_lock = _Lock()
        self._banned: _Dict[str, bool] = {}
        self._core_key = core_key
        self._key_len = key_len
        self._logger = logger
    
    def _recvsoc(self, sock: _socket, addr: _Tuple[str, int], _sv: _SV) -> None:
        sock.settimeout(2.0)
        try: rbytes = sock.recv(self._key_len)
        except TimeoutError:
            sock.close()
            with self._ban_lock:
                self._banned[addr[0]] = True
        else:
            if len(rbytes) != self._key_len:
                sock.close()
                with self._ban_lock:
                    self._banned[addr[0]] = True
            elif not _sv.vertifyBytes(rbytes):
                sock.close()
                with self._ban_lock:
                    self._banned[addr[0]] = True
            else:
                sock.settimeout(None)
                with self._check_lock: self._vertifying_socks -= 1
                self._retsock_queue.put(MsgBag(['NEWSOCK'], (sock, addr), sys_sign = 'ctunnel'))

    def _loop(self) -> None:
        while True:
            with self._flg_lock:
                if not self._still_accepting:
                    self._logger.warn('Receive stop signal!')
                    self._acc_sock.close()
                    break
            with self._ban_lock: 
                if len(self._banned) > 1e5:
                    self._logger.warn('Too many banned IPs, clear banned!')
                    self._banned.clear()
            can_connect = True
            with self._check_lock:
                if self._vertifying_socks > 100:
                    self._logger.warn('Too many sockets waiting auth, stop receiving new socket!')
                    can_connect = False
            if not can_connect:
                while True:
                    self._logger.warn('Wait to release pressure...')
                    relsed = True
                    with self._check_lock:
                        if self._vertifying_socks > 80: relsed = False
                    if not relsed: _slp(2.0)
                    else: break
            if can_connect:
                try: sock, addr = self._acc_sock.accept()
                except TimeoutError: pass
                else:
                    with self._ban_lock:
                        if self._banned.get(addr[0], False):
                            sock.close()
                            continue
                    with self._check_lock:
                        self._vertifying_socks += 1
                        _Thread(target = self._recvsoc, args = (sock, addr, _SV(self._core_key, self._key_len))).start()
                
    def terminateLoop(self) -> None:
        with self._flg_lock:
            self._still_accepting = False

    def acceptLoop(self, retsock_queue: ThreadQueue) -> None:
        self._still_accepting = True
        self._retsock_queue = retsock_queue
        self._main_loop = _Thread(target = self._loop)
        self._main_loop.start()

class SocketCell:
    def __init__(self, cell_queue: Queue, hub_queue: Queue, cell_id: int, maxrate: int, 
                 max_size: int, logger: _LogW, encoder: _Any, pk: bool) -> None:
        self._cellq = cell_queue
        self._hubq = hub_queue
        self._process = None
        self._cid = cell_id
        self._maxsize = max_size
        self._maxrate = maxrate
        self._running_flg = Value('b', False, lock = False)
        self._run_lock = _PLock()
        self._logger = logger
        self._mnlg = logger.getWrapperInstance('baseloop')
        self._encoder = encoder
        self._use_pickle = pk

    @staticmethod
    def _service(_running_flg, _run_lock, _hubq: Queue, _cellq: Queue, _maxsize, _maxrate, 
                 _logger: _LogW, _encoder, _vertilg: _LogW, _downlg: _LogW, use_pk: bool) -> None:
        _vertiq = ThreadQueue()
        _connect_map: _Dict[int, Connection] = {}
        _msgq_map: _Dict[int, ThreadQueue] = {}
        _rate_map: _Dict[int, int] = {}
        _rate_time_map: _Dict[int, float] = {}
        _try_registered: _Dict[int, bool] = {}
        _try_reged: _Dict[int, bool] = {}
        _recvq = ThreadQueue()
        _downlock = _Lock()
        _vertilock = _Lock()
        _vertiflg = False
        _downflg = False
        _connect_lock = _Lock()
        _rate_lock = _Lock()

        def _vertiloop() -> None:
            while True:
                with _vertilock:
                    if not _vertiflg:
                        _vertilg.info('Stop auth Thread!')
                        break
                try: msgb: MsgBag = _vertiq.get(True, 2.0)
                except Empty: pass
                else:
                    if msgb.sys_sign == 'sockend':
                        if msgb.checkTag('VERTIFIED'):
                            _vertilg.info('Socket verified, ID:', msgb.navigate)
                            with _connect_lock:
                                if msgb.getValue() == 'srecv':
                                    _msgq_map.pop(msgb.navigate, None)
                                    _connect_map[msgb.navigate].work(_recvq)
                                elif msgb.getValue() == 'ssend':
                                    _connect_map[msgb.navigate].work(_msgq_map[msgb.navigate], _recvq)
                        elif msgb.checkTag('CLOSED'):
                            _vertilg.info('Socket blocked, ID:', msgb.navigate)
                            with _rate_lock:
                                _rate_map.pop(msgb.navigate, None)
                                _rate_time_map.pop(msgb.navigate, None)
                            with _connect_lock:
                                _msgq_map.pop(msgb.navigate, None)
                                _connect_map.pop(msgb.navigate, None)
                            _hubq.put(MsgBag(['SOCKOUT'], msgb.navigate, sys_sign = 'socketcell'))
        
        def _download() -> None:
            while True:
                with _downlock:
                    if not _downflg: 
                        _downlg.info('Stop bkward Thread!')
                        break
                try: msgb: MsgBag = _recvq.get(True, 2.0)
                except Empty: pass
                else:
                    if msgb.sys_sign == 'sockend':
                        if msgb.checkTag('C_CLOSE'): info = 'client-side close'
                        elif msgb.checkTag('ERR'): info = 'error / timeout'
                        elif msgb.checkTag('S_CLOSE'): info = 'forced close'
                        with _connect_lock:
                            _msgq_map.pop(msgb.navigate, None)
                            _connect_map.pop(msgb.navigate, None)
                        _hubq.put(MsgBag(['SOCKOUT'], msgb.navigate, sys_sign = 'socketcell'))
                        _downlg.info(f'Socket {info}, ID:', msgb.navigate, ', send it to sockethub.')
                    elif msgb.sys_sign == 'apps':
                        if _maxrate > 0:
                            with _rate_lock:
                                _rate_map[msgb.navigate] += 1
                                if _rate_map[msgb.navigate] > _maxrate:
                                    _downlg.warn('Socket sending too many packets, ID:', msgb.navigate)
                                    _connect_map[msgb.navigate].stopWork()
                                    _rate_map[msgb.navigate] = 0
                                if _pfcnt() - _rate_time_map[msgb.navigate] > 1.0:
                                    _rate_map[msgb.navigate] = 0
                                _rate_time_map[msgb.navigate] = _pfcnt()
                        if msgb.checkTag('REGISTER'):
                            if _try_registered.get(msgb.navigate, False): pass
                            else:
                                _downlg.info(f'Socket {msgb.navigate} request registery.')
                                _try_registered[msgb.navigate] = True
                                _hubq.put(msgb)
                        elif msgb.checkTag('REGED'):
                            if _try_reged.get(msgb.navigate, False): pass
                            else:
                                _try_reged[msgb.navigate] = True
                                _hubq.put(msgb)
                        else:
                            _hubq.put(msgb)

        with _downlock: _downflg = True
        with _vertilock: _vertiflg = True
        _vertithread = _Thread(target = _vertiloop)
        _logger.info('Start auth Thread.')
        _vertithread.start()
        _downthread = _Thread(target = _download)
        _logger.info('Start backward Thread.')
        _downthread.start()

        _logger.info('Enter baseloop.')
        while True:
            with _run_lock:
                if not _running_flg.value:
                    _logger.warn('Receive stop signal!')
                    _logger.info('Stopping bkward Thread...')
                    with _downlock: _downflg = False
                    _logger.info('Stopping auth Thread...')
                    with _vertilock: _vertiflg = False
                    _logger.info('Stopping Connections...')
                    for item in _connect_map.items():
                        item[1].stopWork()
                    break
            try: msg_bag: MsgBag = _cellq.get(True, 2.0)
            except Empty: pass
            else:
                if msg_bag.sys_sign == 'sockethub' and msg_bag.checkTag('SOCKIN'):
                    _logger.info('Recv new socket from sockethub, ID:', msg_bag.navigate)
                    _dt = msg_bag.getValue()
                    msgq = ThreadQueue()
                    _tc = Connection(_dt[0], 'server', msg_bag.navigate, _dt[1], _encoder, use_pk)
                    with _rate_lock:
                        _rate_time_map[msg_bag.navigate] = _pfcnt()
                        _rate_map[msg_bag.navigate] = 0
                    with _connect_lock:
                        _connect_map[msg_bag.navigate] = _tc
                        _msgq_map[msg_bag.navigate] = msgq
                    _tc.vertify(True, _vertiq)
                elif msg_bag.sys_sign == 'apps':
                    _msgq_map[msg_bag.navigate].put(msg_bag)

        _vertithread.join()
        _downthread.join()

    def stop(self) -> None:
        with self._run_lock: self._running_flg.value = False

    def run(self) -> None:
        with self._run_lock: self._running_flg.value = True
        self._process = Process(target = SocketCell._service, args = (self._running_flg, self._run_lock, self._hubq,
                                                                self._cellq, self._maxsize, self._maxrate, 
                                                                self._mnlg, self._encoder, self._logger.getWrapperInstance('auth'), 
                                                                self._logger.getWrapperInstance('bkward'), self._use_pickle))
        self._logger.info('SocketCell start!')
        self._process.start()

class SocketHub:
    def __init__(self, cfg: Config, logger: _LogW, logL: _List[_LogW], encoder: _Any) -> None:
        self._inputq: Queue = Queue()
        self._outputq: ThreadQueue = ThreadQueue()
        self._hub_queue: Queue = Queue()
        self._hub_running: bool = False
        self._running_lock = _Lock()
        self._dist_run: bool = False
        self._dist_lock = _Lock()
        self._upload_flg: bool = False
        self._uplock = _Lock()
        self._upload_thread = None
        self._hub_thread = None
        self._distr_thread = None
        self._bind_addresses: _List[_Tuple[str, int]] = cfg.queryConfig('bind_addr')
        self._ctunnels: _List[ConnectionTunnel] = []
        self._cellist: _List[SocketCell] = []
        self._cellqs: _List[Queue] = []
        self._alive_list: _List[int] = []
        self._alive_lock = _Lock()
        self._sid_cid_map: _Dict[int, int] = {}
        self._max_con_per_cell: int = cfg.queryConfig('maxcpc')
        self._max_cell: int = cfg.queryConfig('maxcell')
        self._maxrate: int = cfg.queryConfig('maxrate')
        self._core_key: int = cfg.queryConfig('corekey')
        self._key_len: int = cfg.queryConfig('keylen')
        self._use_ipv6: bool = cfg.queryConfig('ipv6')
        self._use_pickle: bool = cfg.queryConfig('use_pickle')
        self._registered: _Dict[int, int] = {}
        self._regkeys: _Dict[int, str] = {}
        self._reg_lock = _Lock()
        self._logger: _LogW = logger
        self._logL: _List[_LogW] = logL
        self._logCT: _List[_LogW] = [logger.getWrapperInstance('CTunnel{}'.format(index)) for index in range(len(self._bind_addresses))]
        self._sid_iter = 0
        self._encoder = encoder
        self._rs = _RS(64)
        self._fwlg = logger.getWrapperInstance('forwardloop')
        self._rvlg = logger.getWrapperInstance('reverseloop')
        self._mnlg = logger.getWrapperInstance('mainloop')

    @staticmethod
    def exportDefaultCfg(cfg_name: str) -> Config:
        _cfg = Config(cfg_name)
        _cfg.setConfig('bind_addr', [['127.0.0.1', 4448], ['127.0.0.1', 41919]])
        _cfg.setConfig('maxcpc', 10)
        _cfg.setConfig('maxcell', 5)
        _cfg.setConfig('corekey', 135)
        _cfg.setConfig('keylen', 64)
        _cfg.setConfig('ipv6', False)
        _cfg.setConfig('use_pickle', False)
        _cfg.setConfig('maxrate', 50)
        return _cfg

    def _uploadloop(self) -> None:
        while True:
            with self._uplock:
                if not self._upload_flg:
                    self._fwlg.info('Stop forwardloop')
                    break
            try: mbag: MsgBag = self._inputq.get(True, 2.0)
            except Empty: pass
            else:
                with self._reg_lock:
                    if mbag.checkTag('REDIRECT'):
                        if self._registered.get(mbag.navigate, -1) != -1:
                            mbag.navigate = self._registered[mbag.navigate]
                with self._alive_lock:
                    if self._sid_cid_map.get(mbag.navigate, -1) != -1:
                        self._cellqs[self._sid_cid_map[mbag.navigate]].put(mbag)

    def _distributeloop(self) -> None:
        while True:
            with self._dist_lock:
                if not self._dist_run:
                    self._rvlg.info('Stop reverseloop.')
                    break
            try: mbag: MsgBag = self._hub_queue.get(True, 2.0)
            except Empty: pass
            else:
                if mbag.sys_sign == 'socketcell' and mbag.checkTag('SOCKOUT'):
                    self._rvlg.info('Socket out, ID:', mbag.getValue())
                    with self._alive_lock:
                        self._alive_list[self._sid_cid_map[mbag.getValue()]] -= 1
                        self._sid_cid_map.pop(mbag.getValue())
                elif mbag.sys_sign == 'apps':
                    if mbag.checkTag('REGISTER'):
                        rstr = self._rs.exportStr()
                        self._regkeys[mbag.navigate] = rstr
                        self._rs.regenerateStr()
                        ret_data: _List = mbag.getValue()[:]
                        self._rvlg.info(f'SID pair {ret_data} try register with key: {rstr}')
                        ret_data.append(rstr)
                        self._inputq.put(MsgBag(['REGISTER'], ['REGISTER', ret_data], navigate = mbag.getValue()[1], sys_sign = 'apps'))
                    elif mbag.checkTag('REGED'):
                        if self._regkeys[mbag.navigate] == mbag.getValue()[1]:
                            self._rvlg.info(f'SID {mbag.navigate} registered with recv SID {mbag.getValue()[0]}.')
                            with self._reg_lock: self._registered[mbag.navigate] = mbag.getValue()[0]
                    else:
                        with self._reg_lock:
                            if self._registered.get(mbag.navigate, -1) != -1:
                                self._outputq.put(mbag)

    def _hubloop(self) -> None:
        sock_queue = ThreadQueue()
        for addr in self._bind_addresses:
            self._mnlg.info('Start ConnectionTunnel on', addr)
            ct = ConnectionTunnel(tuple(addr), self._core_key, self._key_len, self._logCT.pop(0), self._use_ipv6)
            ct.acceptLoop(sock_queue)
            self._ctunnels.append(ct)
        
        for index in range(self._max_cell):
            self._mnlg.info('Start SocketCell', index, 'on seperated Process.')
            celq = Queue()
            cel = SocketCell(celq, self._hub_queue, index, self._maxrate, self._max_con_per_cell, 
                             self._logL[index], self._encoder, self._use_pickle)
            self._cellist.append(cel)
            self._cellqs.append(celq)
            self._alive_list.append(0)
            cel.run()
        
        while True:
            with self._running_lock:
                if not self._hub_running:
                    self._mnlg.warn('Receive stop signal!')
                    self._mnlg.info('Stopping ConnectionTunnels...')
                    for ct in self._ctunnels: ct.terminateLoop()
                    self._mnlg.info('Stopping SocketCells...')
                    for sc in self._cellist: sc.stop()
                    self._mnlg.info('Send back stop msg.')
                    self._outputq.put(MsgBag(['HUBCLOSE'], None, sys_sign = 'sockethub'))
                    break
            
            try: sock_bag: MsgBag = sock_queue.get(True, 2.0)
            except Empty: pass
            else:
                if sock_bag.sys_sign == 'ctunnel' and sock_bag.checkTag('NEWSOCK'):
                    new_sock: _socket = sock_bag.getValue()[0]
                    with self._alive_lock:
                        miniter, minn = 0, self._alive_list[0]
                        for index in range(self._max_cell):
                            if self._alive_list[index] < minn:
                                minn = self._alive_list[index]
                                miniter = index
                        if self._alive_list[miniter] < self._max_con_per_cell:
                            self._mnlg.info('New socket placed in Cell', miniter)
                            self._alive_list[miniter] += 1
                            self._sid_cid_map[self._sid_iter] = miniter
                            self._cellqs[miniter].put(MsgBag(['SOCKIN'], (*sock_bag.getValue(), ), sys_sign = 'sockethub', 
                                                            navigate = self._sid_iter))
                            self._sid_iter += 1
                        else:
                            self._mnlg.warn('No spare place for new socket!')
                            new_sock.close()
    
    def terminateLoop(self) -> None:
        self._logger.warn('Stop sockethub.')
        with self._running_lock: self._hub_running = False
        with self._dist_lock: self._dist_run = False
        with self._uplock: self._upload_flg = False

    def startLoop(self) -> None:
        with self._running_lock: self._hub_running = True
        with self._dist_lock: self._dist_run = True
        with self._uplock: self._upload_flg = True
        self._logger.info('Start main loop Thread.')
        self._hub_thread = _Thread(target = self._hubloop)
        self._hub_thread.start()
        self._logger.info('Start reversed loop Thread.')
        self._distr_thread = _Thread(target = self._distributeloop)
        self._distr_thread.start()
        self._logger.info('Start forward loop Thread.')
        self._upload_thread = _Thread(target = self._uploadloop)
        self._upload_thread.start()

    def getIOqueue(self) -> _Tuple[Queue, ThreadQueue]:
        return self._inputq, self._outputq


class ServicePort:
    def __init__(self, service_name: str, inputq: Queue, outputq: Queue) -> None:
        self._name = service_name
        self._inputq = inputq
        self._outputq = outputq

    def getIO(self) -> _Tuple[Queue, Queue]:
        return self._inputq, self._outputq

    def getMsg(self, _timeout: float = None) -> MsgBag:
        if _timeout != None: return self._outputq.get(True, _timeout)
        else: return self._outputq.get()

    def putMsg(self, tags: _List[str], val: _Any, target_sid: int, _timeout: float = None, redirect: bool = True) -> None:
        if redirect: tags.append('REDIRECT')
        if _timeout != None:
            self._inputq.put(MsgBag(tags, [self._name, val], sys_sign = 'apps', navigate = target_sid), True, _timeout)
        else: self._inputq.put(MsgBag(tags, [self._name, val], sys_sign = 'apps', navigate = target_sid))

class Server:
    def __init__(self, sh_cfg: Config, plogger: _PL, encoder: _Any = AESCoder) -> None:
        _cell_cnt = sh_cfg.queryConfig('maxcell')
        self._logger = plogger
        self._slg = self._logger.getWrapperInstance('Server')
        self._shlog = self._logger.getWrapperInstance('HUB')
        self._logwl = [self._logger.getWrapperInstance('CELL{}'.format(index)) for index in range(_cell_cnt)]
        self._sh = SocketHub(sh_cfg, self._shlog, self._logwl, encoder)
        self._dist_thread = None
        self._service_map: _Dict[str, Queue] = {}
        self._serve_name: _List[str] = []
        self._running = False
        self._runlock = _Lock()
        self._service_lock = _Lock()

        if sh_cfg.queryConfig('use_pickle'):
            self._slg.warn('Pickle is allowed, this may cause dangerous code execution during network operations!') 
        self._slg.info('Server inited with SH config:', sh_cfg)
        self._slg.info('Using encoder:', encoder.name)
    
    def _distribute(self) -> None:
        while True:
            try: msg_bag: MsgBag = self._outputq.get(True, timeout = 2.0)
            except Empty: pass
            else:
                with self._service_lock:
                    for serve in self._serve_name:
                        if msg_bag.checkTag(serve):
                            self._service_map[serve].put(msg_bag)
            with self._runlock:
                if not self._running:
                    self._slg.warn('Server stopping, sending stop msg...')
                    self._sh.terminateLoop()
                    with self._service_lock:
                        for ser in self._serve_name:
                            self._service_map[ser].put(MsgBag(['STOP'], None, sys_sign = 'server'))
                    break
    
    def bindService(self, name: str) -> _Union[ServicePort, None]:
        if name in self._serve_name:
            self._slg.error(f'Service {name} already exists, change one and try again!')
            return None
        self._slg.info('Bind service:', name)
        outpq = Queue()
        with self._service_lock:
            self._service_map[name] = outpq
            self._serve_name.append(name)
        return ServicePort(name, self._inputq, outpq)

    def stopServer(self) -> None:
        self._slg.warn('Actively close server!')
        with self._runlock: self._running = False

    def runServer(self) -> None:
        self._slg.info('Server start!')
        with self._runlock: self._running = True
        self._slg.info('Start SocketHub.')
        self._sh.startLoop()
        self._inputq, self._outputq = self._sh.getIOqueue()
        self._slg.info('Start bag distributing Thread.')
        self._dist_thread = _Thread(target = self._distribute)
        self._dist_thread.start()


class ClientPort:
    def __init__(self, inputq: Queue, outputq: Queue, sid_pair: _Tuple[int, int]) -> None:
        self._inputq = inputq
        self._outputq = outputq
        self._lock = _PLock()
        self._status = Value('b', True, lock = False)
        self._send_sid = sid_pair[0]
        self._recv_sid = sid_pair[1]
    
    def getIO(self) -> _Tuple[Queue, Queue]:
        return self._inputq, self._outputq

    def register(self) -> None:
        self._inputq.put(MsgBag([], ['REGISTER', [self._send_sid, self._recv_sid]]))
        regbag: MsgBag = self._outputq.get()
        if regbag.checkTag('REGISTER'):
            reg_data = regbag.getValue()
            if reg_data[0] == self._send_sid and reg_data[1] == self._recv_sid:
                self._inputq.put(MsgBag([], ['REGED', [self._recv_sid, reg_data[2]]]))
            else: return None
        else: return None

    def setStatus(self, _sta: _Literal['NORM', 'DIED']) -> None:
        if _sta == 'NORM':
            with self._lock: self._status.value = True
        elif _sta == 'DIED':
            with self._lock: self._status.value = False

    def getMsg(self, _timeout: float = None) -> _Union[MsgBag, None]:
        with self._lock:
            if not self._status.value: return None
            else:
                if _timeout != None: return self._outputq.get(True, timeout = _timeout)
                else: return self._outputq.get()

    def putMsg(self, val: _Any, target_service: str, _timeout: float = None) -> bool:
        with self._lock:
            if not self._status.value: return False
            else:
                if _timeout != None:
                    self._inputq.put(MsgBag([], [target_service, val]), True, _timeout)
                else: self._inputq.put(MsgBag([], [target_service, val]))
                return True

class Client:
    def __init__(self, cli_cfg: Config, plogger: _PL, encoder: _Any = None) -> None:
        self._corekey = cli_cfg.queryConfig('corekey')
        self._keylen = cli_cfg.queryConfig('keylen')
        self._ipv6 = cli_cfg.queryConfig('ipv6')
        self._usepk = cli_cfg.queryConfig('use_pickle')
        self._coder = encoder if encoder != None else AESCoder
        self._data_lock = _Lock()
        self._serve_cons: _Dict[str, Process] = {}
        self._inputqs: _Dict[str, Queue] = {}
        self._outputqs: _Dict[str, Queue] = {}
        self._clid_list: _List[str] = []
        self._wrappers: _Dict[str, ClientPort] = {}
        self._stopflgs: _Dict[str, _Any] = {}
        self._stoplocks: _Dict[str, _Any] = {}
        self._vertiq = Queue()
        self._verti_thread = None
        self._sidretq = ThreadQueue()
        self._running = False
        self._run_lock = _Lock()
        self._logger = plogger.getWrapperInstance('Client')
    
    @staticmethod
    def exportDefaultCfg(cfg_name: str) -> Config:
        cfg = Config(cfg_name)
        cfg.setConfig('corekey', 135)
        cfg.setConfig('keylen', 64)
        cfg.setConfig('ipv6', False)
        cfg.setConfig('use_pickle', False)
        return cfg

    @staticmethod
    def _serveconnect(addr: _Tuple[str, int], inputq: Queue, outputq: Queue, usepk: bool, corek: int, 
                      klen: int, ipv6: bool, encoder: _Any, vertiq: Queue, clid: str, stop_flg, stop_lock) -> None:
        recv_connect = None
        send_connect = None
        if not ipv6:
            recv_sock = _socket(AF_INET, SOCK_STREAM)
            send_sock = _socket(AF_INET, SOCK_STREAM)
        else:
            recv_sock = _socket(AF_INET6, SOCK_STREAM)
            send_sock = _socket(AF_INET6, SOCK_STREAM)
        simplev = _SV(corek, klen)

        recv_sock.connect(addr)
        recv_sock.sendall(simplev.generateBytes())
        recv_connect = Connection(recv_sock, 'recv', encoder = encoder, pk = usepk)
        recv_connect.vertify(False, outputq)
        try: recv_res: MsgBag = outputq.get(True, 2.0)
        except Exception:
            vertiq.put(MsgBag(['FAILED'], clid))
            return
        else:
            if recv_res.checkTag('VERTIFIED'):
                vertiq.put(MsgBag(['VRECV'], clid))
            elif recv_res.checkTag('CLOSED'):
                vertiq.put(MsgBag(['FAILED'], clid))
                return 
        del recv_res

        send_sock.connect(addr)
        send_sock.sendall(simplev.generateBytes())
        send_connect = Connection(send_sock, 'send', encoder = encoder, pk = usepk)
        send_connect.vertify(False, outputq)
        try: send_res: MsgBag = outputq.get(True, 2.0)
        except Exception:
            vertiq.put(MsgBag(['FAILED'], clid))
            return
        else:
            if send_res.checkTag('VERTIFIED'):
                vertiq.put(MsgBag(['VSEND'], clid))
            elif send_res.checkTag('CLOSED'):
                vertiq.put(MsgBag(['FAILED'], clid))
                return 
        del send_res

        vertiq.put(MsgBag(['VERIFIED'], (send_connect._sid, recv_connect._sid)))
        send_connect.work(inputq, outputq)
        recv_connect.work(outputq)

        while True:
            with stop_lock:
                if not stop_flg.value:
                    inputq.put(MsgBag(['CMD'], 'CLOSE'))
                    recv_connect.stopWork()
                    vertiq.put(MsgBag(['STOPPED'], clid))
                    break
            _slp(0.2)

    def _vertiservice(self, _logger: _LogW) -> None:
        _logger.info('Start auth service.')
        while True:
            with self._run_lock:
                if not self._running:
                    _logger.warn('Stop auth thread!')
                    break
            try: vbag: MsgBag = self._vertiq.get(True, 2.0)
            except Empty: pass
            else:
                if vbag.checkTag('FAILED'):
                    _logger.error('Connection', vbag.getValue(), 'failed to verify.')
                    with self._data_lock:
                        self._clid_list.remove(vbag.getValue())
                        self._inputqs.pop(vbag.getValue())
                        self._outputqs.pop(vbag.getValue())
                        self._serve_cons.pop(vbag.getValue())
                        self._stopflgs.pop(vbag.getValue())
                        self._stoplocks.pop(vbag.getValue())
                        self._wrappers[vbag.getValue()].setStatus('DIED')
                elif vbag.checkTag('VSEND'):
                    _logger.info('Connection', vbag.getValue(), 'sending tunnel verified.')
                elif vbag.checkTag('VRECV'):
                    _logger.info('Connection', vbag.getValue(), 'recving tunnel verified.')
                elif vbag.checkTag('VERIFIED'):
                    _logger.info('Verified SID:', vbag.getValue())
                    self._sidretq.put(vbag.getValue())

    def stopClient(self) -> None:
        self._logger.warn('Stopping Client!')
        with self._run_lock: self._running = False
        with self._data_lock:
            for clid in self._clid_list:
                with self._stoplocks[clid]:
                    self._stopflgs[clid].value = False

    def startClient(self) -> None:
        with self._run_lock: self._running = True
        self._verti_thread = _Thread(target = self._vertiservice, args = (self._logger.getWrapperInstance('auth'), ))
        self._verti_thread.start()

    def connectServer(self, server_addr: _Tuple[str, int], client_id: str) -> _Union[ClientPort, None]:
        if client_id in self._clid_list:
            self._logger.error(f'Client {client_id} already exists, change it and try again!')
            return None
        inputq = Queue()
        outputq = Queue()
        self._logger.info('Add connection:', client_id, '->', server_addr)
        cs_flg = Value('b', True, lock = False)
        cs_lock = _PLock()
        cs_process = Process(target = Client._serveconnect, args = (server_addr, inputq, outputq, self._usepk, self._corekey,
                                                                    self._keylen, self._ipv6, self._coder, self._vertiq, client_id,
                                                                    cs_flg, cs_lock))
        cs_process.start()
        sid_pair = self._sidretq.get()
        with self._data_lock:
            self._clid_list.append(client_id)
            self._inputqs[client_id] = inputq
            self._outputqs[client_id] = outputq
            self._stoplocks[client_id] = cs_lock
            self._stopflgs[client_id] = cs_flg
            self._serve_cons[client_id] = cs_process
            cs_port = ClientPort(inputq, outputq, sid_pair)
            self._logger.info('Create ClientPort instance')
            self._wrappers[client_id] = cs_port
        return cs_port
