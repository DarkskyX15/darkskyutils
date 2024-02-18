# -*- coding: UTF-8 -*-
r'''TCP相关的工具'''
from os import cpu_count as _cpu_count
from time import sleep as _slp
from typing import Literal as _Literal, Any as _Any, Union as _Union, Tuple as _Tuple, List as _List, Dict as _Dict
from json import dumps as _dumps, loads as _loads
from sky_lib.encrypt import AES as _AES, RSA as _RSA, RSAKeyPair as _KeyPair, SimpleVertify as _SV, RandomStr as _RS
from sky_lib.logger import LoggerWrapper as _LogW
from sky_lib.config import Config, CONFIGTYPE
from socket import socket as _socket, AF_INET, AF_INET6, SOCK_STREAM
from base64 import b64decode as _b64de, b64encode as _b64en
from multiprocessing import Process, Queue
from threading import Thread as _Thread, Lock as _Lock
from queue import Empty, Full, Queue as ThreadQueue

SERVING_SIDE = _Literal['server', 'client']

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
    def __init__(self, key: bytes, iv: bytes = None) -> None:
        self.aes = _AES(key, iv)
        self.name = 'AESCoder'

    def decrypt(self, data: bytes, key: bytes = None) -> _Union[bytes, None]:
        res = self.aes.decrypt(data, key)
        res = None if res[0] == None else _b64de(res[0])
        return res

    def encrypt(self, data: bytes, key: bytes = None) -> _Union[bytes, None]:
        res = self.aes.encrypt(data, key)
        res = None if res[0] == None else _b64en(res[0])
        return res

class RSACoder(Coder):
    r'''
    预置的RSA加密器
    '''
    def __init__(self, _key_pair: _KeyPair) -> None:
        self.rsa = _RSA(_key_pair)
        self.name = 'RSACoder'
    
    def decrypt(self, data: bytes, key: bytes = None) -> _Union[bytes, None]:
        res = self.rsa.decrypt(data)
        return None if res == None else _b64de(res)
    
    def encrypt(self, data: bytes, key: bytes = None) -> bytes | None:
        res = self.rsa.encrypt(data)
        return None if res == None else _b64en(res)

class MsgBag:
    r'''
    TCP传输时传递的消息包
    '''
    def __init__(self, tags: _List[str] = [], val: _Any = None):
        self._tags = {}
        self._val = val
        for tag in tags:
            self._tags[tag] = True
    
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


    def sendPacket(self, client: _socket, obj: object, key: bytes = None) -> bool:
        r'''
        将`obj`通过`client`发送.
        参数说明:
        - `client`: TCP链接的`socket`对象
        - `obj`: 需要发送的对象(任意可被转成JSON字符串的对象)
        - `key`: 加密时使用的密钥
        '''
        try:
            send_data = _dumps(obj).encode('utf-8')
            coded = self._encoder.encrypt(send_data, key)
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
        except TimeoutError as e:
            raise e
        except Exception as e:
            e_str = 'Error occurred during sending process: '
            if self._error == 'strict': raise PacketError(e_str, e.args)
            else:
                e_str = '[TCPPacketErr]' + e_str
                err = PacketError(e_str, e.args)
                if self._use_logger: self._logw.error(err)
                else: print(err)
            return False

    def recvPacket(self, client: _socket, key: bytes = None) -> _Any:
        r'''
        通过`client`接收信息.
        参数说明:
        - `client`: TCP链接的`socket`对象
        - `key`: 解密时使用的密钥
        '''
        try:
            size = 0
            pack_header = b''
            while size < 2:
                pack_header += client.recv(2 - size)
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
        except TimeoutError as e:
            raise e
        except Exception as e:
            e_str = 'Error occurred during recv process: '
            if self._error == 'strict': raise PacketError(e_str, e.args)
            else:
                e_str = '[TCPPacketErr]' + e_str
                err = PacketError(e_str, e.args)
                if self._use_logger: self._logw.error(err)
                else: print(err)
            return None
        
        try:
            decoded = self._encoder.decrypt(pack_, key)
            obj = _loads(decoded.decode('utf-8'))
        except Exception as e:
            e_str = f'Can not decode packet with \'{self._encoder.name}\' while recving: '
            if self._error == 'strict': raise PacketError(e_str, e.args)
            else:
                e_str = '[TCPPacketErr]' + e_str
                err = PacketError(e_str, e.args)
                if self._use_logger: self._logw.error(err)
                else: print(err)
            return None
        else: return obj

class Connection:
    def __init__(self, logger: _LogW, socket: _socket, side: _Literal['send', 'recv', 'server'],
                 sid: int = None, addr: _Tuple[str, int] = None, encoder: _Any = None) -> None:
        self._socket = socket
        self._sid = sid
        if sid != None: self._sign = 'CONNECT{}'.format(sid)
        self._addr = addr
        self._packter = None
        self._coder = None
        self._codeclass = AESCoder if encoder == None else encoder
        self._working_thread = None
        self._vertify_thread = None
        self._side: _Literal['send', 'recv', 'server'] = side
        self._logger = logger
        self._msgq: ThreadQueue = None
        self._workq: ThreadQueue = None
        self._status: _Literal['CLOSED', 'BAD', 'VERTIFY', 'NORM', 'ERR'] = 'BAD'
        self._status_lock = _Lock()
        self._working_flg = False
        self._work_lock = _Lock()
    
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
            if len(pkey) != 2048:
                self._socket.close()
                return False
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
                self._packter.sendPacket(self._socket, (self._sid, self._addr))
                self._side = self._packter.recvPacket(self._socket)
                self._side = 'recv' if self._side == 'send' else 'send'
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
        try: aes_r = self._socket.recv(32)
        except Exception:
            self._socket.close()
            return False
        else:
            if len(aes_r) != 32:
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
            self._msgq.put(MsgBag(['CON_CONTROL','VERTIFIED'], (self._sid, self._side)))
        else:
            self._socket.close()
            with self._status_lock: self._status = 'CLOSED'
            self._msgq.put(MsgBag(['CON_CONTROL', 'CLOSED'], (self._sid, self._side)))

    def _work_as_recv(self) -> None:
        self._socket.settimeout(8.0)
        while True:
            with self._work_lock:
                if not self._working_flg:
                    self._socket.close()
                    with self._status_lock: self._status = 'CLOSED'
                    self._workq.put(MsgBag(['CON_CONTROL', 'S_CLOSE'], self._sid))
                    break
            try:
                msg = self._packter.recvPacket(self._socket)
            except Exception:
                self._socket.close()
                with self._status_lock: self._status = 'ERR'
                self._workq.put(MsgBag(['CON_CONTROL', 'ERR'], self._sid))
                break
            else:
                if isinstance(msg, str) and msg == 'HEARTBEAT': pass
                if isinstance(msg, str) and msg == 'CLOSE':
                    self._socket.close()
                    with self._status_lock: self._status = 'CLOSED'
                    self._workq.put(MsgBag(['CON_CONTROL', 'C_CLOSE'], self._sid))
                else:
                    self._workq.put(MsgBag(['NORMMSG', self._sign], msg))

    def _work_as_send(self) -> None:
        self._socket.settimeout(8.0)
        while True:
            with self._work_lock:
                if not self._working_flg:
                    self._socket.close()
                    with self._status_lock: self._status = 'CLOSED'
                    self._workq.put(MsgBag(['CON_CONTROL', 'S_CLOSE'], self._sid))
                    break
            try: pbag: MsgBag = self._workq.get_nowait()
            except Empty:
                try: self._packter.sendPacket(self._socket, 'HEARTBEAT')
                except Exception:
                    self._socket.close()
                    with self._status_lock: self._status = 'ERR'
                    self._workq.put(MsgBag(['CON_CONTROL', 'ERR'], self._sid))
                    break
                else: _slp(5.0)
            else:
                try: self._packter.sendPacket(self._socket, pbag.getValue())
                except Exception:
                    self._socket.close()
                    with self._status_lock: self._status = 'ERR'
                    self._workq.put(MsgBag(['CON_CONTROL', 'ERR'], self._sid))
                    break
                if pbag.checkTag('CMD') and pbag.getValue() == 'CLOSE':
                    self._socket.close()
                    with self._status_lock: self._status = 'CLOSED'
                    self._workq.put(MsgBag(['CON_CONTROL', 'C_CLOSE']))

    def work(self, msgQ: ThreadQueue) -> None:
        self._workq = msgQ
        if self._side == 'recv':
            self._working_thread = _Thread(target = self._work_as_recv)
        elif self._side == 'send':
            self._working_thread = _Thread(target = self._work_as_send)
        with self._work_lock: self._working_flg = True
        self._working_thread.start()

    def stopWork(self) -> None:
        with self._work_lock: self._working_flg = False

    def vertify(self, do_async: bool, msgQ: ThreadQueue):
        self._msgq = msgQ
        if do_async:
            self._vertify_thread = _Thread(target = self._vertify)
            self._vertify_thread.start()
        else:
            self._vertify()

class ConnectionTunnel:
    def __init__(self, bind_addr: _Tuple[str, int], core_key: int, ipv6: bool = False) -> None:
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
    
    def _recvsoc(self, sock: _socket, addr: _Tuple[str, int], _sv: _SV) -> None:
        sock.settimeout(2.0)
        try: rbytes = sock.recv(64)
        except TimeoutError:
            sock.close()
            with self._ban_lock:
                self._banned[addr[0]] = True
        else:
            if len(rbytes) != 64:
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
                self._retsock_queue.put(MsgBag(['NEWSOCK'], (sock, addr)))

    def _loop(self) -> None:
        while True:
            with self._flg_lock:
                if not self._still_accepting: break
            with self._ban_lock: 
                if len(self._banned) > 1e5:
                    self._banned.clear()
            can_connect = True
            with self._check_lock:
                if self._vertifying_socks > 100: can_connect = False
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
                        _Thread(target = self._recvsoc, args = (sock, addr, _SV(self._core_key, 64))).start()
                
    def terminateLoop(self) -> None:
        with self._flg_lock:
            self._still_accepting = False

    def acceptLoop(self, retsock_queue: Queue) -> None:
        self._still_accepting = True
        self._retsock_queue = retsock_queue
        self._main_loop = _Thread(target = self._loop)
        self._main_loop.start()

# TODO: Compelete SocketCell
# Cell run in a Process
# Cell check vertify state of Connection & make it work
# Send Distribute MsgBag 
# Collect returned MsgBag
              
class SocketCell:
    def __init__(self, cell_queue: Queue, hub_queue: Queue, cell_id: int) -> None:
        self._cellq = cell_queue
        self._hubq = hub_queue
        self._process = None
        self._connect_list: _List[Connection] = []
        self._cid = cell_id
    
    def _service(self) -> None:
        while True:
            msg_bag: MsgBag = self._cellq.get()

    def run(self) -> None:
        self._process = Process(target = self._service)
        self._process.start()

# TODO: Only Designed for Server
# Manage Socket Cells
# Distribute Sockets
# Distributes Bag from Services
# Send back Bags & Manage registered Services
class SocketHub:
    def __init__(self, use_coder: _Any) -> None:
        self._service_process: Process = None
        self._retsocket_queue: Queue = Queue()
        self._running: bool = False
        self._connect_id: int = 0
        self._alive_cons: int = 0
        self._forward_queue: Queue = Queue()
        self._backward_queue: Queue = Queue()
        self._tunnels: _List[ConnectionTunnel] = []
        self._cell_queues: _List[Queue] = []
        self._cell_list: _List[SocketCell] = []
        self._cell_pressure: _List[int] = []
        self._msg_thread = None
        self._usecoder = use_coder
        # Overall Configs
        self._max_connects = 0
        self._core_key = 0
        self._use_ipv6 = False
        self._is_server = False
        self._cell_cnt: int = 0
        # Server Side Configs
        self._listen_addr_list: _List[_List[str, int]] = []
        
        # Client Side Configs
        self._connect_addr_list: _List[_List[str, int]] = []
        self._connect_repeats: _List[int] = []
    
    def _forwardmsgservice(self) -> None:
        # TODO
        '''线程循环检查前向队列，分发数据包
        特殊地，socket的进入和推出包也放在前向队列
        '''
        # # TODO Change Method
        # if connect_res:
        #     min_pres = self._cell_pressure[-1]
        #     min_pres_pos = len(self._cell_pressure) - 1
        #     for index in range(min_pres_pos + 1):
        #         if self._cell_pressure[index] < min_pres:
        #             min_pres = self._cell_pressure[index]
        #             min_pres_pos = index
        #     self._cell_queues[min_pres_pos].put(connect)
        #     self._alive_cons += 1
        #     self._connect_id += 1
        pass

    def _sockethub(self) -> None:
        if self._is_server:
            # Init cells & tunnels
            for index in range(self._cell_cnt):
                cellq = Queue()
                cellins = SocketCell(self._backward_queue, cellq, index)
                cellins.run()
                self._cell_list.append(cellins)
                self._cell_queues.append(cellq)
            for addr_pair in self._listen_addr_list:
                tunnel = ConnectionTunnel((addr_pair[0], addr_pair[1]), self._use_ipv6, self._core_key)
                tunnel.acceptLoop(self._retsocket_queue)
                self._tunnels.append(tunnel)
            self._msg_thread = _Thread(target = self._forwardmsgservice)
            self._msg_thread.start()

            while self._running:
                if not self._retsocket_queue.empty():
                    try: soc_tp: _Tuple[_socket, _Tuple[str, int]] = self._retsocket_queue.get_nowait()
                    except Empty: pass
                    else:
                        if self._alive_cons >= self._max_connects:
                            soc_tp[0].close()
                        else:
                            # Second Vertify
                            connect = Connection(soc_tp[0], self._connect_id, soc_tp[1], self._usecoder)
                            connect_res = connect.vertifySocketAsServer()
                            if not connect_res: soc_tp[0].close()
                            self._forward_queue.put(MsgBag(['SOCK_ADD'], [], connect))
                            

        else:
            pass

    def runServiceLoop(self, block: bool = True) -> None:
        self._running = True
        if block: self._sockethub()
        else:
            self._service_process = Process(target = self._sockethub)
            self._service_process.start()

    def stopServiceLoop(self) -> None:
        self._running = False
        if self._is_server:
            for tunnel in self._tunnels:
                tunnel.terminateLoop()
        else:
            pass

    def exportDefaultConfig(self, export_config_name: str, side: SERVING_SIDE) -> Config:
        df_config = Config(export_config_name)
        df_config.setConfig('use_ipv6', False)
        df_config.setConfig('core_key', 115)
        cell_cnt = _cpu_count() // 2
        cell_cnt = cell_cnt if cell_cnt else 1
        df_config.setConfig('cell_cnt', cell_cnt)
        df_config.setConfig('max_connects', int(1e4))
        if side == 'server':
            df_config.setConfig('is_server', True)
            df_config.setConfig('listen_addr_list', [['127.0.0.1', 10566]])
        elif side == 'client':
            df_config.setConfig('is_server', False)
            df_config.setConfig('connect_addr_list', [['127.0.0.1', 10566]])
            df_config.setConfig('connect_repeats', [1])
        df_config.saveToFile('simple')
        return df_config

    def exportThisConfig(self, export_config_name: str, cfg_type: CONFIGTYPE, cfg_key: bytes = None) -> Config:
        this_config = Config(export_config_name)
        this_config.setConfig('is_server', self._is_server)
        this_config.setConfig('use_ipv6', self._use_ipv6)
        this_config.setConfig('core_key', self._core_key)
        this_config.setConfig('cell_cnt', self._cell_cnt)
        this_config.setConfig('max_connects', self._max_connects)
        if self._is_server:
            this_config.setConfig('listen_addr_list', self._listen_addr_list)
        else:
            this_config.setConfig('connect_addr_list', self._connect_addr_list)
            this_config.setConfig('connect_repeats', self._connect_repeats)
        this_config.saveToFile(cfg_type, cfg_key)
        return this_config

    def loadConfig(self, _config: Config) -> None:
        self._is_server = _config.queryConfig('is_server')
        self._use_ipv6 = _config.queryConfig('use_ipv6')
        self._core_key = _config.queryConfig('core_key')
        self._cell_cnt = _config.queryConfig('cell_cnt')
        self._max_connects = _config.queryConfig('max_connects')
        if self._is_server:
            self._listen_addr_list = _config.queryConfig('listen_addr_list')
        else:
            self._connect_addr_list = _config.queryConfig('connect_addr_list')
            self._connect_repeats = _config.queryConfig('connect_repeats')
