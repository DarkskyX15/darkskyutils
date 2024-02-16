# -*- coding: UTF-8 -*-
r'''
多进程和多线程的日志输出器, 一般只使用ProcessLogger/ThreadLogger类

避免将ProcessLogger/ThreadLogger的实例传入其他进程或线程的args中, 以防发生其他错误

#### 只建议将LoggerWrapper实例传入线程/进程
'''
from typing import Literal as _Literal, Callable as _Callable, Union as _Union, Any as _Any
from threading import Thread as _Thread
from multiprocessing import Queue as _Queue, Process as _Process
from random import randint as _randint
from time import strftime as _strftime, localtime as _localtime
from os.path import exists as _exists
from os import mkdir as _mkdir

LOGSIGN = _Literal['warn', 'info', 'error', 'stop']
TCOLOR = _Literal['yellow', 'red', 'default', 'green', 'black', 'blue', 'purple', 'cyan', 'white']
COLORMAP = {'black': '30', 'red': '31', 'green': '32', 'yellow': '33', 'blue': '34', 'purple': '35', 'cyan': '36', 'white': '37'}

class LoggerPacket:
    r'''
    日志输出器消息队列使用的消息包, 首先说明默认日志显示格式:

    `[时间][日志等级标志][程序段落名] 日志内容`
    
    时间以`%m-%d %H:%M:%S`的格式输出

    详细的参数说明:
    - `text_color`: 日志在控制台中显示的颜色.
    - `phase_name`: 程序段落名.
    - `level`: 日志等级标志.
    - `logs`: 日志内容.

    所有可用的颜色在 TCOLOR 中有所提示.

    可以继承此类并重写其`getStr`方法, 以自定义日志的输出格式.初始化时的参数均
    被以相同名字保存为属性, 同时有`timestamp`属性表示该类初始化时的时间.
    '''
    def __init__(self, text_color: TCOLOR, phase_name: str, level: str, logs: str) -> None:
        self.text_color = text_color
        self.phase_name = phase_name
        self.level = level
        self.logs = logs
        self.timestamp = _strftime('%m-%d %H:%M:%S', _localtime())
    
    def getColorPrefix(self) -> _Union[str, None]:
        return COLORMAP.get(self.text_color, None)

    def getStr(self) -> str:
        return '[{}][{}][{}] {}'.format(self.timestamp, self.level, self.phase_name, self.logs)
    
class LoggerWrapper:
    r'''
    包装后日志输出器的接口, 方便在程序的不同部分使用.

    你可以继承类并重写其中的`logsPacketer`方法, 并向类中加入自定义的方法, 来达成不同的自定义效果.
    ```Python
    (method) def logsPacketer(
        self: Self@LoggerWrapper,
        logs: str,
        sign: LOGSIGN
    ) -> LoggerPacket
    ```
    `logs`传入的是日志内容, `sign`传入日志类型. 正确的`logsPacketer`函数应该返回一个`LoggerPacket`实例.

    关于`LoggerPacket`的详细参数参见`LoggerPacket`类的说明.

    #### 注意: 继承并重写后的类需要通过`ProcessLogger`的`changeWrapper`方法装载.
    '''
    def __init__(self, phase_name: str, logs_queue: _Queue) -> None:
        self.phase_name: str = phase_name
        self.logs_queue: _Queue = logs_queue

    def pushLog(self, logs_pack: LoggerPacket) -> None:
        self.logs_queue.put(logs_pack)
    
    def logsPacketer(self, logs: str, sign: LOGSIGN) -> LoggerPacket:
        if sign == 'info':
            return LoggerPacket('default', self.phase_name, 'info', logs)
        elif sign == 'warn':
            return LoggerPacket('yellow', self.phase_name, 'WARN', logs)
        elif sign == 'error':
            return LoggerPacket('red', self.phase_name, 'ERROR', logs)
        elif sign == 'stop':
            return LoggerPacket('yellow', self.phase_name, 'STOP', logs)
        else:
            return LoggerPacket('default', self.phase_name, 'unknown', logs)
        
    def stopLogger(self, reason: str) -> None:
        self.pushLog(self.logsPacketer(reason, 'stop'))

    def info(self, *logs: _Any, sep: str = ' ') -> None:
        log_t = sep.join([str(log) for log in logs])
        self.pushLog(self.logsPacketer(log_t, 'info'))
    
    def error(self, *logs: _Any, sep: str = ' ') -> None:
        log_t = sep.join([str(log) for log in logs])
        self.pushLog(self.logsPacketer(log_t, 'error'))
    
    def warn(self, *logs: _Any, sep: str = ' ') -> None:
        log_t = sep.join([str(log) for log in logs])
        self.pushLog(self.logsPacketer(log_t, 'warn'))

class ProcessLogger:
    r'''
    日志输出器主体, 初始化参数说明:
    - `file_output`: 是否开启文件输出, 默认`False`
    - `logs_folder_name`: 储存日志文件的文件夹, 默认为`None`

    开始日志输出时需调用`startLogThread`方法, 
    在程序的不同部分调用`getWrapperInstance`获取`LoggerWrapper`对象, 并使用`LoggerWrapper`的方法输出日志.

    进阶用法查看`LoggerWrapper`类的说明.
    '''
    def __init__(self, file_output: bool = False, logs_folder_name: str = None) -> None:
        self.logs_queue = _Queue()
        self.logger_thread = None
        self.logs_folder = '.\\Logs' if logs_folder_name == None else logs_folder_name.removesuffix('\\')
        self.log_file_name = ''
        self.file_output = file_output
        self.wrapper = LoggerWrapper

        if self.file_output:
            if not _exists(self.logs_folder):
                _mkdir(self.logs_folder)
            self.log_file_name = _strftime('%Y-%m-%d_%H-%M-%S_', _localtime()) + str(_randint(10000, 99999)) + '.log'

    def _work(self) -> None:
        if self.file_output:
            file_out = open(self.logs_folder + '\\' + self.log_file_name, 'w', encoding = 'utf-8')
        while True:
            packet: LoggerPacket = self.logs_queue.get()
            text = packet.getStr()

            if self.file_output: file_out.write(text + '\n')
            color_id = packet.getColorPrefix()
            if color_id != None:
                text = '\033[0;{}m'.format(color_id) + text
            text += '\033[m'
            print(text, flush = True)

            if packet.level == 'STOP':
                if self.file_output: file_out.close()
                break

    def startLogThread(self) -> None:
        self.logger_thread = _Process(target = self._work)
        self.logger_thread.start()

    def changeWrapper(self, wrapper: _Callable) -> None:
        self.wrapper = wrapper

    def getWarpperInstance(self, phase_name: str) -> LoggerWrapper:
        return self.wrapper(phase_name, self.logs_queue)
    
class ThreadLogger:
    '''`ThreadLogger`与`ProcessLogger`在使用上完全一致, 但是`ThreadLogger`在另一线程上运行, 而`ProcessLogger`在另一进程上运行'''

    def __init__(self, file_output: bool = False, logs_folder_name: str = None) -> None:
        self.logs_queue = _Queue()
        self.logger_thread = None
        self.logs_folder = '.\\Logs' if logs_folder_name == None else logs_folder_name.removesuffix('\\')
        self.log_file_name = ''
        self.file_output = file_output
        self.wrapper = LoggerWrapper

        if self.file_output:
            if not _exists(self.logs_folder):
                _mkdir(self.logs_folder)
            self.log_file_name = _strftime('%Y-%m-%d_%H-%M-%S_', _localtime()) + str(_randint(10000, 99999)) + '.log'

    def _work(self) -> None:
        if self.file_output:
            file_out = open(self.logs_folder + '\\' + self.log_file_name, 'w', encoding = 'utf-8')
        while True:
            packet: LoggerPacket = self.logs_queue.get()
            text = packet.getStr()

            if self.file_output: file_out.write(text + '\n')
            color_id = packet.getColorPrefix()
            if color_id != None:
                text = '\033[0;{}m'.format(color_id) + text
            text += '\033[m'
            print(text, flush = True)

            if packet.level == 'STOP':
                if self.file_output: file_out.close()
                break

    def startLogThread(self) -> None:
        self.logger_thread = _Thread(target = self._work)
        self.logger_thread.start()

    def changeWrapper(self, wrapper: _Callable) -> None:
        self.wrapper = wrapper

    def getWarpperInstance(self, phase_name: str) -> LoggerWrapper:
        return self.wrapper(phase_name, self.logs_queue)