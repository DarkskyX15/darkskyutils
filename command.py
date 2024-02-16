# -*- coding: UTF-8 -*-
r'''
简单的命令解释器, 通过解析命令并改变当前函数的函数对象实现.

#### 避免多进程/线程访问同一个`CommandInterpreter`实例
'''
from typing import Callable as _Callable
from typing import Literal as _Literal
from typing import Tuple as _Tuple
from typing import Union as _Union
from typing import List as _List
from typing import Any as _Any
from json import dumps as _dumps, loads as _loads
from base64 import b64decode as _b64decode, b64encode as _b64encode

class RDSCError(Exception):
    r"""
    RDSC文件格式不正确 (无法编译) 时抛出的错误

    `RDSC: Raw DSCommand file`
    """
    def __init__(self, *args: object) -> None:
        super().__init__(*args)

class CommandError(Exception):
    """`CommandInterpreter`抛出的一般错误"""
    def __init__(self, *args: object) -> None:
        super().__init__(*args)

class CommandInterpreter:
    r'''
    简单的命令解释器, 初始化参数如下:
    - `copy_from` (可选): 传入`CommandInterpreter`的实例, 用于创建副本,
    副本只复制原实例的命令树数据
    - `error`: 错误的处理方式, 默认为`'strict'`, `'strict'`将抛出错误, `'loose'`不抛出错误, 
    只在返回值上做区分

    其他用法参见不同方法的说明
    '''
    def __init__(self, copy_from = None, error: _Literal['strict', 'loose'] = 'strict') -> None:
        self.data = list()
        self.error: _Literal['strict', 'loose'] = error
        self.command_tree_exist = False
        self.present_func: int = None
        self.func_list: _List[_Callable] = []
        self.id_mapping: _List[_Tuple[int, str]] = []
        if copy_from != None:
            self.data = copy_from.data.copy()
            self.id_mapping = copy_from.id_mapping.copy()
            self.command_tree_exist = True
    
    
    def regenerateMapping(self) -> None:
        r'''重新生成函数id与命令的对应表, 该函数一般不用额外调用'''
        self.id_mapping = []
        def dfs_regen(node: _List, front: str) -> None:
            if isinstance(node[1], int):
                self.id_mapping.append((node[1], f'{front} {node[0]}'))
            else:
                for sub in node[1]:
                    dfs_regen(sub, f'{front} {node[0]}')
        dfs_regen(self.data, '')

    def complieRDSC(self, rdsc_path: str) -> bool:
        r"""
        编译并加载命令树, 命令文件必须为`utf-8`编码

        若命令文件不正确, 抛出`RDSCError`
        """
        rdsc_file = open(rdsc_path, 'r', encoding = 'utf-8')
        lines = rdsc_file.read().splitlines()
        lines.append('<')
        rdsc_file.close()
        cmd_count = 0
        line_cnt = 0

        def dfs_complie(parent_cmd: str, front: str) -> list:
            nonlocal line_cnt, cmd_count
            data = []
            while len(lines) > 0:
                line = lines.pop(0)
                line_cnt += 1
                if len(line) < 1:
                    raise RDSCError(f'Empty line for RDSC file at line {line_cnt}: {line}')
                elif len(line) == 1 and line[0] != '<':
                    raise RDSCError(f'Incomplete command name for RDSC file at line {line_cnt}: {line}')
                if line[0] == '-':
                    cmd_count += 1
                    data.append([line.removeprefix('-'), cmd_count])
                    self.id_mapping.append((cmd_count, f'{front} {line[1:]}'))
                elif line[0] == '>':
                    data.append(dfs_complie(line, f'{front} {line[1:]}'))
                elif line[0] == '<':
                    return [parent_cmd.removeprefix('>'), data]
                else:
                    raise RDSCError(f'Invaild sign for RDSC file at line {line_cnt}: {line}')
            
        try:
            self.data = dfs_complie('>ROOT', ' ROOT')
        except RDSCError as e:
            self.data = []
            self.id_mapping = []
            self.command_tree_exist = False
            if self.error == 'strict': raise e
            return False
        else:
            self.command_tree_exist = True
            self.func_list = [None] * len(self.id_mapping)
            return True

    def saveToFile(self, save_path: str, key: int = None) -> bool:
        r"""
        将已加载的命令树保存至文件, 若`key`被指定, 则使用`key`简单加密文件.

        `key`取值任意, 但内部限制在`[0, 256)`
        """
        if not self.command_tree_exist:
            if self.error == 'strict':
                raise CommandError('Could not save command tree to file: command not loaded')
            return False
        try:
            jstr = _dumps(self.data)
            b64str = _b64encode(jstr.encode('utf-8'))
            if key != None:
                key %= 256
                key = abs(key)
                encoded = []
                for byte in b64str:
                    encoded.append(byte ^ key)
                b64str = bytes(encoded)
            f = open(save_path, 'wb')
            f.write(b64str)
            f.close()
        except Exception as e:
            if self.error == 'strict': raise e
            return False
        else: return True

    def loadFromFile(self, load_path: str, key: int = None) -> bool:
        r"""
        从文件读取命令树, 若`key`被指定, 则使用 key 简单解密文件.
        #### 无论是否成功读取, 命令树数据都会被重置.

        若报`Unicode`或`Base64`解码错误, 检查是否遗漏参数`key`或`key`参数是否与文件对应
        """
        try:
            file = open(load_path, 'rb')
            raw_ = file.read()
            file.close()
            if key != None:
                key %= 256
                key = abs(key)
                decoded = []
                for byte in raw_:
                    decoded.append(byte ^ key)
                raw_ = bytes(decoded)
            cooked_ = _b64decode(raw_).decode('utf-8')
            self.data = _loads(cooked_)
        except Exception as e:
            self.command_tree_exist = False
            self.data = []
            self.id_mapping = []
            if self.error == 'strict': raise e
            return False
        else:
            self.command_tree_exist = True
            self.regenerateMapping()
            self.func_list = [None] * len(self.id_mapping)
            return True

    def getJsonStr(self) -> str:
        '''导出Json编码的命令树字符串, 非明文.'''
        return _b64encode(_dumps(self.data).encode('utf-8')).decode('utf-8')

    def loadJsonStr(self, json_str: str) -> bool:
        r'''
        从Json字符串中加载命令树, 建议使用由`getJsonStr`导出的字符串.
        #### 注意: 传入的字符串不能使用`saveToFile`方法得到的字符串
        '''
        try:
            self.data = _loads(_b64decode(json_str).decode('utf-8'))
        except Exception as e:
            self.command_tree_exist = False
            self.data = []
            self.id_mapping = []
            if self.error == 'strict': raise e
            return False
        else:
            self.command_tree_exist = True
            self.regenerateMapping()
            self.func_list = [None] * len(self.id_mapping)
            return True

    def printTree(self) -> None:
        '''在控制台中直接打印命令树'''
        print(self.data)

    def printDetail(self) -> None:
        r'''打印命令与函数id的对应表, 若命令树不存在, 不进行任何输出

        `Command`一栏中的`'ROOT '`在实际使用中应忽略'''
        if not self.command_tree_exist: return
        for index in range(len(self.id_mapping)):
            print(f'[{index}] Func_id: {self.id_mapping[index][0]} | Command:{self.id_mapping[index][1]} | Bind: {self.func_list[self.id_mapping[index][0] - 1]}')
    
    def walkCommand(self, command_line: str) -> _Union[_Tuple[int, _List[str]], None]:
        r'''
        解析`command_line`, 返回对应的叶节点编号和剩余参数的元组

        若叶节点不存在, 节点编号为`-1`, 若命令树不存在, 返回`None`
        '''
        if not self.command_tree_exist:
            if self.error == 'strict':
                raise CommandError(f'Command tree not loaded, present tree data: {self.data}')
            return None

        command_line = command_line.lstrip()
        command_line = command_line.rstrip()
        command_line = 'ROOT ' + command_line
        args = command_line.split(' ')

        def step(children_list: _List) -> int:
            if len(args) == 0:
                if self.error == 'strict':
                    raise CommandError('Error occurred when interpreting command: incomplete command')
                return -1
            key = args.pop(0)
            flg = False
            func_id = 0
            for child in children_list:
                if child[0] == key:
                    flg = True
                    if isinstance(child[1], int):
                        return child[1]
                    else:
                        func_id = step(child[1])
                    break
            if not flg:
                if self.error == 'strict':
                    raise CommandError(f'Error occurred when interpreting command: unknown key \'{key}\'')
                return -1
            return func_id
        
        return step([self.data]), args
    
    def bindFunctions(self, *_functions: _Callable) -> bool:
        r'''按传入的顺序依次将函数对象与函数id绑定, 若命令树不存在, 默认抛出`CommandError`'''
        if not self.command_tree_exist:
            if self.error == 'strict':
                raise CommandError('Can not bind functions: command tree does not exist.')
            return False
        try:
            for index in range(len(_functions)):
                self.func_list[index] = _functions[index]
        except IndexError as e:
            if self.error == 'strict': raise e
            return False
        else: return True
    
    def selectFunction(self, command_line: str) -> _List[str]:
        r'''
        解析`command_line`, 并将当前函数设置成解析结果, 同时将多余的命令项返回, 无多余参数时返回空列表

        默认抛出错误`CommandError`, 设置为不抛出错误时返回`None`
        '''
        result = self.walkCommand(command_line)
        if result == None:
            if self.error == 'strict':
                raise CommandError('Cannot select function: command tree not loaded')
            return None
        if result[0] == -1:
            if self.error == 'strict':
                raise CommandError('Cannot select function: no such command')
            return None
        self.present_func = result[0] - 1
        return result[1]
    
    def pushArgs(self, *args: _Any) -> _Any:
        r'''
        传参并调用当前函数, 返回当前函数的返回值

        出现异常时默认抛出错误, 设置为不报错时返回`None`
        '''
        if self.present_func == None:
            if self.error == 'strict':
                raise CommandError('Function called before selected')
            return None
        if self.func_list[self.present_func] == None:
            if self.error == 'strict':
                raise CommandError(f'No bind function at func_id: {self.present_func}')
            return None
        try:
            result = self.func_list[self.present_func](*args)
        except TypeError:
            args_s = ', '.join([str(ag) for ag in args])
            if self.error == 'strict':
                raise CommandError(f'Error calling function({self.func_list[self.present_func]}): arguments({args_s}) cannot fit in the function')
            return None
        else:
            return result
        