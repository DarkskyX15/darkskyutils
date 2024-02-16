# -*- coding: UTF-8 -*-
r'''
简单的配置文件操作, 查看`Config`类的说明了解用法

#### 注意: 避免在多个线程/进程中访问同一个实例
'''
from typing import Any as _Any, Dict as _Dict, Literal as _Literal, Union as _Union, List as _List
from base64 import b64encode as _b64encode, b64decode as _b64decode
from json import dumps as _dumps, loads as _loads
from os.path import exists as _exists
from os import mkdir as _mkdir

CONFIGTYPE = _Literal['simple', 'json', 'encrypted']

class SimpleConfigError(Exception):
    def __init__(self, line: int, e_type: str, t_type: int) -> None:
        if t_type == 0:
            super().__init__('Cannot interpret simple config file at line {}: {}'.format(line, e_type))
        else:
            super().__init__('Cannot save simple config file: {}'.format(e_type))

class Config:
    r'''
    配置文件类, 参数说明:
    - `config_name`: 配置文件的名称, 启用树状储存后能够用`.`表层级 (如: `test.example.foo`)
    - `config_folder`: 保存配置文件的根文件夹, `None`时默认为`'.\\Configs'`
    - `tree_storage`: 开启时按照配置文件名的层级储存配置文件, 默认为`False`
    - `error`: 错误提示类型, 为`'strict'`时遇部分错误会抛出, 为`'loose'`时遇错误仅会将返回值设为`False`

    所有的配置文件有默认后缀名`.cfg`, `config_name`不带后缀名

    查看类中的方法的说明来了解基本用法, 如`loadFromFile`, `saveToFile`等
    '''
    def __init__(self, config_name: str, config_folder: str = None, 
                 tree_storage: bool = False, error: _Literal['strict', 'loose'] = 'loose') -> None:
        self.config_folder: str = '.\\Configs' if config_folder == None else config_folder.removesuffix('\\')
        self.config_name: str = config_name
        self.tree_storage: bool = tree_storage
        self.config_data: _Dict[str, _Any] = dict()
        self.error: _Literal['strict', 'loose'] = error
        
        if not _exists(self.config_folder):
            _mkdir(self.config_folder)
        if self.tree_storage:
            sub_paths = self.config_name.split('.')
            if len(sub_paths) <= 1:
                self.config_name = sub_paths[0]
                sub_folder = self.config_folder
            else:
                self.config_name = sub_paths[-1]
                sub_folder = self.config_folder
                for sub in sub_paths[:-1]:
                    sub_folder += '\\' + sub
                    if not _exists(sub_folder):
                        _mkdir(sub_folder)
            self.config_path = sub_folder + '\\' + self.config_name
        else:
            self.config_path = self.config_folder + '\\' + self.config_name
        self.config_path += '.cfg'
    
    def __str__(self) -> str:
        return str(self.config_data)

    def loadFromFile(self, config_type: CONFIGTYPE, key: bytes = None) -> bool:
        r'''
        从文件中加载配置文件, 参数说明:

        - `config_type`: 配置文件格式
        - `key`: 当配置文件为加密文件时使用的密钥

        配置文件格式共有3种: `simple, json, encrypted`
        ## simple
        `simple`为简单的, 易于编辑的配置文件, 格式如下: `[数据类型首字母]:[键名]:[值]`

        支持的数据类型有: `int, float, bool, str, list`, 
        用`\`连接因过长而换行的配置条目.
        #### 注意: 列表元素仅支持与上述相同的类型, 可以用任意符号分隔列表(或不分隔), 列表中元素用`()`包裹, 列表中元素不能包含键名.
        当`simple`类型配置文件出现格式错误, 且错误提示类型为`'strict'`时, 会抛出`SimpleConfigError`.
        
        ## json
        `json`类型使用Python内置的`json`库进行配置的打包, 所有的配置会被放入一个字典, 
        配置文件中只保存代表此字典的JSON字符串.
        ## encrypted
        `encrypted`类型本质是经过简单加密的配置字符串, 使用该类型时必须给定`key`值, 否则返回`False`但不报错.
        '''
        try:
            file = open(self.config_path, 'r', encoding = 'utf-8')
            file_data = file.read()
            file.close()
        except Exception as e:
            if self.error == 'strict': raise e
            return False
        
        success = True
        if config_type == 'simple':
            def do_interpret(pcs: str) -> object:
                args = pcs.split(':')
                item_type = args[0]
                content = ':'.join(args[1:])
                if item_type == 's':
                    return (content, 'SUCCESS')
                elif item_type == 'l':
                    split_stack: _List[int] = []
                    elements: _List[str] = []
                    for index in range(len(content)):
                        if content[index] == '(':
                            split_stack.append(index)
                        if content[index] == ')':
                            front = split_stack.pop()
                            if not len(split_stack):
                                elements.append(content[front: index + 1])
                    if len(split_stack) > 0:
                        return (None, 'Unpaired brackets')
                    res: _List[_Any] = []
                    for ele in elements:
                        sub_res = do_interpret(ele[1:-1])
                        if sub_res[1] != 'SUCCESS': return sub_res
                        res.append(sub_res[0])
                    return (res, 'SUCCESS')
                elif item_type == 'i':
                    try: res = int(content)
                    except Exception: return (None, 'Bad format for int')
                    else: return (res, 'SUCCESS')
                elif item_type == 'f':
                    try: res = float(content)
                    except Exception: return (None, 'Bad format for float')
                    else: return (res, 'SUCCESS')
                elif item_type == 'b':
                    if content == 'True': return (True, 'SUCCESS')
                    elif content == 'False': return (False, 'SUCCESS')
                    else: return (None, 'Bad format for bool')
                else: return (None, 'Unkown type')

            raw_lines = file_data.splitlines()
            config_lines: _List[str] = []
            in_connection = False
            joined_line = ''
            for r_line in raw_lines:
                if not r_line:
                    config_lines.append(r_line)
                    continue
                if r_line[-1] == '\\':
                    in_connection = True
                    joined_line += r_line[:-1]
                else:
                    if in_connection:
                        joined_line += r_line
                        config_lines.append(joined_line)
                        in_connection = False
                    else:
                        config_lines.append(r_line)
            
            for index in range(len(config_lines)):
                line: str = config_lines[index].lstrip()
                if not line: continue
                if line[0] == '#': continue
                args = line.split(':')
                if len(args) < 3:
                    if self.error == 'strict':
                        raise SimpleConfigError(index, 'too few arguments.', 0)
                    else: success = False
                c_name = args[1]
                c_obj = do_interpret(':'.join([args[0]] + args[2:]))
                if c_obj[1] != 'SUCCESS':
                    if self.error == 'strict': 
                        raise SimpleConfigError(index + 1, 'Cannot load \'{}\' with type {} [{}]'.format(line[1:], line[0], c_obj[1]), 0)
                    success = False
                else:
                    self.config_data[c_name] = c_obj[0]
        
        elif config_type == 'json':
            try:
                self.config_data = _loads(file_data)
            except Exception as e:
                if self.error == 'strict': raise e
                success = False
            else: success = True
        
        elif config_type == 'encrypted':
            if key == None: return False
            try:
                dected = []
                encted = _b64decode(file_data)
                for byte in encted:
                    dected.append(byte ^ key)
                self.config_data = _loads(bytes(dected).decode('utf-8'))
            except Exception as e:
                if self.error == 'strict': raise e
                success = False
            else: success = True

        else:
            success = False
        return success

    def saveToFile(self, config_type: CONFIGTYPE, key: bytes = None) -> bool:
        r'''`saveToFile`将配置保存到文件,参数说明与`loadFromFile`完全一致'''
        try:
            file = open(self.config_path, 'w', encoding = 'utf-8')
        except Exception as e:
            if self.error == 'strict': raise e
            return False
        success = True
        if config_type == 'simple':
            def make_list_config(objs: _List[_Any]) -> str:
                strf_list: str = ''
                for obj in objs:
                    if isinstance(obj, bool):
                        strf_list += f'(b:{obj}), '
                    elif isinstance(obj, int):
                        strf_list += f'(i:{obj}), '
                    elif isinstance(obj, float):
                        strf_list += f'(f:{obj}), '
                    elif isinstance(obj, str):
                        strf_list += f'(s:{obj}), '
                    elif isinstance(obj, list):
                        res = make_list_config(obj)
                        if res[1] != 'SUCCESS':
                            return res
                        strf_list += f'(l:{res[0]}), '
                    else:
                        return (None, f'Unsupported type({obj})')
                return (strf_list.removesuffix(', '), 'SUCCESS')

            for item in self.config_data.items():
                if isinstance(item[1], bool):
                    file.write('{}:{}:{}\n'.format('b', item[0], item[1]))
                elif isinstance(item[1], int):
                    file.write('{}:{}:{}\n'.format('i', item[0], item[1]))
                elif isinstance(item[1], float):
                    file.write('{}:{}:{}\n'.format('f', item[0], item[1]))
                elif isinstance(item[1], str):
                    file.write('{}:{}:{}\n'.format('s', item[0], item[1]))
                elif isinstance(item[1], list):
                    res = make_list_config(item[1])
                    if res[1] != 'SUCCESS':
                        if self.error == 'strict':
                            raise SimpleConfigError('', f'error compiling list({item[1]}) [{res[1]}]', 1)
                        else:
                            success = False
                            continue
                    file.write('{}:{}:{}\n'.format('l', item[0], res[0]))
                else:
                    if self.error == 'strict':
                        raise SimpleConfigError('', f'unsupported data type({item[1]}).', 1)
                    else: success = False
            file.close()
        
        elif config_type == 'json':
            try:
                file.write(_dumps(self.config_data))
            except Exception as e:
                if self.error == 'strict': raise e
                success = False
            finally: file.close()
        
        elif config_type == 'encrypted':
            if key == None:
                file.close()
                return False
            try:
                enctped = []
                for byte in _dumps(self.config_data).encode('utf-8'):
                    enctped.append(byte ^ key)
                file.write(_b64encode(bytes(enctped)).decode('utf-8'))
            except Exception as e:
                if self.error == 'strict': raise e
                success = False
            finally: file.close()
        else:
            success = False
        return success
    
    def queryConfig(self, key: str) -> _Union[_Any, None]:
        r'''取得`key`所对应的配置值. 若`key`不存在, 返回`None`'''
        return self.config_data.get(key, None)

    def checkConfig(self, key: str) -> bool:
        r'''检查配置文件键值中是否存在`key`. 若存在, 返回`True`, 否则`False`'''
        return False if self.config_data.get(key, None) != None else True

    def setConfig(self, key: str, val: _Any) -> bool:
        r'''设置`key`所对应的配置值. 若对应值存在, 则覆盖'''
        self.config_data[key] = val
    
    def delConfig(self, key: str) -> _Union[_Any, None]:
        r'''删除`key`对应的键值对, 并返回其值. 若键不存在, 返回`None`'''
        self.config_data.pop(key, None)
    