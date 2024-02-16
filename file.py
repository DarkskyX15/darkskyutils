# -*- coding: UTF-8 -*-
"""可能有用的文件处理和路径处理函数"""
from typing import Tuple as _Tuple, List as _List, Callable as _Callable
from multiprocessing import Queue as _Queue
from os.path import getsize as _getsize, join as _join, exists as _exists
from os import walk as _walk, remove as _remove, rmdir as _rmdir, makedirs as _makedirs


def getTotalFileSize(path_list: _List[str]) -> int:
    """返回`path_list`中所有路径对应的文件的总大小, 单位: B"""
    tot_size = 0
    for path in path_list:
        tot_size += _getsize(path)
    return tot_size

def sortWithSize(file_list: _List[str], _reversed: bool = False) -> _List[_Tuple[str, int]]:
    r"""
    用`file_list`中的路径生成如下元组: `(path, file_size)`
    - `file_size`:文件对应的大小
    - `path`:文件对应的路径

    返回由上述元组组成的列表, 并根据文件大小排序, 通过`_reversed`参数改变排列顺序
    """
    raw_list = list()
    for path in file_list:
        raw_list.append((path, _getsize(path)))
    raw_list.sort(key = lambda pair: pair[1], reverse = _reversed)
    return raw_list

def getMultiPaths(folder_path: str) -> _Tuple[_List[str], _List[str]]:
    r"""
    返回一对路径列表:`(file_paths, folder_paths)`
    - `file_paths`:`folder_path`下所有文件的路径列表
    - `folder_paths`:`folder_path`下所有文件夹的路径列表 (包括`folder_path`本身)
    """
    file_path_list = list()
    folder_list = list()
    for filepath, foldernames, filenames in _walk(folder_path):
        for filename in filenames:
            file_path_list.append(_join(filepath, filename))
        folder_list.append(filepath)
    return (file_path_list, folder_list)

def pathRemovePrefix(path_list: _List[str], prefix: str, replaced: str = '.') -> _List[str]:
    r"""
    对于列表中的每个`path`, 将前缀`prefix`替换为`replaced`

    `replaced`默认为 '.'
    """
    after_list = list()
    if replaced.endswith('\\'):
        replaced = replaced.removesuffix('\\')
    if prefix.endswith('\\'):
        prefix = prefix.removesuffix('\\')
    for path in path_list:
        after_list.append(path.replace(prefix, replaced))
    return after_list

def pathAddPrefix(path_list: _List[str], prefix: str, replaced: str = None) -> _List[str]:
    r"""
    对于列表中的每个`path`, 给路径加上前缀`prefix`.

    如果给定了`replaced`参数, 则将每个`path`中的`prefix`替换为`replaced`
    """
    after_list = list()
    if prefix.endswith('\\'):
        prefix = prefix.removesuffix('\\')
    for path in path_list:
        if replaced == None:
            after_list.append(prefix + path)
        else:
            after_list.append(prefix.replace(replaced, prefix, 1))
    return after_list

def sizeToStr(size_by_bite: int) -> str:
    """将字节大小转换成更易读的字符串, 比如: 64MB(B/KB/GB)"""
    size_with_str = str()
    if size_by_bite < 1024:
        size_with_str = str(size_by_bite) + 'B'
    elif 1024 <= size_by_bite < 1048576:
        size_by_bite /= 1024.0
        size_with_str = str(size_by_bite) + 'KB'
    elif 1048576 <= size_by_bite < 1073741824:
        size_by_bite /= 1048576.0
        size_with_str = str(size_by_bite) + 'MB'
    elif 1073741824 <= size_by_bite:
        size_by_bite /= 1073741824.0
        size_with_str = str(size_by_bite) + 'GB'
    return size_with_str

def strToSize(size_str: str) -> int:
    r"""将易读的字符串, 比如: 64.5MB(B/KB/GB) 转换成字节数量.
    #### 转换结果的精度取决于字符串的精度"""
    if 'KB' in size_str:
        size_ = float(size_str.removesuffix('KB'))
        size_ *= 1024.0
        return int(size_)
    elif 'MB' in size_str:
        size_ = float(size_str.removesuffix('MB'))
        size_ *= 1024.0 * 1024.0
        return int(size_)
    elif 'GB' in size_str:
        size_ = float(size_str.removesuffix('GB'))
        size_ *= 1024.0 * 1024.0 * 1024.0
        return int(size_)
    elif 'B' in size_str:
        size_ = int(size_str.removesuffix('B'))
        return size_

def doFileSelect(file_with_attr: _List[_Tuple], filter: _Callable = None) -> _Tuple[_List[_Tuple], _List[_Tuple]]:
    r"""
    用`filter`函数筛选列表中的元组, 元组一般可以为文件路径和属性的组合

    `filter`函数接收一个元组作为其参数, 并返回`True`或`False`表示是否被筛出

    返回由两个列表组成的元组`(筛出的元组列表, 余下的元组列表)`
    """
    trues: _List[_Tuple] = []
    falses: _List[_Tuple] = []
    for obj in file_with_attr:
        if filter(obj): trues.append(obj)
        else: falses.append(obj)
    return trues, falses
    
def getMaxFile(path_list: list[str]) -> int:
    """取`path_list`中所有路径对应文件的最大文件, 返回一个元组`(最大文件大小, 最大文件路径)`"""
    max_size = -1
    max_file_path = ''
    for path in path_list:
        _size = _getsize(path)
        if _size > max_size:
            max_size = _size
            max_file_path = path
    return max_size, max_file_path

def deleteContents(folder_path: str) -> bool:
    r"""
    删除`folder_path`下所有的文件和文件夹.

    如果有文件不能被删除, 返回`False`, 否则返回`True`
    """
    file_list, folder_list = getMultiPaths(folder_path)
    if folder_list:
        folder_list.pop(0)
    flg = True
    for file in file_list:
        try:
            _remove(file)
        except Exception:
            flg = False
            continue
    for folder in folder_list:
        try:
            _rmdir(folder)
        except Exception:
            flg = False
            continue
    return flg

def splitFile(file_path: str, block_cnt: int, buffer_name: str = '', 
              msg_queue: _Queue = None, overwrite_name: str = None) -> bool:
    r"""
    将指定的文件分块
    - `file_path` 为指定文件的路径
    - `block_cnt` 指定该文件将被分成的块数
    - 文件块将默认被保存在 `.\file_split\` 下 (指定`overwrite_name`参数可以改变保存位置)
    - 如果 'buffer' 被指定, 文件块将会被保存在`.\file_split\%buffer_name%\`下
    - 如果 'msg_queue' 被指定, 一旦一个文件块被分割完毕, 代表文件块编号的整数会被推进列表
    #### 文件块直接根据编号命名
    """
    if overwrite_name == None: overwrite_name = 'file_split'
    source_size = _getsize(file_path)
    source_file = open(file_path, 'rb')
    source_file_pointer = 0
    rit_bound = 0
    noir_block_size = source_size // block_cnt
    last_block_size = source_size - noir_block_size * (block_cnt - 1)
    if buffer_name != '':
        file_saved_folder = '.\\{}\\'.format(overwrite_name) + buffer_name
    else:
        file_saved_folder = '.\\' + overwrite_name

    if not _exists(file_saved_folder):
        _makedirs(file_saved_folder)

    for block in range(block_cnt):
        
        filen = file_saved_folder + '\\' + str(block)
        block_output = open(filen, 'wb')

        if block == block_cnt - 1:
            rit_bound += last_block_size
        else:
            rit_bound += noir_block_size
        
        while source_file_pointer < rit_bound:
            size = rit_bound - source_file_pointer
            if size > 1024:
                size = 1024
            block_output.write(source_file.read(size))
            source_file_pointer += size
        
        block_output.close()
        if msg_queue != None:
            msg_queue.put(block)

def mergeFile(save_path: str, block_cnt: int, buffer_name: str = '', 
              msg_queue: _Queue = None, overwrite_name: str = None) -> None:
    r"""
    将文件块整合成单个文件
    - `save_path`指定单个文件保存的路径 (包括文件名和后缀名), `block_cnt`指定文件块的数量.
    - 文件块默认从`.\file_split\`读取 (可以通过指定`overwrite_name`调整).
    - 如果`buffer_name`被指定, 文件块将会从`.\file_split\%buffer_name%\`下读取.
    - 如果`msg_queue`被指定, 文件块整合的过程将由`msg_queue`控制.

    `msg_queue`中只能放入代表文件块编号的整数, 接收到对应的整数后, 该函数将立刻开始尝试对应文件块的整合.
    """
    if overwrite_name == None: overwrite_name = 'file_split'
    output_file = open(save_path, 'wb')

    if buffer_name != '':
        folder_path = '.\\{}\\'.format(overwrite_name) + buffer_name + '\\'
    else:
        folder_path = '.\\{}\\'.format(overwrite_name)
    
    if msg_queue == None:
        for block in range(block_cnt):
            read_file_path = folder_path + str(block)
            block_read = open(read_file_path, 'rb')
            patch = block_read.read(1024)
            while patch:
                output_file.write(patch)
                patch = block_read.read(1024)
            block_read.close()
    else:
        waiting_buffer = []
        waiting_buffer.append(msg_queue.get())
        block_pointer = 0
        file_path = ''
        for block in range(block_cnt):
            while True:
                found_flg = False
                for index in range(len(waiting_buffer)):
                    if waiting_buffer[index] == block_pointer:
                        file_path = folder_path + str(waiting_buffer[index])
                        block_pointer += 1
                        waiting_buffer.pop(index)
                        found_flg = True
                        break
                if not found_flg:
                    waiting_buffer.append(msg_queue.get())
                else:
                    break
            
            block_source = open(file_path, 'rb')
            patch = block_source.read(1024)
            while patch:
                output_file.write(patch)
                patch = block_source.read(1024)
            block_source.close()
    output_file.close()
