# -*- coding: UTF-8 -*-
import typing, ctypes
from typing import Any

T_COLOR = ('black', 'red', 'green', 'yellow', 'blue', 'purple', 'cyan', 'white', 'None')
T_DMODE = ('default', 'reset', 'highlight', 'underlined', 'blink', 'reversed', 'None')

COLOR = typing.Literal['black', 'red', 'green', 'yellow', 'blue', 'purple', 'cyan', 'white', 'None']
DMODE = typing.Literal['default', 'reset', 'highlight', 'underlined', 'blink', 'reversed', 'None']

FRONT_COLOR = {'black': '30', 'red': '31', 'green': '32', 'yellow': '33', 'blue': '34', 'purple': '35', 'cyan': '36', 'white': '37'}
BACK_COLOR = {'black': '40', 'red': '41', 'green': '42', 'yellow': '43', 'blue': '44', 'purple': '45', 'cyan': '46', 'white': '47'}
MODE_SIGN = {'default': '0', 'reset': '-1', 'highlight': '1', 'underlined': '4', 'blink': '5', 'reversed': '7'}

STD_OUTPUT_HANDLE = -11
OUTPUT_HANDLE = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)

class TextComponent:

    """基础文本组件"""

    def __init__(self, text: str, display_mode: DMODE = 'reset', front_color: COLOR = 'None', back_color: COLOR = 'None') -> None:

        """初始化一个文本组件，以下是参数说明：\n
        text:文本\n
        display_mode:显示模式，默认为reset（默认样式输出）\n
        front_color:前景色\n
        back_color:背景色\n"""

        if display_mode not in T_DMODE:
            display_mode = 'reset'
        if front_color not in T_COLOR:
            front_color = 'None'
        if back_color not in T_COLOR:
            back_color = 'None'

        self.pos_attr_list: typing.List[typing.Tuple[typing.Tuple[int, int], str]] = []
        self.raw_text = text
        self.front_color = front_color
        self.back_color = back_color
        self.display_mode = display_mode
        self.front_color = front_color
        self.back_color = back_color
        self.display_mode = display_mode
        self.final_str = ''
        self.remakeFinalStr()

    def remakeFinalStr(self) -> None:

        """重新生成带样式的字符串\n
        该函数会在初始化文本组件时首次调用\n
        同时会在每次输出该文本时重新调用\n
        注意：一般不需要重写该方法"""

        display_mode = self.display_mode
        front_color = self.front_color
        back_color = self.back_color

        if display_mode == 'reset':
            self.final_str = self.raw_text
        else:
            if front_color == 'None' and back_color == 'None':
                front = '\033[{}m'.format(MODE_SIGN[display_mode])
            elif back_color == 'None':
                front = '\033[{};{}m'.format(MODE_SIGN[display_mode], FRONT_COLOR[front_color])
            else:
                front = '\033[{};{};{}m'.format(MODE_SIGN[display_mode], FRONT_COLOR[front_color], BACK_COLOR[back_color])
            self.prefix = front
            self.final_str = front + self.raw_text + '\033[m'
            self.pos_attr_list.append(((0, len(self.raw_text) - 1), front))
        
    def __str__(self) -> str:
        """重新生成供输出的字符串\n
        该方法先调用updateText()，再调用remakeFinalStr()"""
        self.updateText()
        self.remakeFinalStr()
        return self.final_str

    def updateText(self) -> None:
        """更新文本\n
        重写该方法以丰富文本组件的内容"""
        pass

    def getRawText(self) -> str:
        """返回文本组件的文本值"""
        return self.raw_text

    def getTextAttribute(self, display_mode: DMODE = '', front_color: COLOR = '', back_color: COLOR = '') -> typing.Tuple[str, str, str]:
        """获取文本组件的属性值\n
        返回一个三元组: (display_mode, front_color, back_color)\n
        可传参数覆盖返回值, 例如: TextComponent('text', 'default', 'green').getTextAttribute(back_color = 'white')\n
        返回: ('default', 'green', 'white')"""
        attr_list = [self.display_mode, self.front_color, self.back_color]
        if display_mode:
            attr_list[0] = display_mode
        if front_color:
            attr_list[1] = front_color
        if back_color:
            attr_list[2] = back_color
        return tuple(attr_list)
    
    def getPosAttribute(self, pos: int) -> str:
        """获取指定位置字符的格式前缀"""
        for pos_and_attr in self.pos_attr_list:
            if pos_and_attr[0][0] <= pos <= pos_and_attr[0][1]:
                return pos_and_attr[1]
        return ''

    def getEqualBlank(self) -> str:
        """获取与文本值等宽的空字符"""
        return ' ' * mixedStrLength(self.raw_text)

class VariableText(TextComponent):
    """与变量绑定的文本, 继承文本组件"""
    def __init__(self, var_name: str, display_mode: DMODE = 'reset', front_color: COLOR = 'None', back_color: COLOR = 'None') -> None:
        """初始化组件, 参数说明:\n
        var_name: 绑定的场景中的全局变量名\n
        display_mode, front_color, back_color与文本组件中参数作用一致"""
        super().__init__('NaN', display_mode, front_color, back_color)
        self.var_name = var_name
        self.remakeFinalStr()
    
    def attachToScene(self, scene) -> None:
        """绑定场景到文本组件\n
        此方法在Scene.addWidget(widget)后调用"""
        self.attached_scene = scene

    def updateText(self) -> None:
        """从场景的全局变量中更新文本值"""
        self.raw_text = self.attached_scene.getOverallVar(self.var_name)
        if self.raw_text == None:
            self.raw_text = 'NaN'

class ComplexText(TextComponent):
    """复杂文本组件, 方便不同格式文本组件的同行输出"""
    def __init__(self, *texts: TextComponent) -> None:
        """初始化文本组件, 参数如下:\n
        *texts: 不定数量的文本组件(支持TextComponent和VariableText)"""
        self.raw_text = ''
        self.final_str = ''
        self.pos_attr_list: typing.List[typing.Tuple[typing.Tuple[int, int], str]] = []
        self.texts = texts
        self.remakeFinalStr()
    
    def attachAllVariables(self, scene) -> None:
        """将texts中的所有VariableText与scene关联"""
        for text in self.texts:
            if isinstance(text, VariableText):
                text.attachToScene(scene)

    def remakeFinalStr(self) -> None:
        """重新生成带格式的文本"""
        self.raw_text = ''
        self.final_str = ''
        self.pos_attr_list.clear()
        pointer = 0
        for text in self.texts:
            if text.pos_attr_list:
                self.pos_attr_list.append(((text.pos_attr_list[0][0][0] + pointer, text.pos_attr_list[0][0][1] + pointer), text.pos_attr_list[0][1]))
            pointer += len(text.getRawText()) + 1
            self.raw_text += text.getRawText() + ' '
            self.final_str += text.final_str + ' '
        self.raw_text = self.raw_text.rstrip()
        self.final_str = self.final_str.rstrip()
    
    def updateText(self) -> None:
        """更新texts中的所有text"""
        for text in self.texts:
            text.updateText()
            text.remakeFinalStr()

class BaseOption:
    """OptionList使用的基本选项类"""
    def __init__(self, text: TextComponent, tips: TextComponent) -> None:
        """初始化控件, 参数说明:\n
        text: 选项的文本组件\n
        tips: 选项提示的文本组件"""
        self.text = text
        self.text_chosen = TextComponent(text.getRawText(), *text.getTextAttribute(back_color = 'white'))
        self.tips = tips

    def onChosen(self) -> typing.Any:
        """重写该方法以自定义该选项被选择时的动作"""
        pass

    def getNormalText(self) -> TextComponent:
        """获取选项没被选中时显示的文本组件"""
        return self.text
    
    def getHoverText(self) -> TextComponent:
        """获取选项被选中时显示的文本组件"""
        return self.text_chosen
    
    def getTipText(self) -> typing.Union[TextComponent, None]:
        """获取选项相关提示的文本组件"""
        return self.tips
    
    def changeTip(self, _tip: TextComponent) -> None:
        """更改选项相关提示的文本组件"""
        self.tips = _tip

class SimpleOption(BaseOption):
    def __init__(self, text: TextComponent, option_index: int, tip: TextComponent = TextComponent('')) -> None:
        super().__init__(text, tip)
        self.index = option_index
    
    def onChosen(self) -> typing.Any:
        return self.index

class BadOption(BaseOption):
    def __init__(self, text: TextComponent) -> None:
        tips = TextComponent('该选项暂时不可用', 'highlight', 'red')
        super().__init__(text, tips)
    
    def onChosen(self) -> Any:
        return None

class COORD(ctypes.Structure):
    _fields_ = [('X', ctypes.c_short), ('Y', ctypes.c_short)]
    def __init__(self, x: int, y: int) -> None:
        self.X = x
        self.Y = y

def goToXY(position: COORD) -> None:
    ctypes.windll.kernel32.SetConsoleCursorPosition(OUTPUT_HANDLE, position)

def mixedStrLength(s: str) -> int:
    _len = 0
    for letter in s:
        if letter.isascii():
            _len += 1
        else:
            _len += 2
    return _len
