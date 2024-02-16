# Skygraph Engine (需要维护)
*注：文档中有‘^’前缀的变量为有默认值的变量，有‘\*’前缀的为可变长度的变量*  
# Introduction
使用该模块创建简单的命令行界面  
**仅适用于Windows新版控制台**
**需要的前置模块：keyboard、win32gui**

如何使用
- 在主文件的根目录新建Scene文件夹
- 在Scene文件夹中编写自己的场景文件
- 在主文件中实例化SceneManager
- 调用SceneManager的startLoop方法  

*使用 pyinstaller 打包时请将自己的场景文件添加至 .spec 文件的 **hiddenimports列表** 中*  

# Components
模块目前由三部分组成
- Graphic.py
- Scene.py
- Widget.py

## Graphic.py
包含了三种文本组件
- TextComponent (普通文本组件)
- VariableText (变量文本组件)
- ComplexText (复杂文本组件)

*后面两种文本组件均继承 TextComponent*  

包含了预置的三种选项类
- BaseOption (基础选项)
- SimpleOption (简单选项)
- BadOption (不能选择的选项)

*后面两种选项类均继承 BaseOption*

包含了坐标类 *COORD*  

包含了方法 *goToXY、 mixedStrLength*  

## Scene.py
包含与场景相关的类
- BaseScene
- SceneManager

## Widget.py
包含预置的各种组件
- BaseWidget
- OptionList
- LabelBox
- InputBox
- DynamicTextPrinter
- Pauser
- ListedText

*所有组件应该继承 BaseWidget 并通过重写其中的方法实现自定义的功能*  


# BaseScene & Scene Manager

## Scene Manager
管理并加载场景  

### 初始化  
```python
def __init__(self: Self@SceneManager) -> None
```

### 属性

`scene_queue` (list) : 存储场景的队列  
`global_vars` (dict) : 储存全局变量的字典  
`working_path` (str) : 程序的工作路径  
`window_handle` (int) : 命令行窗口的句柄  

### 方法  

**setGlobalValue**  
*设置全局变量（所有场景共用）*  
```python
def setGlobalValue(
    self: Self@SceneManager,
    key: str,
    value: Any
) -> None
```
- key (str) 全局变量的名字
- value (Any) 全局变量的值  

**getGlobalValue**  
*获取全局变量*  
```python
def getGlobalValue(
    self: Self@SceneManager,
    key: str
) -> (Any | None)
```
- key (str) 全局变量的名字
- 返回值: 全局变量的值 (Any) *若名字不存在，返回None*  

**removeGlobalValue**  
*删除全局变量*  
```python
def removeGlobalValue(
    self: Self@SceneManager,
    key: str
) -> (Any | None)
```
- key (str) 全局变量的名字
- 返回值: 全局变量的值。*若变量名不存在，则返回None* (Any | None)

**loadScene**  
*将场景加入场景队列的末尾*  
*场景必须存放在主程序根文件夹的Scene目录内*  
```python
def loadScene(
    self: Self@SceneManager,
    scene_name: str
) -> None
```
- scene_name (str) 场景文件名  

**checkFocus**  
*检查程序的命令行窗口是否是前置窗口*  
```python
def checkFocus(self: Self@SceneManager) -> bool
```  
- 返回值: 是否是前置窗口 （bool）  

**startLoop**  
*开始场景循环，循环在场景队列为空时自动结束*  
```python
def startLoop(self: Self@SceneManager) -> None
```

## BaseScene  
场景基类  
### 初始化  
```python
def __init__(
    self: Self@BaseScene,
    scene_manager: SceneManager,
    scene_name: str = 'Untitled'
) -> None
```  
- scene_manager (SceneManager): 场景属于的场景管理器
- scene_name (str): 场景名 *( 默认为 Untitled )*

### 属性  
`scene_manager` (SceneManager): 属于的SceneManager  
`scene_name` (str): 场景名  
`tick_per_sec` (int): 场景每秒的刻数  
`looping_flg` (bool): 场景是否在循环过程中  
`now_tick` (int): 场景经过的刻数  

### 方法  
**setTick**  
*设置场景每秒的刻数*  
```python
def setTick(
    self: Self@BaseScene,
    ticks: int
) -> None
```
- ticks (int): 刻数  

返回值: None  

**getTick**  
*获取场景的刻数*  
```python
def getTick(self: Self@BaseScene) -> int
```
- 返回值: 刻数 (int)  

**getTimeInterval**  
*获取每刻之间的间隔时间，该函数在每刻间被SceneManager调用，来获取 time.sleep() 所需的值*  
```python
def getTimeInterval(self: Self@BaseScene) -> float
```
- 返回值: 秒数 (float)  

**setOverallVar**  
*设置属于场景的全局变量值*  
```python
def setOverallVar(
    self: Self@BaseScene,
    key: str,
    val: Any
) -> None
```
- key (str): 变量名  
- val (Any): 变量值  

**getOverallVar**  
*获取属于场景的全局变量值*  
```python
def getOverallVar(
    self: Self@BaseScene,
    key: str
) -> (Any | None)
```
- key (str): 变量名
- 返回值: 变量值 (Any | None) *变量名不存在时，返回None*  

**enableKeyboardHook**  
*启用该场景的键盘监听*  
```python
def enableKeyboardHook(self: Self@BaseScene) -> None
```  

**addWidget**  
*向场景中添加控件*  
```python
def addWidget(
    self: Self@BaseScene,
    widget: BaseWidget,
    weight: int = 0
) -> None
```
- widget (BaseWidget): 控件对象  
- ^weight (int): 控件的优先级 *(默认值为0)*   

**removeWidget**  
*删除场景中的控件*  
```python
def removeWidget(
    self: Self@BaseScene,
    widget_name: str
) -> bool
```
- widget_name (str): 指定控件的名字
- 返回值: 是否成功删除了控件 (bool)  

**findWidget**  
*查找场景中有对应名称的控件*  
```python
def findWidget(
    self: Self@BaseScene,
    widget_name: str
) -> (BaseWidget | None)
```
- widget_name (str): 指定控件的名字
- 返回值: 控件对象 (BaseWidget) *若控件名不存在，返回None*  

**aliveWidgetNum**
*场景中存活的控件数量*  
```python
def aliveWidgetNum(self: Self@BaseScene) -> int
```
- 返回值: 存活数量 (int)

**pushMsgPacket**  
*向场景的消息队列中发送消息包*  
```python
def pushMsgPacket(
    self: Self@BaseScene,
    packet_sign: str,
    parameters: dict
) -> None
```
- packet_sign (str): 消息包标识符  
- parameters (dict): 消息参数

**scheduleMsg**  
*检查计划消息队列，并发送计划消息*  
```python
def scheduledMsg(self: Self@BaseScene) -> None
```

**addSchedule**  
*添加计划消息事件*  
```python
def addSchedule(
    self: Self@BaseScene,
    interval_tick: int,
    packet_sign: str,
    parameters: dict
) -> None
```
- interval_tick (int): 计划消息的间隔刻数
- packet_sign (str): 消息标识符
- parameters (dict): 消息包参数

**removeSchedule**  
*移除指定的计划消息。注意：只检查消息间隔刻数和消息标识符*  
```python
def removeSchedule(
    self: Self@BaseScene,
    tick: int,
    packet_sign: str
) -> bool
```
- tick (int): 计划消息的间隔刻数  
- packet_sign (str): 消息标识符
- 返回值: 是否删除了指定的计划消息 (bool)  

**getWidgetReturn**  
*获得控件结束时的返回值*  
```python
def getWidgetReturn(
    self: Self@BaseScene,
    widget_name: str
) -> (Any | None)
```
- widget_name (str): 指定控件的名称  
- 返回值: 控件返回的值，*控件名不存在时，返回None*

**reprintScene**  
*重新打印场景，该方法调用每一个处在场景中控件的 reprintWidget 方法*  
```python
def reprintScene(self: Self@BaseScene) -> None
```  

**onStart**  
*该方法在场景进入循环时被调用（在__init__之后）。重写该方法来自定义场景开始时的行为*  
```python
def onStart(self: Self@BaseScene) -> None
```  

**endLoop**
*在下一刻结束该场景的循环*  
```python
def endLoop(self: Self@BaseScene) -> None
```  

**isLooping**  
*该场景是否在循环中*  
```python
def isLooping(self: Self@BaseScene) -> bool
```
- 返回值: 是否在循环中 (bool)  

**onLoop**  
*该方法在每一刻被调用，重写此方法来自定义场景在每一刻的行为*  
```python
def onLoop(self: Self@BaseScene) -> None
```

**onEnd**  
*该方法在场景结束时被调用，重写此方法来自定义场景结束时的行为*  
```python
def onEnd(self: Self@BaseScene) -> None
```

# TextComponent及其子类  
## TextComponent  

最基本的文本组件，几乎所有的文本界面都是由文本组件构成的  

### 初始化  
```python
def __init__(
    self: Self@TextComponent,
    text: str,
    display_mode: DMODE = 'reset',
    front_color: COLOR = 'None',
    back_color: COLOR = 'None'
) -> None
```
- text (str): 文本组件的文本值
- display_mode (str): 显示方式
- front_color (str): 前景色
- back_color (str): 背景色  

**参数解释**  
*DMODE (display mode)*  
|效果|display_mode|
|----|----------|
|原始控制台文本|reset|
|默认|default|
|高亮|highlight|
|带下划线|underlined|
|闪烁|blink|
|反色|reversed|

*COLOR (color)*  
|颜色|color|
|---|---|
|黑色|black|
|红色|red|
|绿色|green|
|黄色|yellow|
|蓝色|blue|
|紫色|purple|
|白色|white|
|青色|cyan|

### 属性  
`pos_attr_list: list[Tuple[Tuple[int, int], str]]`: 字符位置与属性的对应表  
`raw_text: str`: 原始文本  
`final_str`: 带格式的文本  

### 方法  
**remakeFinalStr**  
*重新生成带样式的字符串，该函数会在初始化文本组件时首次调用，同时会在每次输出该文本时重新调用。
注意：一般不需要重写该方法*  
```python
def remakeFinalStr(self: Self@TextComponent) -> None
```  

**\_\_str\_\_**  
*重写了__str__方法，以便直接用 print 输出文本组件来得到带样式的文本
重新生成供输出的字符串
该方法先调用updateText()，再调用remakeFinalStr()*  
```python
def __str__(self: Self@TextComponent) -> str
```  
- 返回值: 带样式的文本 (str)  

**updateText**  
*更新文本
重写该方法以丰富文本组件的内容*  
```python
def updateText(self: Self@TextComponent) -> None
```  

**getRawText**  
*返回文本组件的原始文本*  
```python
def getRawText(self: Self@TextComponent) -> str
```  
- 返回值: 原始文本 (str)  

**getTextAttribute**  
*获取文本组件的属性值
返回一个三元组: (display_mode, front_color, back_color)
可传参数覆盖返回值, 例如: TextComponent('text', 'default', 'green').getTextAttribute(back_color = 'white')
返回: ('default', 'green', 'white')*  
```python
def getTextAttribute(
    self: Self@TextComponent,
    display_mode: DMODE = '',
    front_color: COLOR = '',
    back_color: COLOR = ''
) -> Tuple[str, str, str]
```  
- ^display_mode (str): 覆盖显示模式
- ^front_color (str): 覆盖前景色
- ^back_color (str): 覆盖背景色
- 返回值: 格式元组 (Tuple[str, str, str])  

**getPosAttribute**  
*获取指定位置字符的格式前缀*  
```python
def getPosAttribute(
    self: Self@TextComponent,
    pos: int
) -> str
```  
- pos (int): 字符位置  
- 返回值: 格式前缀 (str)  

*__格式前缀&格式后缀__*  
TextComponent基于控制字符调整控制台输出的颜色和显示模式。格式前缀包含了前景色，背景色，显示模式的信息，格式后缀一律为`/033[m`  

**getEqualBlank**  
*获取与文本值等宽的空字符串*  
```python
def getEqualBlank(self: Self@TextComponent) -> str
```  
- 返回值: 空白字符串 (str)  

## VariableText  
能与变量绑定显示的文本组件  
### 初始化  
```python
def __init__(
    self: Self@VariableText,
    var_name: str,
    display_mode: DMODE = 'reset',
    front_color: COLOR = 'None',
    back_color: COLOR = 'None'
) -> None
```  
- var_name (str): 绑定的场景中的全局变量名
- display_mode (str): 显示模式
- front_color (str): 前景色  
- back_color (str): 背景色

### 属性  
`var_name: str`: 场景的全局变量名  
*其他属性继承TextComponent*  

### 方法  
**attachToScene**  
*绑定场景到文本组件，使文本组件能够查询变量
此方法应在向场景添加该组件后调用，否则报错*  
```python
def attachToScene(
    self: Self@VariableText,
    scene: BaseScene
) -> None
```  
- scene (BaseScene): 需要绑定的场景  

**(重写的) updateText**  
*从场景的全局变量中更新文本值*  
```python
def updateText(self: Self@VariableText) -> None
```  

## ComplexText  
复杂文本组件, 方便不同格式文本组件的同行输出  
### 初始化  
```python
def __init__(
    self: Self@ComplexText,
    *texts: TextComponent
) -> None
```  
- *texts (TextComponent): TextComponent及其子类，但不能是ComplexText  

### 属性  
`texts: tuple[TextComponent, ...]`: 初始化时传入的文本组件元组  
*其他属性继承TextComponent*  

### 方法  
**attachAllVariables**  
*将 texts 中的所有 VariableText 与 scene 关联*
```python
def attachAllVariables(
    self: Self@ComplexText,
    scene: BaseScene
) -> None
```  
- scene (BaseScene): 需要关联的场景对象

**(重写的) remakeFinalStr**  
*重新生成带格式的文本*  
```python
def remakeFinalStr(self: Self@ComplexText) -> None
```  

**(重写的) updateText**  
*更新 texts 中的所有 text*
```python
def updateText(self: Self@ComplexText) -> None
```  

# BaseOption及其子类  
## BaseOption  
OptionList使用的基本选项类  
### 初始化  
```python
def __init__(
    self: Self@BaseOption,
    text: TextComponent,
    tips: TextComponent
) -> None
```  
- text (TextComponent): 选项的文本组件
- tips (TextComponent): 选项提示的文本组件  

### 属性  
