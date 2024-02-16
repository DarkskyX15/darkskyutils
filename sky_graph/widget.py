# -*- coding: UTF-8 -*-
import typing
from sky_lib.sky_graph.graphic import BaseOption, COORD, TextComponent, ComplexText, VariableText, goToXY, mixedStrLength


class BaseWidget:
    def __init__(self, widget_name: str) -> None:
        self.name = widget_name
        self.keyboard_global_hook = False
        self.refresh_tag = True

    def setKeyboardGlobal(self) -> None:
        self.keyboard_global_hook = True
 
    def isGlobalKeyHook(self) -> bool:
        return self.keyboard_global_hook

    def attachToScene(self, scene) -> None:
        self.attached_scene = scene
    
    def setNeedRefresh(self) -> None:
        self.refresh_tag = True

    def doNeedRefresh(self) -> bool:
        return self.refresh_tag

    def receiveKeyboard(self, key_name: str, event_type: str) -> bool:
        return False
    
    def receiveMsgPacket(self, packet_sign: str, parameters: dict) -> bool:
        return False

    def __refreshWidget__(self):
        self.refresh_tag = False
        return self.refreshWidget()

    def __removeWidget__(self) -> None:
        self.removeWidget()
        self.attached_scene.pushMsgPacket('WIDGET_REMOVED', {'widget_name': self.name})
    
    def removeWidget(self) -> None:
        pass

    def refreshWidget(self) -> typing.Union[typing.Any, None]:
        pass

    def reprintWidget(self) -> None:
        pass

class ParamaterChecker:
    def __init__(self, parameters: dict) -> None:
        self.parameters = parameters
    
    def checkConsistence(self, paras: dict) -> bool:
        items = self.parameters.items()
        for item in items:
            if item[1] != paras.get(item[0], None):
                return False
        return True

class ListenEvent:
    def __init__(self) -> None:
        self.activated = False
        self.operate_type: str = 'None'
        self.attached_scene = None
        self.criteria: list[typing.Tuple[str, ParamaterChecker]] = []
        self.judge_results: list[bool] = []
        self.do_not_remove: bool = False
        self.target_widget: BaseWidget = None
        self.widget_name: str = ''
        self.widget_weight = 0

    def bindScene(self, scene) -> None:
        self.attached_scene = scene

    def setEndScene(self) -> None:
        self.operate_type = 'ENDSCENE'
        self.activated = True

    def setAddWidget(self, target_widget: BaseWidget, weight: int = 0) -> None:
        self.target_widget = target_widget
        self.operate_type = 'ADDWIDGET'
        self.widget_weight = weight
        self.activated = True

    def setRemoveWidget(self, target_widget_name: str) -> None:
        self.widget_name = target_widget_name
        self.operate_type = 'REMOVEWIDGET'
        self.activated = True

    def appendCriteria(self, packet_sign: str, para_checker: ParamaterChecker) -> None:
        self.criteria.append((packet_sign, para_checker))
        self.judge_results.append(False)

    def appendKeyboard(self, key_name: str, up_or_down: typing.Literal['up', 'down']) -> None:
        self.criteria.append(('KEYBOARD', ParamaterChecker({'key_name': key_name, 'event_type': up_or_down})))
        self.judge_results.append(False)

    def setReuse(self) -> None:
        self.do_not_remove = True

    def onCheck(self, packet_sign: str, parameters: dict) -> bool:
        for index in range(len(self.criteria)):
            if self.criteria[index][0] == packet_sign:
                if self.criteria[index][1].checkConsistence(parameters):
                    self.judge_results[index] = True
        for res in self.judge_results:
            if not res: return False
        return True

    def onActivate(self) -> None:
        self.judge_results.clear()
        for index in range(len(self.criteria)):
            self.judge_results.append(False)
        
        if self.operate_type == 'ENDSCENE':
            self.attached_scene.endLoop()
        elif self.operate_type == 'ADDWIDGET':
            self.attached_scene.addWidget(self.target_widget, self.widget_weight)
        elif self.operate_type == 'REMOVEWIDGET':
            self.attached_scene.removeWidget(self.widget_name)

class OptionList(BaseWidget):
    def __init__(self, *options: BaseOption, start_pos: COORD = COORD(0, 0), direction: typing.Literal['auto', 'vertical'] = 'auto'
                 , max_width: int = 60, widget_name: str, use_list: list[BaseOption] = None) -> None:
        super().__init__(widget_name)
        if use_list != None:
            options = use_list
        single_max_length = -1
        for option in options:
            single_max_length = max(single_max_length, mixedStrLength(option.getNormalText().getRawText()),
                                    mixedStrLength(option.getTipText().getRawText()))
        option_per_line = max_width // single_max_length
        if direction == 'vertical':
            option_per_line = 1
        
        self.start_pos = start_pos
        self.width = min(option_per_line, len(options)) * single_max_length + len(options)
        self.length = len(options) // option_per_line + (len(options) % option_per_line != 0)
        self.direct = (0, 0)
        self.first_print = True

        x_iter = start_pos.X
        y_iter = start_pos.Y + 1
        self.option_pos_list: typing.List[typing.List[typing.Tuple[COORD, BaseOption]]] = []
        option_pos_line = []
        option_pointer = 0
        line_pt = 0

        while True:
            option_pos_line.append((COORD(x_iter, y_iter), options[option_pointer]))

            option_pointer += 1
            x_iter += single_max_length + 1
            line_pt += 1
            if line_pt >= option_per_line:
                self.option_pos_list.append(option_pos_line)
                option_pos_line = []
                line_pt = 0
                x_iter = self.start_pos.X
                y_iter += 1

            if option_pointer >= len(options):
                self.option_pos_list.append(option_pos_line)
                break
        
        self.up_key = 'up'
        self.down_key = 'down'
        self.left_key = 'left'
        self.right_key = 'rigth'
        self.option_x = 0
        self.option_y = 0
        self.var_key = None
        self.modifier = None
        self.tip_coord = COORD(self.start_pos.X + 1, self.start_pos.Y + self.length + 1)
    
    def overWriteKeys(self, up_key: str, down_key: str, left_key: str, right_key: str) -> None:
        self.up_key = up_key
        self.down_key = down_key
        self.left_key = left_key
        self.right_key = right_key

    def receiveKeyboard(self, key_name: str, event_type: str) -> bool:
        if event_type == 'down':
            if key_name == 'enter':
                self.direct = (1, 1)
                return True
            elif key_name == self.left_key:
                self.direct = (-1, 0)
                return True
            elif key_name == self.up_key:
                self.direct = (0, -1)
                return True
            elif key_name == self.down_key:
                self.direct = (0, 1)
                return True
            elif key_name == self.right_key:
                self.direct = (1, 0)
                return True
            return False
        else:
            return False

    def bindGlobalVar(self, key: str, modifier: typing.Callable = None) -> None:
        self.var_key = key
        self.modifier = modifier

    def firstPrint(self) -> None:
        split_line = TextComponent('-' * self.width, 'default', 'purple')
        goToXY(self.start_pos)
        print(split_line, end = '', flush = True)
        for pos_option_line in self.option_pos_list:
            for pos_option in pos_option_line:
                goToXY(pos_option[0])
                print(pos_option[1].getNormalText(), end = '', flush = True)
        goToXY(COORD(self.start_pos.X, self.start_pos.Y + self.length + 1))
        print('>', end = '', flush = True)  
        goToXY(COORD(self.start_pos.X, self.start_pos.Y + self.length + 2))
        print(split_line, end = '', flush = True)

        goToXY(self.tip_coord)
        print(TextComponent('...', 'default', 'yellow'), end = '', flush = True)
        goToXY(self.option_pos_list[self.option_y][self.option_x][0])
        print(self.option_pos_list[self.option_y][self.option_x][1].getHoverText(), end = '', flush = True)

    def reprintWidget(self) -> None:
        split_line = TextComponent('-' * self.width, 'default', 'purple')
        goToXY(self.start_pos)
        print(split_line, end = '', flush = True)
        for pos_option_line in self.option_pos_list:
            for pos_option in pos_option_line:
                goToXY(pos_option[0])
                print(pos_option[1].getNormalText(), end = '', flush = True)
        goToXY(COORD(self.start_pos.X, self.start_pos.Y + self.length + 1))
        print('>', end = '', flush = True)
        goToXY(COORD(self.start_pos.X, self.start_pos.Y + self.length + 2))
        print(split_line, end = '', flush = True)

        goToXY(self.tip_coord)
        print(self.option_pos_list[self.option_y][self.option_x][1].getTipText(), end = '', flush = True)
        goToXY(self.option_pos_list[self.option_y][self.option_x][0])
        print(self.option_pos_list[self.option_y][self.option_x][1].getHoverText(), end = '', flush = True)

    def refreshWidget(self):
        if self.first_print:
            self.first_print = False
            self.firstPrint()
        
        if self.direct != (0, 0):
            self.attached_scene.pushMsgPacket('OPLIST_CHANGE', {'widget_name': self.name})

            if self.direct == (1, 1):
                chosen = self.option_pos_list[self.option_y][self.option_x][1].onChosen()
                if chosen != None:
                    self.attached_scene.pushMsgPacket('OPLIST_CHOSEN', {'widget_name': self.name, 'parameters': chosen})
                    if self.var_key != None:
                        if self.modifier != None:
                            self.attached_scene.setOverallVar(self.var_key, self.modifier(chosen))
                        else:
                            self.attached_scene.setOverallVar(self.var_key, chosen)
                    return chosen

            else:
                goToXY(self.option_pos_list[self.option_y][self.option_x][0])
                print(self.option_pos_list[self.option_y][self.option_x][1].getNormalText(), end = '', flush = True)

                if 0 <= self.option_x + self.direct[0] <= len(self.option_pos_list[self.option_y]) - 1:
                    self.option_x += self.direct[0]
                if 0 <= self.option_y + self.direct[1] <= len(self.option_pos_list) - 1:
                    if self.option_x < len(self.option_pos_list[self.option_y + self.direct[1]]):
                        self.option_y += self.direct[1]
                    
                goToXY(self.tip_coord)
                print(' ' * (self.width - 1), end = '', flush = True)
                goToXY(self.tip_coord)
                print(self.option_pos_list[self.option_y][self.option_x][1].getTipText(), end = '', flush = True)
                goToXY(self.option_pos_list[self.option_y][self.option_x][0])
                print(self.option_pos_list[self.option_y][self.option_x][1].getHoverText(), end = '', flush = True)

            self.direct = (0, 0)

    def removeWidget(self) -> None:
        blank = ' ' * self.width
        for index in range(self.length + 3):
            goToXY(COORD(self.start_pos.X, self.start_pos.Y + index))
            print(blank, end = '', flush = True)
        self.attached_scene.reprintScene()

class LabelBox(BaseWidget):
    def __init__(self, *textlines: TextComponent, start_pos: COORD, anchor: typing.Literal['left', 'right', 'mid'] = 'left',
                  widget_name: str) -> None:
        super().__init__(widget_name)
        if anchor not in ('left', 'right', 'mid'):
            anchor = 'left'
        self.anchor = anchor
        self.start_pos = start_pos
        self.width = -1
        self.textlines = textlines
        self.dynamic = False
        self.remakePositions()

    def attachAllVariables(self) -> None:
        for text in self.textlines:
            if isinstance(text, VariableText):
                text.attachToScene(self.attached_scene)
            elif isinstance(text, ComplexText):
                text.attachAllVariables(self.attached_scene)

    def setWaitMsg(self, packet_sign: str, key: str, value: typing.Any) -> None:
        self.wait_sign = packet_sign
        self.wait_key = key
        self.wait_value = value
        self.dynamic = True

    def receiveMsgPacket(self, packet_sign: str, parameters: dict) -> bool:
        if not self.dynamic:
            return False
        if packet_sign == self.wait_sign and parameters[self.wait_key] == self.wait_value:
            self.attached_scene.pushMsgPacket('LABEL_RECVMSG', {'widget_name': self.name})
            goToXY(self.start_pos)
            print(' ' * (self.width + 2))
            for text in self.textlines:
                text.updateText()
                text.remakeFinalStr()
            self.remakePositions()
            self.setNeedRefresh()
            return True
        return False

    def remakePositions(self):
        start_pos = self.start_pos
        self.width = -1
        for text in self.textlines:
            self.width = max(self.width, mixedStrLength(text.getRawText()))
        mid = self.width // 2 + start_pos.X + 1
        self.pos_and_text: typing.List[typing.Tuple[COORD, TextComponent]] = []
        pos_x, pos_y = start_pos.X, start_pos.Y
        for text in self.textlines:
            length = mixedStrLength(text.getRawText())
            if self.anchor == 'left':
                self.pos_and_text.append((COORD(pos_x + 1, pos_y), text))
            elif self.anchor == 'right':
                self.pos_and_text.append((COORD(pos_x + 1 + self.width - length, pos_y), text))
            elif self.anchor == 'mid':
                self.pos_and_text.append((COORD(mid - length // 2, pos_y), text))
            pos_y += 1

    def refreshWidget(self):
        self.reprintWidget()

    def reprintWidget(self) -> None:
        pos_y = self.start_pos.Y
        pos_end = self.start_pos.X + 1 + self.width
        for pos_text in self.pos_and_text:
            goToXY(COORD(self.start_pos.X, pos_y))
            print(TextComponent(r'|', 'default', 'purple'))
            goToXY(pos_text[0])
            print(pos_text[1])
            goToXY(COORD(pos_end, pos_y))
            print(TextComponent(r'|', 'default', 'purple'))
            pos_y += 1

    def removeWidget(self) -> None:
        blank = ' ' * (self.width + 2)
        for pos_text in self.pos_and_text:
            goToXY(COORD(self.start_pos.X, pos_text[0].Y))
            print(blank)
        self.attached_scene.reprintScene()

class InputBox(BaseWidget):
    def __init__(self, input_title: TextComponent, widget_name: str, 
                 start_pos: COORD, ispassword: bool = False, max_width: int = -1) -> None:
        super().__init__(widget_name)
        self.input_title = input_title
        self.linked = False
        self.link_value = None
        self.start_pos = start_pos
        self.display_str = ''
        self.data_str = ''
        self.finish_tag = False
        self.ispass = ispassword
        self.cursor_pos = 0
        self.width = max(mixedStrLength(input_title.getRawText()), max_width)
    
    def setConsistence(self, link_value: str) -> None:
        self.linked = True
        self.link_value = link_value

    def receiveKeyboard(self, key_name: str, event_type: str) -> bool:
        if key_name == 'esc':
            if self.linked:
               self.finish_tag = True 
            else:
                return False
        
        if event_type == 'down':
            if key_name == 'enter':
                if not self.linked:
                    self.finish_tag = True
                else:
                    self.attached_scene.setOverallVar(self.link_value, self.data_str)
                    self.attached_scene.pushMsgPacket('INPUT_RECV', {'widget_name': self.name})
                    self.data_str = ''
                    self.display_str = ''
                    self.cursor_pos = 0
                    self.setNeedRefresh()
                    return True
            
            if key_name == 'left':
                if self.cursor_pos - 1 >= 0:
                    self.cursor_pos -= 1
            elif key_name == 'right':
                if self.cursor_pos + 1 <= len(self.data_str):
                    self.cursor_pos += 1
            
            if key_name == 'home':
                self.cursor_pos = 0
            elif key_name == 'end':
                self.cursor_pos = len(self.data_str)

            if key_name == 'backspace':
                if self.cursor_pos <= 0:
                    return True
                self.data_str = self.data_str[:self.cursor_pos - 1] + self.data_str[self.cursor_pos:]
                if self.ispass:
                    self.display_str = self.display_str.removesuffix('*')
                else:
                    self.display_str = self.data_str
                
                if self.cursor_pos - 1 >= 0:
                    self.cursor_pos -= 1

            if key_name.isascii() and len(key_name) == 1 and len(self.data_str) < self.width:
                self.data_str = self.data_str[:self.cursor_pos] + key_name + self.data_str[self.cursor_pos:]
                if self.cursor_pos + 1 <= self.width + 1:
                    self.cursor_pos += 1
                if self.ispass:
                    self.display_str += '*'
                else:
                    self.display_str = self.data_str      
            return True
        return False

    def reprintWidget(self) -> None:
        for y in range(3):
            goToXY(COORD(self.start_pos.X, self.start_pos.Y + y))
            print(TextComponent(r'|', 'default', 'purple'), ' ' * self.width)
            goToXY(COORD(self.start_pos.X + 1 + self.width, self.start_pos.Y + y))
            print(TextComponent(r'|', 'default', 'purple'))
        
        goToXY(COORD(self.start_pos.X + 1, self.start_pos.Y))
        print(self.input_title)
        goToXY(COORD(self.start_pos.X + 1, self.start_pos.Y + 1))
        print(self.display_str)
        goToXY(COORD(self.start_pos.X + self.cursor_pos + 1, self.start_pos.Y + 2))
        print(TextComponent('^', 'highlight', 'yellow'))

    def refreshWidget(self) -> typing.Any | None:
        if self.finish_tag:
            return self.data_str
        self.reprintWidget()

    def removeWidget(self) -> None:
        blank = ' ' * (self.width + 2)
        for y in range(3):
            goToXY(COORD(self.start_pos.X, self.start_pos.Y + y))
            print(blank)
        self.attached_scene.reprintScene()

class DynamicTextPrinter(BaseWidget):
    def __init__(self, text: TextComponent, tick_per_charcter: int, widget_name: str, 
                 start_pos : COORD, max_width: int = 0) -> None:
        super().__init__(widget_name)
        self.start_pos = start_pos
        self.text = text
        self.tick = 0
        self.tot = 0
        self.line_width = 0
        self.line = 0
        self.interval_tick = tick_per_charcter
        self.width = mixedStrLength(text.getRawText())
        if max_width > 2:
            self.width = max_width
        self.inprint = True

    def receiveKeyboard(self, key_name: str, event_type: str) -> bool:
        if event_type == 'down' and key_name == 'space':
            if self.inprint:
                self.inprint = False
                self.attached_scene.pushMsgPacket('DTP_FIN', {'widget_name': self.name})
                self.reprintWidget()
                return True
        return False

    def refreshWidget(self) -> typing.Any | None:
        if self.inprint:
            self.tick += 1
            if self.tick >= self.interval_tick:
                if self.tot >= len(self.text.getRawText()):
                    self.inprint = False
                    self.attached_scene.pushMsgPacket('DTP_FIN', {'widget_name': self.name})
                else:
                    if self.line_width + mixedStrLength(self.text.getRawText()[self.tot]) > self.width:
                        self.line += 1
                        goToXY(COORD(self.start_pos.X, self.start_pos.Y + self.line))
                        self.line_width = mixedStrLength(self.text.getRawText()[self.tot])
                    else:
                        goToXY(COORD(self.start_pos.X + self.line_width, self.start_pos.Y + self.line))
                        self.line_width += mixedStrLength(self.text.getRawText()[self.tot])
                    front = self.text.getPosAttribute(self.tot)
                    if front:
                        end = '\033[m'
                    else:
                        end = ''
                    print(front + self.text.getRawText()[self.tot] + end)
                    self.tot += 1
                    self.tick = 0
            self.setNeedRefresh()

    def reprintWidget(self) -> None:
        pos_x = pos_y = 0
        tot = 0
        length = len(self.text.getRawText())
        while tot < length:
            if pos_x + mixedStrLength(self.text.getRawText()[tot]) > self.width:
                pos_y += 1
                goToXY(COORD(self.start_pos.X, self.start_pos.Y + pos_y))
                print(self.text.getPosAttribute(tot) + self.text.getRawText()[tot] + '\033[m')
                pos_x = mixedStrLength(self.text.getRawText()[tot])
            else:
                goToXY(COORD(self.start_pos.X + pos_x, self.start_pos.Y + pos_y))
                print(self.text.getPosAttribute(tot) + self.text.getRawText()[tot] + '\033[m')
                pos_x += mixedStrLength(self.text.getRawText()[tot])
            tot += 1

    def removeWidget(self) -> None:
        blank = ' ' * self.width
        for l in range(self.line):
            goToXY(COORD(self.start_pos.X, self.start_pos.Y + l))
            print(blank)
        self.attached_scene.reprintScene()

class Pauser(BaseWidget):
    def __init__(self, text: TextComponent, pause_key: str, start_pos: COORD, widget_name: str) -> None:
        super().__init__(widget_name)
        self.text = text
        self.exit_flg = False
        self.width = mixedStrLength(self.text.getRawText())
        self.pause_key = pause_key
        self.start_pos = start_pos
    
    def receiveKeyboard(self, key_name: str, event_type: str) -> bool:
        if event_type == 'down':
            if self.pause_key == 'ALL':
                self.exit_flg = True
            if key_name == self.pause_key:
                self.exit_flg = True
        return True

    def reprintWidget(self) -> None:
        goToXY(self.start_pos)
        split_line = TextComponent('+ ' + '-' * self.width + ' +', 'default', 'purple')
        print(split_line)

        goToXY(COORD(self.start_pos.X, self.start_pos.Y + 1))
        print(ComplexText(TextComponent('|', 'default', 'purple'), self.text, TextComponent('|', 'default', 'purple')))

        goToXY(COORD(self.start_pos.X, self.start_pos.Y + 2))
        print(split_line)
    
    def refreshWidget(self) -> typing.Any | None:
        if self.exit_flg:
            self.attached_scene.pushMsgPacket('PAUSER_EXIT', {'widget_name': self.name})
            return self.pause_key
        self.reprintWidget()
        self.setNeedRefresh()

    def removeWidget(self) -> None:
        blank = ' ' * (self.width + 4)
        for i in range(3):
            goToXY(COORD(self.start_pos.X, self.start_pos.Y + i))
            print(blank)
        self.attached_scene.reprintScene()

class Trigger(BaseWidget):
    def __init__(self, *events: ListenEvent, widget_name: str) -> None:
        super().__init__(widget_name)
        self.events = list(events)
    
    def attachToScene(self, scene) -> None:
        self.attached_scene = scene
        for event in self.events:
            event.bindScene(scene)

    def addEvent(self, event: ListenEvent) -> None:
        self.events.append(event)

    def receiveMsgPacket(self, packet_sign: str, parameters: dict) -> bool:
        for index in range(len(self.events))[::-1]:
            if self.events[index].onCheck(packet_sign, parameters):
                self.events[index].onActivate()
                if not self.events[index].do_not_remove:
                    del self.events[index]

    def receiveKeyboard(self, key_name: str, event_type: str) -> bool:
        for index in range(len(self.events))[::-1]:
            if self.events[index].onCheck('KEYBOARD', {'key_name': key_name, 'event_type': event_type}):
                self.events[index].onActivate()
                if not self.events[index].do_not_remove:
                    del self.events[index]

class ListedText(BaseWidget):
    def __init__(self, start_pos: COORD, max_width: int, max_height: int, widget_name: str) -> None:
        super().__init__(widget_name)
        self.upper_bound = TextComponent('=' * max_width, 'default', 'purple')
        self.vertical_element = TextComponent('|', 'default', 'purple')
        self.corner = TextComponent('+', 'default', 'purple')
        self.max_width = max(max_width, 8)
        self.max_height = max_height
        self.start_pos = start_pos
        self.exit_flg = False
        self.object_list: typing.List[typing.Tuple[int, typing.Any]] = []
        self.page_list: typing.List[typing.List[typing.Any]] = []
        self.present_page: typing.List[typing.Any] = []
        self.object_index = 0
        self.max_page_index = 0
        self.display_page_index = 0
        self.next_key = 'page up'
        self.last_key = 'page down'
    
    def overWriteKeys(self, last_page_key: str, next_page_key: str) -> None:
        self.last_key = last_page_key
        self.next_key = next_page_key

    def receiveKeyboard(self, key_name: str, event_type: str) -> bool:
        if event_type == 'down':
            if key_name == self.last_key and self.display_page_index > 0:
                self.display_page_index -= 1
                self.setNeedRefresh()
                return True
            elif key_name == self.next_key and self.display_page_index < self.max_page_index:
                self.display_page_index += 1
                self.setNeedRefresh()
                return True
        return False

    def forceExit(self) -> None:
        self.exit_flg = True

    def countPageLength(self) -> int:
        page_length = 0
        for _object in self.present_page:
            object_str = _object.getRawText() if isinstance(_object, TextComponent) else _object.__str__()
            object_len: int = mixedStrLength(object_str)
            page_length += object_len // self.max_width
            page_length += (object_len % self.max_width != 0)
        return page_length

    def makeLastLine(self) -> TextComponent:
        count_str = '<<{}/{}>>'.format(self.display_page_index + 1, self.max_page_index + 1)
        rest_length = (self.max_width - len(count_str) - 2) // 2
        left_str = '=' * rest_length
        right_str = '=' * (rest_length + (len(count_str) % 2 == 1))
        return ComplexText(TextComponent(left_str, 'default', 'purple'), 
                           TextComponent(count_str, 'default', 'green', 'white'), 
                           TextComponent(right_str, 'default', 'purple'))

    def clearContent(self) -> None:
        blank = ' ' * self.max_width
        for i in range(self.max_height):
            goToXY(COORD(self.start_pos.X, self.start_pos.Y + i))
            print(blank, end = '', flush = True)

    def printPage(self) -> None:
        self.clearContent()
        to_print: typing.List[typing.Any] = None
        if self.display_page_index <= 0:
            to_print = self.present_page
        else:
            to_print = self.page_list[self.display_page_index - 1]
        
        pos_Y = self.start_pos.Y
        for _object in to_print:
            if isinstance(_object, TextComponent):
                goToXY(COORD(self.start_pos.X, pos_Y))
                top_str = _object.getRawText()
                pt_str = 0
                length_cnt = 0
                while pt_str < len(top_str):
                    sub_len = mixedStrLength(top_str[pt_str])
                    if length_cnt + sub_len > self.max_width:
                        pos_Y += 1
                        goToXY(COORD(self.start_pos.X, pos_Y))
                        length_cnt = sub_len
                    else:
                        length_cnt += sub_len
                    print(_object.getPosAttribute(pt_str) + top_str[pt_str] + '\033[m', end = '', flush = True)
                    pt_str += 1
                pos_Y += 1
            else:
                top_str = _object.__str__()
                lpt = rpt = 0
                while rpt < len(top_str):
                    if mixedStrLength(top_str[lpt: rpt + 1]) > self.max_width:
                        goToXY(COORD(self.start_pos.X, pos_Y))
                        print(top_str[lpt: rpt], flush = True)
                        pos_Y += 1
                        lpt = rpt
                    else:
                        rpt += 1
                if lpt < rpt:
                    goToXY(COORD(self.start_pos.X, pos_Y))
                    print(top_str[lpt: ], flush = True)
                    pos_Y += 1

    def printFrame(self) -> None:
        # Corner
        goToXY(COORD(self.start_pos.X - 1, self.start_pos.Y - 1))
        print(self.corner, flush = True)
        goToXY(COORD(self.start_pos.X - 1, self.start_pos.Y + self.max_height))
        print(self.corner, flush = True)
        goToXY(COORD(self.start_pos.X + self.max_width, self.start_pos.Y - 1))
        print(self.corner, flush = True)
        goToXY(COORD(self.start_pos.X + self.max_width, self.start_pos.Y + self.max_height))
        print(self.corner, flush = True)
        # Vertical
        for x in range(self.max_height):
            goToXY(COORD(self.start_pos.X - 1, self.start_pos.Y + x))
            print(self.vertical_element, end = '', flush = True)
            goToXY(COORD(self.start_pos.X + self.max_width, self.start_pos.Y + x))
            print(self.vertical_element, end = '', flush = True)
        # Horizontal
        goToXY(COORD(self.start_pos.X, self.start_pos.Y - 1))
        print(self.upper_bound, end = '', flush = True)
        goToXY(COORD(self.start_pos.X, self.start_pos.Y + self.max_height))
        print(self.makeLastLine(), end = '', flush = True)
   
    def reprintWidget(self) -> None:
        self.printFrame()
        self.printPage()
    
    def refreshWidget(self) -> typing.Any | None:
        if self.exit_flg:
            return self.display_page_index
        self.reprintWidget()

    def addObject(self, _object: typing.Any) -> int:
        max_chars = self.max_width * self.max_height
        object_str = _object.getRawText() if isinstance(_object, TextComponent) else _object.__str__()
        if mixedStrLength(object_str) >= max_chars:
            rpt = len(object_str)
            while mixedStrLength(object_str[: rpt]) > max_chars - 3:
                rpt -= 1
            _object = object_str[: rpt] + '...'
        self.object_list.append((self.object_index, _object))
        self.object_index += 1
        self.present_page.append(_object)
        if self.countPageLength() > self.max_height:
            self.present_page.pop()
            self.page_list.insert(0, self.present_page)
            self.present_page = []
            self.present_page.insert(0, _object)
            self.max_page_index += 1
        self.setNeedRefresh()
        return self.object_index - 1
    
    def remakePages(self) -> None:
        temp_list = self.object_list.copy()
        self.present_page.clear()
        self.page_list.clear()
        self.max_page_index = 0
        self.display_page_index = 0
        while len(temp_list):
            present_obj = temp_list.pop(0)
            self.present_page.append(present_obj[1])
            if self.countPageLength() > self.max_height:
                self.present_page.pop()
                self.page_list.append(self.present_page)
                self.present_page = []
                self.present_page.append(present_obj[1])
                self.max_page_index += 1

    def removeObject(self, by_index: int = -1, by_object: typing.Any = None) -> None:
        if by_object != None:
            for _object in self.object_list:
                if id(by_object) == id(_object[1]):
                    del _object
                    break     
        else:
            if by_index == -1:
                self.object_list.pop()
                return
            for _object in self.object_list:
                if _object[0] == by_index:
                    del _object
                    break    
        self.remakePages()

    def removeWidget(self) -> None:
        blank = ' ' * (self.max_width + 2)
        for i in range(self.max_height + 2):
            goToXY(COORD(self.start_pos.X - 1, self.start_pos.Y - 1 + i))
            print(blank, end = '', flush = True)
        self.attached_scene.reprintScene()
