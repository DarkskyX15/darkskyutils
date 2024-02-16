# -*- coding: UTF-8 -*-
import typing, importlib, os, keyboard, win32gui, time
from sky_lib.sky_graph.widget import BaseWidget
from sky_lib.sky_graph.graphic import COORD, goToXY


class BaseScene:
    def __init__(self, scene_manager, scene_name: str = 'Untitled') -> None:
        self.scene_manager: SceneManager = scene_manager
        self.scene_name = scene_name
        self.widget_list: typing.List[typing.Tuple[int, BaseWidget]] = []
        self.msg_queue: typing.List[typing.Tuple[str, dict]] = []
        self.schedule_list: typing.List[typing.Tuple[int, str, dict]] = []
        self.widget_returns: typing.List[typing.Tuple[str, typing.Tuple]] = []
        self.prepare_remove: typing.List[str] = []
        self.overall_variable: dict = dict()
        self.looping_flg = False
        self.arrange_reprint = False
        self.tick_per_sec = 20
        self.now_tick = 0
    
    def setTick(self, ticks: int) -> None:
        self.tick_per_sec = ticks
    
    def getTick(self) -> int:
        return self.now_tick

    def getTimeInterval(self) -> float:
        return 1.0 / self.tick_per_sec

    def setOverallVar(self, key: str, val: typing.Any) -> None:
        self.overall_variable[key] = val
    
    def getOverallVar(self, key: str) -> typing.Union[typing.Any, None]:
        return self.overall_variable.get(key, None)

    def enableKeyboardHook(self) -> None:
        def listen(event: keyboard.KeyboardEvent) -> None:
            on_focus = self.scene_manager.checkFocus()
            for _widget in self.widget_list[::-1]:
                if on_focus and not _widget[1].isGlobalKeyHook():
                    if _widget[1].receiveKeyboard(event.name, event.event_type):
                        _widget[1].setNeedRefresh()
                        break
                elif _widget[1].isGlobalKeyHook():
                    if _widget[1].receiveKeyboard(event.name, event.event_type):
                        _widget[1].setNeedRefresh()
                        break
        keyboard.hook(listen)

    def addWidget(self, widget: BaseWidget, weight: int = 0) -> None:
        def compare(_widget) -> int:
            return _widget[0]
        widget.attachToScene(self)
        widget.setNeedRefresh()
        self.pushMsgPacket('WIDGET_ADDED', {'widget_name': widget.name})
        self.widget_list.append((weight, widget))
        self.widget_list.sort(key = compare)

    def removeWidget(self, widget_name: str) -> bool:
        for index in range(len(self.widget_list)):
            if self.widget_list[index][1].name == widget_name:
                del self.widget_list[index]
                return True
        return False

    def findWidget(self, widget_name: str) -> typing.Union[BaseWidget, None]:
        for _widget in self.widget_list:
            if _widget[0] == widget_name:
                return _widget[1]
        return None

    def aliveWidgetNum(self) -> int:
        return len(self.widget_list)

    def pushMsgPacket(self, packet_sign: str, parameters: dict) -> None:
        self.msg_queue.append((packet_sign, parameters))

    def scheduledMsg(self) -> None:
        for schedule in self.schedule_list:
            if self.now_tick > 0 and self.now_tick % schedule[0] == 0:
                self.pushMsgPacket(schedule[1], schedule[2])
        self.now_tick += 1
        if self.now_tick > 72000:
            self.now_tick = 0

    def addSchedule(self, interval_tick: int, packet_sign: str, parameters: dict) -> None:
        def compare(schedule) -> int:
            return schedule[0]
        if interval_tick > 72000:
            interval_tick = 72000
        self.schedule_list.append((interval_tick, packet_sign, parameters))
        self.schedule_list.sort(key = compare)
    
    def removeSchedule(self, tick: int, packet_sign: str) -> bool:
        for index in range(len(self.schedule_list)):
            if tick == self.schedule_list[index][0] and packet_sign == self.schedule_list[index][1]:
                del self.schedule_list[index]
                return True
        return False

    def pushWidgetReturn(self, widget_name: str, parameters: typing.Any) -> None:
        self.widget_returns.append((widget_name, parameters))

    def getWidgetReturn(self, widget_name: str) -> typing.Union[typing.Any, None]:
        for unit in self.widget_returns:
            if unit[0] == widget_name:
                return unit[1]
        return None

    def reprintScene(self) -> None:
        self.arrange_reprint = True

    def __onStart__(self):
        self.looping_flg = True
        self.onStart()
    
    def onStart(self):
        pass
    
    def endLoop(self) -> None:
        self.looping_flg = False

    def isLooping(self) -> bool:
        return self.looping_flg

    def __onLoop__(self) -> None:
        if self.arrange_reprint:
            for _widget in self.widget_list:
                _widget[1].reprintWidget()
            self.arrange_reprint = False
        while len(self.msg_queue) > 0:
            packet = self.msg_queue.pop(0)
            for _widget in self.widget_list:
                if _widget[1].receiveMsgPacket(packet[0], packet[1]):
                    _widget[1].setNeedRefresh()
        for _widget in self.widget_list:
            if _widget[1].doNeedRefresh():
                widget_return = _widget[1].__refreshWidget__()
                if widget_return != None:
                    self.pushWidgetReturn(_widget[1].name, widget_return)
                    _widget[1].__removeWidget__()
                    self.prepare_remove.append(_widget[1].name)
        if len(self.prepare_remove) > 0:
            for remove in self.prepare_remove:
                self.removeWidget(remove)
            self.prepare_remove.clear()
        self.onLoop()
    
    def onLoop(self) -> None:
        pass

    def onEnd(self) -> None:
        pass

class SceneManager:
    def __init__(self) -> None:
        self.scene_queue: typing.List[BaseScene] = []
        self.working_path = os.getcwd() + '\\TouhouSolo.exe'
        self.window_handle = win32gui.FindWindow(None, self.working_path)
        self.global_vars = dict()
        self.show_tick_time = False
    
    def displayTickTime(self) -> None:
        self.show_tick_time = True

    def setGlobalValue(self, key: str, value: typing.Any) -> None:
        self.global_vars[key] = value
    
    def getGlobalValue(self, key: str) -> typing.Union[typing.Any, None]:
        return self.global_vars.get(key, None)

    def removeGlobalValue(self, key: str) -> typing.Union[typing.Any, None]:
        return self.global_vars.pop(key, None)

    def loadScene(self, scene_name: str) -> None:
        module = importlib.import_module('Scene.' + scene_name)
        self.scene_queue.append(module.Scene(self))

    def checkFocus(self) -> bool:
        return (self.window_handle == win32gui.GetForegroundWindow())

    def startLoop(self) -> None:
        zero_point = COORD(0, 0)
        while len(self.scene_queue):
            os.system('cls')
            present_scene = self.scene_queue.pop(0)
            present_scene.__onStart__()
            while present_scene.isLooping():
                start_time = time.time()
                present_scene.scheduledMsg()
                present_scene.__onLoop__()
                tick_time = present_scene.getTimeInterval()
                end_time = time.time()
                sleep_time = round(tick_time - end_time + start_time, 4)
                if self.show_tick_time:
                    goToXY(zero_point)
                    print('      ', end = '', flush = True)
                    fps = 1 / (end_time - start_time) if sleep_time < 0 else 1 / tick_time
                    goToXY(zero_point)
                    print(round(fps, 1), end = '', flush = True)
                if sleep_time > 0: time.sleep(sleep_time)
            present_scene.onEnd()
