# -*-coding:utf-8 -*-
import inspect
import ctypes
import socket
import threading
import traceback
import sys
import idaapi
import ida_dbg
import ida_kernwin

if sys.version_info.major==2:
    from SocketServer import *
else:
    from socketserver import *

RI_BASE_PORT = 9945


class MainTCPHandler(BaseRequestHandler):
    def handle(self):
        idaapi.msg("Accepting connection from {}\n".format(
            self.client_address[0]))
        while True:
            try:
                data = self.request.recv(1024).decode()
                if len(data) == 0:
                    break
                command = data.strip().split(' ')
                if len(command) == 0:
                    continue
                idaapi.msg('recv> '+' '.join(command)+'\n')
                result = False
                if command[0] == 'attachWithExit':
                    if ida_kernwin.execute_sync(ida_dbg.is_debugger_on, 0):
                        ida_kernwin.execute_sync(ida_dbg.exit_process, 0)
                    if len(command) == 1:
                        pid = ida_kernwin.execute_sync(
                            lambda: ida_dbg.attach_process(-1), 0) == 1
                    else:
                        pid = ida_kernwin.execute_sync(
                            lambda: ida_dbg.attach_process(int(command[1])), 0) == 1
                    result = (pid == 1)
                elif command[0] == 'continue':
                    result = ida_kernwin.execute_sync(
                        ida_dbg.continue_process, 0) == 1
                elif command[0] == 'detach':
                    result = ida_kernwin.execute_sync(
                        ida_dbg.detach_process, 0)
                elif command[0] == 'attach':
                    if len(command) == 1:
                        pid = ida_kernwin.execute_sync(
                            lambda: ida_dbg.attach_process(-1), 0) == 1
                    else:
                        pid = ida_kernwin.execute_sync(
                            lambda: ida_dbg.attach_process(int(command[1])), 0) == 1
                    result = (pid == 1)
                elif command[0] == 'exit':
                    result = ida_kernwin.execute_sync(ida_dbg.exit_process, 0)
                elif command[0] == 'isDebugging':
                    result = ida_kernwin.execute_sync(
                        ida_dbg.is_debugger_on, 0)

                idaapi.msg('res>  '+str(result)+'\n')
                if result:
                    self.request.sendall(b'T\n')
                else:
                    self.request.sendall(b'F\n')
            except:
                traceback.print_exc()

        idaapi.msg("Closing connection from {}\n".format(
            self.client_address[0]))


class RIAction(idaapi.action_handler_t):
    @classmethod
    def get_name(self):
        return 'RemoteIDA:'+self.__name__

    @classmethod
    def get_label(self):
        return self.label

    @classmethod
    def register(self, plugin, label):
        self.plugin = plugin
        self.label = label
        instance = self()
        return idaapi.register_action(idaapi.action_desc_t(
            self.get_name(),  # Name. Acts as an ID. Must be unique.
            instance.get_label(),  # Label. That's what users see.
            instance  # Handler. Called when activated, and for updating
        ))

    @classmethod
    def unregister(self):
        idaapi.unregister_action(self.get_name())

    @classmethod
    def activate(self, ctx):
        return 1

    @classmethod
    def update(self, ctx):
        try:
            if ctx.form_type == idaapi.BWN_DISASM:
                return idaapi.AST_ENABLE_FOR_FORM
            else:
                return idaapi.AST_DISABLE_FOR_FORM
        except Exception as e:
            # Add exception for main menu on >= IDA 7.0
            return idaapi.AST_ENABLE_ALWAYS


class RIStartServer(RIAction):
    def activate(self, ctx):
        self.plugin.startServer()
        return 1


class RIStopServer(RIAction):
    def activate(self, ctx):
        self.plugin.stopServer()
        return 1


class RIRestartServer(RIAction):
    def activate(self, ctx):
        self.plugin.restartServer()
        return 1


def _async_raise(tid, exctype):
    """raises the exception, performs cleanup if needed"""
    tid = ctypes.c_long(tid)
    if not inspect.isclass(exctype):
        exctype = type(exctype)
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(
        tid, ctypes.py_object(exctype))
    if res == 0:
        raise ValueError("invalid thread id")
    elif res != 1:
        # """if it returns a number greater than one, you're in trouble,
        # and you should call it again with exc=NULL to revert the effect"""
        ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, None)
        raise SystemError("PyThreadState_SetAsyncExc failed")


def stop_thread(thread):
    _async_raise(thread.ident, SystemExit)


class RemoteIDA(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = "Control IDA by TCP"
    wanted_name = "RemoteIDA"  # 插件的名称，在IDA界面导航栏中显示 Edit->Plugins->myplugin
    wanted_hotkey = ""
    help = ""
    server = None

    def init(self):
        RIStartServer.register(self, 'Start')
        RIStopServer.register(self, 'Stop')
        RIRestartServer.register(self, 'Restart')

        idaapi.attach_action_to_menu(
            "Edit/RemoteIDA/Start", RIStartServer.get_name(), idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu(
            "Edit/RemoteIDA/Stop", RIStopServer.get_name(), idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu(
            "Edit/RemoteIDA/Restart", RIRestartServer.get_name(), idaapi.SETMENU_APP)

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        self.stopServer()
        idaapi.unregister_action(RIStartServer.get_name())
        idaapi.unregister_action(RIRestartServer.get_name())
        idaapi.unregister_action(RIStopServer.get_name())

    def startServer(self):
        if self.server != None:
            idaapi.msg(">>> There is a running server\n")
            return
        i = 0
        while True:
            try:
                server = TCPServer(
                    ("", RI_BASE_PORT+i), MainTCPHandler)
                self.server = threading.Thread(target=server.serve_forever)
                self.server.start()
                break
            except socket.error:
                i += 1
        idaapi.msg(">>> Start server at port "+str(RI_BASE_PORT+i)+'\n')

    def stopServer(self):
        if self.server != None:
            stop_thread(self.server)
            idaapi.msg(">>> Stop server\n")
            self.server = None
        else:
            idaapi.msg(">>> There is no running server\n")

    def restartServer(self):
        self.stopServer()
        self.startServer()


def PLUGIN_ENTRY():
    return RemoteIDA()
