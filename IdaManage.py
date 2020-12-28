from functools import wraps
from logging import error
from typing import Union
from pwnlib.elf.elf import ELF
from pwnlib.exception import PwnlibException
from pwnlib.replacements import sleep
from pwnlib.tubes.remote import remote
from pwnlib.tubes.process import process
from pwnlib.tubes.ssh import ssh_channel
from pwnlib.util.proc import pidof
import traceback


def parseAddr(addr: str):
    addr = addr.strip()
    if ':' in addr:
        return [x.strip() for x in addr.split(':')]
    if ' ' in addr:
        return [x.strip() for x in addr.split(' ')]


def connect(remoteAddr: str = '',
            elf: str = '',
            isRemote: bool = False,
            idaAddr: str = '192.168.137.1:9945',
            *args, **kwargs):
    def decorator(func):
        @wraps(func)
        def inner():
            _isRemote = isRemote
            e = None
            if remoteAddr == '' and elf == '':
                raise TypeError('Both of remoteAddr and elf is void')
            if remoteAddr == '':
                _isRemote = False
            if elf == '':
                _isRemote = True
            else:
                e = ELF(elf, checksec=False)

            if _isRemote:
                p = remote(*parseAddr(remoteAddr), *args, **kwargs)
                ida = IDAManage(isWork=False)
            else:
                p = process(elf, *args, **kwargs)
                ida = IDAManage(*parseAddr(idaAddr), p)
            try:
                func(p, ida, e)
                p.interactive()
            except InterruptedError:
                pass
            except Exception as e:
                traceback.print_exception(e)
            finally:
                ida.exit()
                ida.close()
        return inner
    return decorator


class IDAManage:
    ida = None
    proc = None
    isWork = False

    def __init__(self, ip: str = '', port: int = 0, proc: Union[process, ssh_channel] = None, isWork: bool = True) -> None:
        if not isWork:
            return
        self.proc = proc
        try:
            self.ida = remote(ip, port)
        except PwnlibException:
            error('Cannot connect to '+ip+' on port '+port)
        else:
            self.isWork = True

    def __checkwork(func):
        @wraps(func)
        def inner(self, *args, **kwargs):
            if self.isWork:
                return func(self, *args, **kwargs)
        return inner

    @__checkwork
    def attach(self) -> bool:
        if self.proc == None:
            self.ida.send('attach '+str(pidof(self.proc)[0]))
        else:
            self.ida.send('attach '+str(pidof(self.proc)[0]))
        sleep(0.2)
        return self.ida.recvline(keepends=False) == 'T'

    @__checkwork
    def attachWithExit(self) -> bool:
        if self.proc == None:
            self.ida.send('attachWithExit '+str(pidof(self.proc)[0]))
        else:
            self.ida.send('attachWithExit '+str(pidof(self.proc)[0]))
        sleep(0.2)
        return self.ida.recvline(keepends=False) == 'T'

    @__checkwork
    def exit(self) -> bool:
        self.ida.send('exit')
        return self.ida.recvline(keepends=False) == 'T'

    @__checkwork
    def c(self) -> bool:
        self.ida.send('continue')
        return self.ida.recvline(keepends=False) == 'T'

    @__checkwork
    def detach(self) -> bool:
        self.ida.send('detach')
        return self.ida.recvline(keepends=False) == 'T'

    @__checkwork
    def isDebugging(self) -> bool:
        self.ida.send('isDebugging')
        return self.ida.recvline(keepends=False) == 'T'

    @__checkwork
    def close(self):
        self.ida.close()
