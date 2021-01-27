# PwnWithIDA

这是一个IDA的插件配上一个python库，配合`pwnlib`使用，可以让IDA方便的`attach`、`continue`、`detach`等操作。

## 原理

IDA插件启动一个TCP服务器，支持几个简单的命令，使用python向该服务器发送指令，达到自动`attach`等功能

## 使用方法

1. 复制`remoteIdaPlugin/remoteIDA.py`到IDA的`plugin`目录下
2. 在IDA菜单中`Edit/RemoteIDA`启动TCP服务器，IDA的python控制器会输出TCP服务器的端口
3. 将`IdaManage.py`复制到编写exp的目录下，导入`IdaManage`即可开始使用

## 代码样例

### 单独使用

```python
# 1.导入
from IdaManage import *

# 2.创建对象
# 连接本地，需要IDA调试时
ida=IDAManage('127.0.0.1',9945,p)
# 连接远程，不希望IDA调试代码起作用时
# 若这样创建，之后所有该对象的代码失效
ida=IDAManage(isWork=False)

# 3.操作
# 附加IDA调试
ida.attach()
# 附加IDA调试并continue
ida.attachAndContinue()
# 附加IDA调试,若IDA当前处于调试状态，将先终止当前调试，然后attach
ida.attachWithExit()
# continue，相当于快捷键F9
ida.c()
# 返回IDA当前是否处于调试状态(bool)
ida.isDebugging()

# 4.结束
# 终止当前调试进程
ida.exit()
# detach
ida.detach()
# 结束与IDA的连接
ida.close()

```

### 使用装饰器

使用装饰器可以方便的初始化一些变量，强烈推荐

```python
from typing import Union
from pwn import *
from IdaManage import *

# 本地打通后只需要将此标志改成True，即可连接远程
REMOTE = False

@connect(
    # nc连接地址,ip和端口之间用冒号或空格隔开
    remoteAddr='192.168.1.1:1000',
    # 本地的执行文件
    elf='./pwn',
    # 连接远程tcp还是启动本地程序
    # remoteAddr和elf只有一个设置时，此参数省略
    isRemote=REMOTE,
    # IDA的地址,ip和端口之间用冒号或空格隔开
    idaAddr='127.0.0.1:9945'
)
# 若connect装饰器中elf参数未设置，elf参数不可用
def main(p: Union[remote, process], ida: IDAManage, elf: ELF):
    # 附加IDA调试
    # 连接远程时此代码自动失效，不需要手动注释
    ida.attach()
    # 正常使用pwnlib库
    p.sendline('hello world')
    # IDA调试器 continue
    ida.c()
    # 最后会自动进入p.interactive()然后结束IDA调试
    # 此处不需要写


if __name__ == "__main__":
    # 这里不用传参数，参数由装饰器传入
    main()
```


## 其它

这个版本使用的是明文TCP连接，存在很大安全隐患，未来可能会改进

欢迎大家提交PR