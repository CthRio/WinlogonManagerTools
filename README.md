

# WinlogonManagerTools

WinlogonManagerTools 是通过 HOOK 或 HotPatch 技术拦截 Winlogon 进程事件的工具集。通过这些工具，可以修改 Winlogon 进程负责的部分系统快捷键的响应过程，此外还包括一些用户层操作的电源事件和登陆事件等等。



<p align="center">
  <a href="https://github.com/CthRio/WinlogonManagerTools/">
    <img src="images/logo.png" alt="Logo" width="80" height="80">
  </a>
  <h3 align="center">WinlogonManagerTools</h3>
  <p align="center">
    拦截并修改 Winlogon 事件的工具
    <br />
    <a href="https://github.com/CthRio/WinlogonManagerTools"><strong>探索本项目的文档 »</strong></a>
    <br />
    <br />
    <a href="https://github.com/CthRio/WinlogonManagerTools/blob/master/screenshoots">查看屏幕截图</a>
    ·
    <a href="https://github.com/CthRio/WinlogonManagerTools/issues">报告Bug</a>
    ·
    <a href="https://github.com/CthRio/WinlogonManagerTools/issues">提出新特性</a>
  </p>


</p>


 本篇 README.md 面向开发者

## 目录

- [上手指南](#上手指南)
  - [开发前的配置要求](#开发前的配置要求)
  - [安装步骤](#安装步骤)
- [文件目录说明](#文件目录说明)
- [开发的架构](#开发的架构)
- [部署](#部署)
- [使用到的框架](#使用到的框架)
- [贡献者](#贡献者)
  - [如何参与开源项目](#如何参与开源项目)
- [作者](#作者)
- [鸣谢](#鸣谢)

### 上手指南



###### 开发前的配置要求

1. Visual Studio 2022 v142
2. Windows 10/11

###### **安装步骤**

1. Clone the repo

```sh
git clone https://github.com/CthRio/WinlogonManagerTools.git
```

### 文件目录说明


```
filetree 
│  LICENSE.txt
│  README.md
│  WinlogonMessageFilter.cpp
│  WinlogonMessageFilter.sln
│
├─CommonManager
│      CommonManager.aps
│      CommonManager.rc
│      CommonManager.vcxproj
│      main.cpp
│      resource.h
│
├─docs
| 
├─Release
│      CommonManager.exe
│      CommonManager.pdb
│      rpcrt4.dll
│      rpcrt4.dll.idb
│      winlogon.exe
│      winlogon.exe.idb
│      WMsgInterceptor.exe
│
├─RpcServerTestCancel
│      BackgroundImage.bmp
│      BackgroundImage.jpg
│      Common.cpp
│      Common.h
│      CustomDialog.h
│      Funky Stars.wav
│      icon_62797_big.ico
│      icon_62797_sm.ico
│      Icon_About_22540.ico
│      Icon_Close_22531.ico
│      main.cpp
│      main.h
│      ReConfig.cpp
│      ReConfig.h
│      resource.h
│      RpcServerTestCancel.aps
│      RpcServerTestCancel.cpp
│      RpcServerTestCancel.h
│      RpcServerTestCancel.manifest
│      RpcServerTestCancel.rc
│      RpcServerTestCancel.vcxproj
│
├─WMsgController
│  │  ClassDiagram.cd
│  │  framework.h
│  │  pch.cpp
│  │  pch.h
│  │  RDa39640
│  │  resource.h
│  │  targetver.h
│  │  WMsgController.aps
│  │  WMsgController.cpp
│  │  WMsgController.h
│  │  WMsgController.rc
│  │  WMsgController.vcxproj
│  │  WMsgControllerDlg.cpp
│  │  WMsgControllerDlg.h
│  │
│  └─res
│          WMsgController.ico
│          WMsgController.rc2
│          WMsgController2.ico
│
├─WMsgHookCore
│      dllmain.cpp
│      framework.h
│      ldrp.h
│      pch.cpp
│      pch.h
│      WMsgHookCore.cpp
│      WMsgHookCore.vcxproj
│
└─x64
    └─Release
        CommonManager.exe
        CommonManager.pdb
        config.txt
        RpcServerTestCancel.exe
        RpcServerTestCancel.pdb
        WinlogonMessageFilter.exe
        WinlogonMessageFilter.pdb
        WMsgController.exe
        WMsgController.pdb
        WMsgInterceptor.exe
        WMsgKMsgHookCore.dll

```



### 开发的架构 

本项目基于 C/C++ 开发。

### 部署

暂无

### 使用到的框架

- 

### 贡献者

请阅读 **CONTRIBUTING.md** 查阅为该项目做出贡献的开发者。

#### 如何参与开源项目

贡献使开源社区成为一个学习、激励和创造的绝佳场所。我们对你所作的任何贡献都是**非常感谢**的。


1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request



### 作者

涟幽 516 (CthRio)

CSDN:https://blog.csdn.net/qq_59075481 

 *您也可以在贡献者名单中参看所有参与该项目的开发者。*

### 版权说明

该项目签署了 MIT 授权许可，详情请参阅 [LICENSE.txt](https://github.com/CthRio/WinlogonManagerTools/blob/master/LICENSE.txt)

### 鸣谢


- [GitHub Emoji Cheat Sheet](https://www.webpagefx.com/tools/emoji-cheat-sheet)
- [Choose an Open Source License](https://choosealicense.com)
- [GitHub Pages](https://pages.github.com)
- [Animate.css](https://daneden.github.io/animate.css)

<!-- links -->

[your-project-path]:CthRio/WinlogonManagerTools
[contributors-url]: https://github.com/CthRio/WinlogonManagerTools/graphs/contributors
[forks-url]: https://github.com/CthRio/WinlogonManagerTools/network/members
[stars-url]: https://github.com/CthRio/WinlogonManagerTools/stargazers
[license-url]: https://github.com/CthRio/WinlogonManagerTools/blob/master/LICENSE.txt

