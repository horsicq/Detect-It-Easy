[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=NF3FBD3KHMXDN)
[![GitHub tag (latest SemVer)](https://img.shields.io/github/tag/horsicq/DIE-engine.svg)](http://ntinfo.biz)
[![GitHub All Releases](https://img.shields.io/github/downloads/horsicq/DIE-engine/total.svg)](http://ntinfo.biz)
[![gitlocalized ](https://gitlocalize.com/repo/4736/whole_project/badge.svg)](https://gitlocalize.com/repo/4736/whole_project?utm_source=badge)

Detect It Easy
==============

![alt text](https://github.com/horsicq/Detect-It-Easy/blob/master/mascots/3.01.png "Version")

![alt text](https://github.com/horsicq/Detect-It-Easy/blob/master/screenshot.jpg "Screenshot")

Detect It Easy, or abbreviated "DIE" is a program for determining types of files.

"DIE" is a cross-platform application, apart from Windows version there are also
available versions for Linux and Mac OS.

Many programs of the kind (PEID, PE tools) allow to use third-party signatures.
Unfortunately, those signatures scan only bytes by the pre-set mask, and it is
not possible to specify additional parameters. As the result, false triggering
often occur. More complicated algorithms are usually strictly set in the program
itself. Hence, to add a new complex detect one needs to recompile the entire
project. No one, except the authors themselves, can change the algorithm of
a detect. As time passes, such programs lose relevance without the constant support.

Detect It Easy has totally open architecture of signatures. You can easily
add your own algorithms of detects or modify those that already exist. This
is achieved by using scripts. The script language is very similar to JavaScript
and any person, who understands the basics of programming, will understand easily
how it works. Possibly, someone may decide the scripts are working very slow.
Indeed, scripts run slower than compiled code, but, thanks to the good optimization
of Script Engine, this doesn't cause any special inconvenience. The possibilities
of open architecture compensate these limitations.

DIE exists in three versions. Basic version ("DIE"), Lite version ("DIEL") and
console version ("DIEC"). All the three use the same signatures, which are located
in the folder "db". If you open this folder, nested sub-folders will be found
("Binary", "PE" and others). The names of sub-folders correspond to the types of files.
First, DIE determines the type of file, and then sequentially loads all the signatures,
which lie in the corresponding folder. Currently the program defines the following types:

* MSDOS executable files MS-DOS

* PE executable files Windows

* ELF executable files Linux

* MACH executable files Mac OS

* Binary all other files

Download: https://github.com/horsicq/DIE-engine/releases

Changelog: https://github.com/horsicq/Detect-It-Easy/blob/master/changelog.txt

![alt text](https://github.com/horsicq/Detect-It-Easy/blob/master/mascots/die.jpg "Mascot")


Run with Docker
=======

You can also run DIE with [Docker](https://www.docker.com/community-edition)! Of course, this requires that you have git and Docker installed.

Here's how to use DIE with Docker:

```bash
git clone https://github.com/horsicq/Detect-It-Easy
cd Detect-It-Easy/
docker build . -t horsicq:diec
docker/diec.sh ~/example/infected.exe

filetype: PE32
arch: I386
mode: 32
endianess: LE
type: GUI
  protector: Themida/Winlicense(2.X)[-]
  linker: Turbo Linker(2.25*,Delphi)[GUI32]
```


How to build on Linux
=======

Install Qt 5.15.2: https://github.com/horsicq/build_tools

Clone project: git clone --recursive https://github.com/horsicq/DIE-engine.git

Edit build_lin64.sh ( check QT_PATH variable)

Run build_lin64.sh

How to build on OSX
=======

Install Qt 5.15.2: https://github.com/horsicq/build_tools

Clone project: git clone --recursive https://github.com/horsicq/DIE-engine.git

Edit build_mac.sh ( check QT_PATH variable)

Run build_mac.sh

How to build on Windows(XP)
=======

Install Visual Studio 2013: https://github.com/horsicq/build_tools

Install Qt 5.6.3 for VS2013: https://github.com/horsicq/build_tools

Install 7-Zip: https://github.com/horsicq/build_tools

Clone project: git clone --recursive https://github.com/horsicq/DIE-engine.git

Edit build_winxp.bat ( check VS_PATH,  SEVENZIP_PATH, QT_PATH variables)

Run build_winxp.bat

How to build on Windows(7-10)
=======

Install Visual Studio 2019: https://github.com/horsicq/build_tools

Install Qt 5.15.2 for VS2019: https://github.com/horsicq/build_tools

Install 7-Zip: https://github.com/horsicq/build_tools

Clone project: git clone --recursive https://github.com/horsicq/DIE-engine.git

Edit build_win32.bat ( check VS_PATH,  SEVENZIP_PATH, QT_PATH variables)

Edit build_win64.bat ( check VS_PATH,  SEVENZIP_PATH, QT_PATH variables)

Run build_win32.bat

Run build_win64.bat
