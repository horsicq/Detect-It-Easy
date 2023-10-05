[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=NF3FBD3KHMXDN)
[![GitHub tag (latest SemVer)](https://img.shields.io/github/tag/horsicq/DIE-engine.svg)](http://ntinfo.biz)
[![GitHub All Releases](https://img.shields.io/github/downloads/horsicq/DIE-engine/total.svg)](http://ntinfo.biz)
[![gitlocalized ](https://gitlocalize.com/repo/4736/whole_project/badge.svg)](https://github.com/horsicq/XTranslation)

[![OS Linux](https://img.shields.io/badge/os-linux-brightgreen)](https://github.com/horsicq/DIE-engine/releases)
[![OS Windows](https://img.shields.io/badge/os-windows-brightgreen)](https://github.com/horsicq/DIE-engine/releases)
[![OS MacOS](https://img.shields.io/badge/os-macos-brightgreen)](https://github.com/horsicq/DIE-engine/releases)

Detect It Easy
==============

* Download: https://github.com/horsicq/DIE-engine/releases
* How to run: https://github.com/horsicq/Detect-It-Easy/blob/master/docs/RUN.md
* How to build: https://github.com/horsicq/Detect-It-Easy/blob/master/docs/BUILD.md
* Changelog: https://github.com/horsicq/Detect-It-Easy/blob/master/changelog.txt

You can help with translation: https://github.com/horsicq/XTranslation

![alt text](https://github.com/horsicq/Detect-It-Easy/blob/master/docs/1.png "1")
![alt text](https://github.com/horsicq/Detect-It-Easy/blob/master/docs/2.png "2")
![alt text](https://github.com/horsicq/Detect-It-Easy/blob/master/docs/3.png "3")
![alt text](https://github.com/horsicq/Detect-It-Easy/blob/master/docs/4.png "4")
![alt text](https://github.com/horsicq/Detect-It-Easy/blob/master/docs/5.png "5")
![alt text](https://github.com/horsicq/Detect-It-Easy/blob/master/docs/6.png "6")

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

DIE exists in three versions. Basic version ("die"), Lite version ("diel") and
console version ("diec"). All the three use the same signatures, which are located
in the folder "db". If you open this folder, nested sub-folders will be found
("Binary", "PE" and others). The names of sub-folders correspond to the types of files.
First, DIE determines the type of file, and then sequentially loads all the signatures,
which lie in the corresponding folder. Currently the program defines the following types:

* MSDOS executable files MS-DOS
* PE executable files Windows
* ELF executable files Linux
* MACH executable files Mac OS
* Binary all other files

Packages
=======

- Chocolatey(Windows): https://community.chocolatey.org/packages/die (Thanks **chtof**(https://github.com/chtof) and **Rob Reynolds**(https://github.com/ferventcoder))
- Parrot OS: Package name **detect-it-easy** (Thanks **Nong Hoang Tu**(https://github.com/dmknght))
- Arch Linux: https://aur.archlinux.org/packages/detect-it-easy-git/ (Thanks **Arnaud Dovi**(https://github.com/class101))
- REMnux https://remnux.org/ (Thanks **REMnux team**(https://twitter.com/REMnux/status/1401935989266919426))
- openSUSE https://build.opensuse.org/package/show/home:mnhauke/detect-it-easy (Thanks Martin Hauke)

Telegram Bot
=======

You could find the Bot in Telegram @detectiteasy_bot or simply enter in the search for Telegram "Detect It Easy"

Thanks to all the people who already contributed!
=======

<a href="https://github.com/horsicq/Detect-It-Easy/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=horsicq/Detect-It-Easy" />
</a>

## Special Thanks

- [PELock Software Protection & Reverse Engineering](https://www.pelock.com)

![alt text](https://github.com/horsicq/Detect-It-Easy/blob/master/mascots/logo.png "Mascot")



