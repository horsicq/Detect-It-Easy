How to build on Docker
=======
git clone --recursive https://github.com/horsicq/DIE-engine.git

cd DIE-engine

docker build .

How to build on Linux based on Debian
=======

Install packages:

- sudo apt-get install qtbase5-dev -y
- sudo apt-get install qtscript5-dev -y
- sudo apt-get install qttools5-dev-tools -y
- sudo apt-get install libqt5svg5-dev -y
- sudo apt-get install git -y
- sudo apt-get install build-essential -y
- sudo apt-get install qt5-default -y (Ubuntu 14.04-20.04)
- sudo apt-get install qtchooser -y (Ubuntu 21.04-22.04)
- sudo apt-get install qt5-qmake -y (Ubuntu 21.04-22.04)

git clone --recursive https://github.com/horsicq/DIE-engine.git

cd DIE-engine

Run build script: bash -x build_dpkg.sh

Install deb package: sudo dpkg -i release/die_[Version].deb

Run DiE: *die [FileName] or diec [FileName] or diel [FileName]*

How to build on Linux(Automake)
=======

Qt framework has to be installed on the system.

(Ubuntu)Install Qt Framework: **sudo apt-get install --quiet --assume-yes build-essential qt5-default qtbase5-dev qttools5-dev-tools qtscript5-dev libqt5svg5-dev**

Clone project: git clone --recursive https://github.com/horsicq/DIE-engine.git

- chmod a+x configure
- ./configure
- make
- sudo make install

Run DiE: *die [FileName] or diec [FileName] or diel [FileName]*

How to build on OSX
=======

Install Qt 5.15.2: https://github.com/horsicq/build_tools

Clone project: git clone --recursive https://github.com/horsicq/DIE-engine.git

Edit build_mac.sh ( check QMAKE_PATH variable)

Run build script: bash -x build_mac.sh

How to build on Windows(XP)
=======

Install Visual Studio 2013: https://github.com/horsicq/build_tools

Install Qt 5.6.3 for VS2013: https://github.com/horsicq/build_tools

Install 7-Zip: https://github.com/horsicq/build_tools

Clone project: git clone --recursive https://github.com/horsicq/DIE-engine.git

Edit build_winxp.bat ( check VSVARS_PATH,  SEVENZIP_PATH, QMAKE_PATH variables)

Run build_winxp.bat

How to build on Windows(7-10)
=======

Install Visual Studio 2019: https://github.com/horsicq/build_tools

Install Qt 5.15.2 for VS2019: https://github.com/horsicq/build_tools

Install 7-Zip: https://github.com/horsicq/build_tools

Clone project: git clone --recursive https://github.com/horsicq/DIE-engine.git

Edit build_win32.bat ( check VSVARS_PATH,  SEVENZIP_PATH, QMAKE_PATH variables)

Edit build_win64.bat ( check VSVARS_PATH,  SEVENZIP_PATH, QMAKE_PATH variables)

Run build_win32.bat

Run build_win64.bat

How to build with CMAKE
=======
git clone --recursive https://github.com/horsicq/DIE-engine.git

cd DIE-engine

cmake .

make