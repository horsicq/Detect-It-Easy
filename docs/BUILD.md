# How to build on Docker

```bash
git clone https://github.com/horsicq/DIE-engine.git
cd DIE-engine
sudo docker build . -t horsicq:diec
```

# How to build on Linux based on Debian 

You can also watch tutorial on [YouTube](https://www.youtube.com/watch?v=hODcbA_1Tns)

#### Install packages:

```bash
sudo apt-get install qtbase5-dev qtscript5-dev qttools5-dev-tools libqt5svg5-dev git build-essential -y
```

- Ubuntu 14.04-20.04:

```bash
sudo apt-get install qt5-default -y
```

- Ubuntu 21.04-22.04

```bash
sudo apt-get install qtchooser qt5-qmake -y
```

#### Clone this repo recursively:

```bash
git clone --recursive https://github.com/horsicq/DIE-engine.git
cd DIE-engine
```

#### Run build script:

```bash
bash -x build_dpkg.sh
```

#### Install deb package:

```bash
sudo dpkg -i release/$(ls release)
```

# How to build on Linux(Automake)

### Qt framework has to be installed on the system.

#### (Ubuntu) Install Qt Framework:

```bash
sudo apt-get install --quiet --assume-yes build-essential qt5-default qtbase5-dev qttools5-dev-tools qtscript5-dev libqt5svg5-dev
```

#### Clone this repo recursively:

```bash
git clone --recursive https://github.com/horsicq/DIE-engine.git
cd DIE-engine
```

#### Build

Might require sudo privileges

```bash
chmod a+x configure
./configure
make -j4
sudo make install
```

# How to build on macOS

Install Qt 5.15.2: https://github.com/horsicq/build_tools

Clone project: git clone --recursive https://github.com/horsicq/DIE-engine.git

Edit build_mac.sh ( check QMAKE_PATH variable)

Run build script: bash -x build_mac.sh

# How to build on Windows(XP)

Install Visual Studio 2013: https://github.com/horsicq/build_tools

Install Qt 5.6.3 for VS2013: https://github.com/horsicq/build_tools

Install 7-Zip: https://github.com/horsicq/build_tools

Clone project: git clone --recursive https://github.com/horsicq/DIE-engine.git

Edit build_winxp.bat ( check VSVARS_PATH, SEVENZIP_PATH, QMAKE_PATH variables)

Run build_winxp.bat

# How to build on Windows(7-11)

Install Visual Studio 2019: https://github.com/horsicq/build_tools

Install Qt 5.15.2 for VS2019: https://github.com/horsicq/build_tools

Install 7-Zip: https://github.com/horsicq/build_tools

Clone project: git clone --recursive https://github.com/horsicq/DIE-engine.git

Edit build_win32.bat ( check VSVARS_PATH, SEVENZIP_PATH, QMAKE_PATH variables)

Edit build_win64.bat ( check VSVARS_PATH, SEVENZIP_PATH, QMAKE_PATH variables)

Run build_win32.bat

Run build_win64.bat

# How to build with CMAKE

#### Clone this repo recursively:

```bash
git clone --recursive https://github.com/horsicq/DIE-engine.git
cd DIE-engine
```

#### Build

```bash
mkdir -p build
cmake . -B build
cd build
make -j4
# To use it as a command, uncomment the following line:
# sudo make install -j4
```
