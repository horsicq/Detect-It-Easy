
* die GUI version
* diec console version
* diel GUI lite version


How to run portable version on Linux
=======

* download an appImage file https://github.com/horsicq/DIE-engine/releases/download/3.04/Detect_It_Easy-3.04-x86_64.AppImage
* make the file executable (chmod +x Detect_It_Easy-3.04-x86_64.AppImage)
* run it (./Detect_It_Easy-3.04-x86_64.AppImage)

How to run on macOS
=======

https://github.com/horsicq/build_tools/blob/master/OSX_NO_CERT.md

Run with Docker
=======

You can also run DIE with [Docker](https://www.docker.com/community-edition)! Of course, this requires that you have git and Docker installed.

Here's how to use DIE with Docker:

```bash
git clone --recursive https://github.com/horsicq/Detect-It-Easy
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
