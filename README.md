# SideLOADR

A "simple" script to perform DLL sideloading using Python.

See [Disclaimers](#disclaimers) for my references. Thanks
to the awesome pool of information out there on this topic.
I am trying my hand at making a Python implementation based
on cocomelonc's PoC on his blog linked below then try to just
make it nice and uniform. This is more of a foray rahter 
than me being novel in any sense. 

## Description

This is a Python script and setup to enable someone to 
perform DLL sideloading (or consequently DLL hijacking)
using a Linux machine. This project has a nice Docker
container which should allow for easy proxy DLL creation
on the fly.

## How To Use

`sideloadr` is pretty simple to use. You can make use of Poetry
or Docker to execute the utility.

Make sure if you are not using Docker, that you have `mingw-w64`
installed for cross compliation of Windows binaries. 

### Help Menu

```console
usage: sideloadr [-h] [--no-clean] [--x86] victim payload proxy outdir

positional arguments:
  victim      Path to the DLL we want to impersonate.
  payload     Path to the shellcode we want to execute.
  proxy       What we want to rename the victim DLL to for proxying.
  outdir      The output directory for all artifacts.

optional arguments:
  -h, --help  show this help message and exit
  --no-clean  Do not clean the build folder. Keep cpp and def file.
  --x86       Set when you want to compile 32-bit instead of the default 64-bit
```

### Example Walkthrough

First find the DLL you which you want to target. For example, we could
target `C:\Windows\System32\bcrypt.dll` and transfer that over to our
Linux machine. 

Then we will make sure we either install the correct dependencies for
poetry and this project or build the Docker container included for 
SideLOADR. 

We want to also make some raw shellcode which should be executed within
the adversarial DLL. You could do this with Sliver, Metasploit, Cobalt
Strike, or be cool and write it yourself. 

At this point you should have something like:

- `bcrypt.dll`
- `payload.raw`

For demonstration purposes, I am going to assume you have them both in 
a folder called `/tmp/memes`. 

For Poetry we would run the following command:

```console
poetry run sideloadr /tmp/memes/bcrypt.dll /tmp/memes/payload.raw new_name_for_original_dll.dll /tmp/memes/output_dir
```

For Docker, you have less control over the out directory but it would be like so:

```console
# Assuming you named the image sideloadr
docker run -v /tmp/memes/:/workdir sideloadr /workdir/bcrypt.dll /workdir/payload.raw new_name_for_original_dll.dll /workdir/output_dir
```

In both cases, your `/tmp/memes` directory should look like so:

```console
.
|- bcrypt.dll
|- payload.raw
|- output_dir/
  |- bcrypt.dll
  |- new_name_for_original_dll.dll
```

If you set `--no-clean`, then you should also see `bcrypt.cpp` and `bcrypt.def`
for this case. 

If you are DLL sideloading, then the next step is to transfer `bcrypt.dll`
and `new_name_for_original_dll.dll` to your target machine into some user
writable directory. Then copy over your victim executable. `printui.exe` works
pretty well for Windows Server 2016. Then once you execute `printui.exe` with
both the DLLs in the same directory, you will have the desired shellcode 
executed. 

This by no means does AV avoidance. Though you could probably do a simple rev
shell in C++ using a similar technique as to what was seen in this blogpost
by Flangvik: https://flangvik.com/2019/07/24/Bypassing-AV-DLL-Side-Loading.html. 

### Extending

Since this is fairly simple, most of the extending of this payload generation
is via modification of the [constants.py](sideloadr/constants.py) file. This
is the basic DLL C++ code. You can probably add extra activity here. 

At some point I may want to add in multiple styles of DLL payloads which can
all be templated with the same method I am using for sideloadr but for now I
am not doing that. Feel free to modify at your own will!

Also note, you can make the DLL template launch the shellcode in the main 
thread instead of making a new thread by commending out the `CreateThread`
function call and then uncommenting the DECL for `meme()` and uncommenting
the call for it in `DllMain`.

Fun fact, Meterpreter needs to be launched from its own thread. If you try
to launch Meterpreter from the same thread as the DLL loading thread, it will
try to launch but consistently fail. The basic reverse shell payload will work
fine though but just know you may need to sacrafice a notepad.exe process or
something to get a Meterpreter shell to stablize. 

## Disclaimers ##

### People I Got Information From
Not all the code or ideas are all my own. This is heavily
inspired by the following resources:

- @cocomelonckz: 
  - https://cocomelonc.github.io/pentest/2021/10/12/dll-hijacking-2.html
- @Flangvik: 
  - https://github.com/Flangvik/DLLSideloader
- Mandiant: 
  - https://github.com/mandiant/DueDLLigence
  - https://www.mandiant.com/resources/blog/abusing-dll-misconfigurations
- @k3idii:
  - https://gist.github.com/k3idii/da4235d3b9eaa2ebe349555a92eac6c2

### This Script is Pretty Basic ##

This is not super robust. May try to build it out more at
some point.


