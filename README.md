# ai2_msgpack
Script for unpacking/repacking MessagePack files from AI: The Somnium Files - nirvanA Initiative.

# Installation
For Windows, just use the compiled [latest release](https://github.com/SutandoTsukai181/ai2_msgpack/releases).

If you don't want to use that, then you have to get the "correct" requirements:

This script needs a [specific fork of msgpack](https://github.com/SutandoTsukai181/msgpack-python-typed-ints) to work. You can either download the [wheels](https://github.com/SutandoTsukai181/msgpack-python-typed-ints/releases/tag/v1.0.5) and install them with `pip`, or you can just clone the [msgpack_typed_ints](https://github.com/SutandoTsukai181/msgpack-python-typed-ints) repository and put the `msgpack` folder in the same directory as this script.

Installing a wheel will provide better performance due to the compiled cython implementation of msgpack. If you choose to clone the repo instead, you will be using the pure python fallback implementation, which will be a bit slower. Do note however, that installing the wheels will overwrite the official msgpack package, if you have it installed.

# Usage
You can just drag and drop files to process them. If a file ends with `.json` it will be repacked, otherwise it will be unpacked. You can also drag and drop multiple files/folders at the same time.

Here is the `--help` message for the full usage:
```
usage: ai2_msgpack.exe [-h] [-o OUTPUT] [-u | -r] [-c] [-a] [-s] input [input ...]

Unpacks/repacks MessagePack files from Ai: The Somnium Files: nirvanA Initiative.

positional arguments:
  input                 path(s) to input file(s) and/or folder(s) that contain files to process.

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        path to output directory (defaults to same directory as the input). If multiple input folders are given, this will be ignored for them.    
  -u, --unpack          Unpack non-json files into json, and ignore json files.
  -r, --repack          Repack json files into MessagePack, and ignore non-json files.
  -c, --use-schema      Write a schema along with unpacked files, and use an existing schema when repacking.
  -a, --overwrite-all   Overwrite existing files without prompting.
  -s, --silent          Remove all prompts during execution. Enabling this will enable "--overwrite-all".

Mode: If neither "--unpack" nor "--repack" are specified, then both are enabled at the same time (i.e. json files will be repacked, non-json files will be unpacked).

Schema: If "--use-schema" is specified, then:
    for each file unpacked, another file with extension ".msgschema.json" will be created, which will contain type information for the unpacked json file.
    for each file repacked, if its schema exists, it will be used when repacking to get the correct type information.
This should be used to enforce specific packing types to fix repacking for some files (i.e. some .code files).
```

# Credits
Original script was made by Arsym, who figured out the compression.

Thanks to [Timo654](https://github.com/Timo654) for extensively testing the script.
