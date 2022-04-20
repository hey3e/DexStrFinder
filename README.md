# DexStrFinder
A script to find target string in dex.

This is a small tool to find strings in dex files, which is modified from a dex parser. It is faster than searching strings line by line in the source code of apk because it directly parses the string_id_list and search strings in the result.

### Usage:
```
python3 dexParser.py [path of dex] [re]
```
