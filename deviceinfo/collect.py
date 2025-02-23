"""
Collects all devices from deviceinfo.device and generates a file with two dicts, one mapping device names
to signatures, one mapping ids to interfaces, the other one from signatures to names. Provide path to devices folöder.
"""

import os
import argparse
import textwrap
import re

def main():

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent('''\
    Collects data of all devices stored in a Python file in the folder given as an argument.
    Three dictionaries are created, dev_ids, mapping device names to ids, dev_names mapping ids to names,
    and dev_iface, which maps ids to interaces.
        '''))

    parser.add_argument("filename",
                        help="name (and path) of file to harvest data from or path to folder with atdf files"
                        )

    arguments = parser.parse_args()

    dev_id = {}
    dev_name = {}
    dev_iface = {}
    for file in os.listdir(arguments.filename):
        if file.endswith(".py"):
            with open(arguments.filename + "/" +file) as f:
                spec = f.read()
                if spec.find("DEVICE_INFO") < 0:
                    continue
                name = re.findall("'name'\\s*:\\s*'(.*)'", spec)[0]
                id = int(re.findall("'device_id'\\s*:\\s*(0x.*),", spec)[0], 16)
                iface = re.findall("'interface'\\s*:\\s*'(.*)'", spec)[0]
                dev_id[name] = id
                oldname = dev_name.get(id)
                if not oldname:
                    dev_name[id] = name
                elif oldname.startswith(name):
                    dev_name[id] = name + "(" + oldname.removeprefix(name) + ")"
                elif name.startswith(oldname):
                    dev_name[id] = oldname + "(" + name.removeprefix(oldname) + ")"
                else:
                    dev_name[id] = name + "/" + oldname
                dev_iface[id] = iface
    
    print('dev_id =', dev_id)
    print('dev_name =', dev_name)
    print('dev_iface =', dev_iface)
    
if __name__ == "__main__":
    main()
