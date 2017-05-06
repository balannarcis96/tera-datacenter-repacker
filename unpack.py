import datacenter
import itertools
import os.path
from lxml import etree


def mkdir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def make_etree(data, element):
    name = data.get_name(element)
    root = etree.Element(name)

    for attr in element.get_attributes():
        attrname = data.get_name(attr)
        val = attr.value

        if type(val) not in [int, bool, float]:
            val = val.getstr()
        else:
            val = str(val)

        root.set(attrname, val)

    root.set("unk1", str(element.unk1))

    for elem in element.get_children():
        root.append(make_etree(data, elem))

    return root

def make_xml(data, element):
    root = make_etree(data, element)
    return etree.tostring(root, pretty_print=True)

# todo: load from commandline / process

packed = "D:\Games\TERA\Client\S1Game\S1Data\DataCenter_Final_EUR.dat.bck"
key = bytes(bytearray.fromhex("033BC669EC0C9136DEE66D616CA75712"))
iv = bytes(bytearray.fromhex("25B55107792BD1018E9567086CDA5965"))

data = open(packed, "rb").read()
unpacked = datacenter.unpack(data, key, iv)

stream = datacenter.StructStream(unpacked)
data = datacenter.Datacenter()

stream.unpack(data)
stream = None           # free a bit of abused memory


root = data.get_root()
key =  lambda child: data.get_name(child)

children = sorted(root.get_children(), key=key)
children = itertools.groupby(children, key=key)

target = "out\\xml\\"

print("Creating xmls")

for key, group in children:
    group = list(group)
    print(key)

    if len(group) == 1:
        path = os.path.join(target, key + ".xml")
        out = open(path, "wb")
        elem = group[0]

        out.write(make_xml(data, elem))

    else:
        dir = os.path.join(target, key)
        mkdir(dir)

        for i, elem in enumerate(group):
            path = os.path.join(dir, "{}-{}.xml".format(key, i))
            out = open(path, "wb")
            out.write(make_xml(data, elem))