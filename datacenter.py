from Crypto.Cipher import AES
from Crypto.Hash import SHA256

import struct
import zlib
import binascii
import io
import collections

def sha1(text):
    s = SHA256.new()
    s.update(text)
    return s.hexdigest()

def unpack(data, key, iv):
    print ("Unpacking ...")
    print ('Original:\t' + sha1(data))

    orig_len = len(data) - (len(data) // 16) * 16
    last_block = len(data) - (len(data) // 16) * 16
    data += b"\x00" * (16 - last_block)

    aes = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
    decrypted = aes.decrypt(data)

    padding = decrypted[orig_len-16:]

    decrypted = decrypted[:orig_len-16]
    print ('Decrypted:\t' + sha1(decrypted))

    unpacked = zlib.decompress(decrypted[4:])

    print ('Unpacked:\t' + sha1(unpacked))

    return unpacked

def pack(data, key, iv):
    print ("Packing ...")
    print ('Original:\t' + sha1(data))

    packed = struct.pack("<I", len(data)) + zlib.compress(data)
    print ('Packed:\t\t' + sha1(packed))

    orig_len = len(packed) - (len(packed) // 16) * 16
    last_block = len(packed) - (len(packed) // 16) * 16
    packed += b"\x00" * (16 - last_block)

    aes = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
    encrypted = aes.encrypt(packed)

    encrypted = encrypted[:orig_len-16]

    print ('Encrypted:\t' + sha1(encrypted))

    return encrypted


class StructStream:
    def __init__(self, data=b""):
        self.data = io.BytesIO(data)

    def unpack(self, *formats):
        res = []

        for format in formats:
            if type(format) == str:
                size = struct.calcsize(format)
                data = self.data.read(size) 
                res += [struct.unpack(format, data)]
            else:
                res += [format.__unpack__(self)]

        if len(res) == 1:
            return res[0]
        else:
            return tuple(res) 

    def pack(self, format, *args):
        if type(format) == str:
            self.data.write(struct.pack(format, *args))
        else:
            format.__pack__(self)
            for obj in args:
                obj.__pack__(self) 

    def getvalue(self):
        return self.data.getvalue()

    def seek(self, x, mode=1):
        return self.data.seek(x, mode)

    def write(self, *args, **kwargs):
        return self.data.write(*args, **kwargs)

    def read(self, *args, **kwargs):
        return self.data.read(*args, **kwargs)

    def tell(self):
        return self.data.tell()

def readstr(str, start):
    stop = start
    for index, char in enumerate(str[start:], start=start):
        if ord(char) == 0:
            stop = index
            break

    return str[start:stop]


def Address(target):
    class AddressGeneric:
        __slots__ = ("upper", "lower", "target")

        def __init__(self, upper=0, lower=0):
            self.upper = upper
            self.lower = lower

        def __unpack__(self, stream):
            self.upper, self.lower = stream.unpack("<HH")

            return self

        def __pack__(self, stream):
            stream.pack("<HH", self.upper, self.lower)

        def get(self):
            return self.target[self.upper][self.lower]

        def getstr(self):
            return readstr(self.target[self.upper], self.lower)

        def getrange(self, *args):
            for x in range(*args):
                # print(self.upper, self.lower, "+", x)
                yield self.target[self.upper][self.lower + x]

        def __str__(self):
            return "Address({}, {})".format(self.upper, self.lower)

    AddressGeneric.target = target
    return AddressGeneric

def Region(type, size=0, offby=0, writesize=True, writeactual=False, debug=False):
    class RegionGeneric:
        def __init__(self):
            self.type = type
            self.offby = offby
            self.size = size
            self.actual = 0
            self.data = []

            self.writesize = writesize
            self.writeactual = writeactual


        def __unpack__(self, stream):
            if self.writesize:
                self.size, = stream.unpack("<I")
            
            if self.writeactual:
                self.actual, = stream.unpack("<I")

            self.size += self.offby
            self.data = [stream.unpack(self.type()) for i in range(self.size)]

            return self
            
        def __pack__(self, stream):
            if self.writesize:
                stream.pack("<I", self.size - self.offby)

            if self.writeactual:
                stream.pack("<I", self.actual)

            for obj in self.data:
                stream.pack(obj)

        def __iadd__(self, other):
            if type(other) != self.type:
                raise TypeError("Region of {} can't hold {}".format(self.type, type(other)))

            self.data += [other]
            self.size += 1
            self.actual += 1

        def __getitem__(self, i):
            return self.data[i + self.offby]

        def __setitem__(self, i, x):
            self.data[i + self.offby] = x

        def __iter__(self):
            return iter(self.data)

        def __len__(self):
            return len(self.data)

    return RegionGeneric

class Utf16String(str):
    def __unpack__(self, stream):
        size, x = stream.unpack("<II")
        value = stream.read(size * 2).decode("utf16")
        return type(self)(value) 

    def __pack__(self, stream):
        stream.pack("<II", len(self), len(self))
        stream.write(self.encode("utf16")[2:])


def Metadata(addrtype):
    class MetadataGeneric:
        def __unpack__(self, stream):
            self.unk1, self.length, self.order = stream.unpack("<III")
            self.addr = stream.unpack(addrtype())
            
            return self

        def __pack__(self, stream):
            stream.pack("<III", self.unk1, self.length, self.order)
            stream.pack(self.addr)

    return MetadataGeneric


def Element(AttributeAddr, ElementAddr):
    class ElementGeneric:
        def __unpack__(self, stream):
            self.name_index, self.unk1, self.attribute_count, self.child_count = stream.unpack("<HHHH")
            self.attributes = stream.unpack(AttributeAddr())
            self.children = stream.unpack(ElementAddr())

            return self

        def __pack__(self, stream):
            stream.pack("<HHHH", self.name_index, self.unk1, self.attribute_count, self.child_count)
            stream.pack(self.attributes, self.children)

        def get_children(self):
            yield from self.children.getrange(self.child_count)
        
        def get_attributes(self):
            yield from self.attributes.getrange(self.attribute_count)

    return ElementGeneric

def Attribute(StringAddr):
    class AttributeGeneric:
        __slots__ = ("value", "name_index", "typecode")

        def __unpack__(self, stream):
            self.name_index, typecode = stream.unpack("<HH")
            self.value = None

            if typecode == 1:
                self.value, = stream.unpack("<I")
            elif typecode == 2:
                self.value, = stream.unpack("<f")
            elif typecode == 5:
                self.value = stream.unpack("<I")[0] != 0
            else:
                # print(typecode)
                self.value = stream.unpack(StringAddr())

            self.typecode = typecode

            return self

        def __pack__(self, stream):
            typecode = 1 if type(self.value) == int else (2 if type(self.value) == float else (5 if type(self.value) == bool else 3))
            typecode = self.typecode

            stream.pack("<HH", self.name_index, typecode)

            if typecode == 1:
                stream.pack("<I", self.value)
            elif typecode == 2:
                stream.pack("<f", self.value)
            elif typecode == 5:
                stream.pack("<I", 1 if self.value else 0)
            else:
                stream.pack(self.value)


            # stream.pack(self.attributes, self.children)

    return AttributeGeneric

class Header:
    def __unpack__(self, stream):
        self.unk1, self.unk2, self.unk3, self.version = stream.unpack("<IIII")
        self.unk4, self.unk5, self.unk6, self.unk7 = stream.unpack("<IIII")
        return self

    def __pack__(self, stream):
        stream.pack("<IIII", self.unk1, self.unk2, self.unk3, self.version)
        stream.pack("<IIII", self.unk4, self.unk5, self.unk6, self.unk7)

class Footer:
    def __unpack__(self, stream):
        self.unk1, = stream.unpack("<I")
        return self

    def __pack__(self, stream):
        stream.pack("<I", self.unk1)

class Unk1:
    def __unpack__(self, stream):
        self.unk1, self.unk2 = stream.unpack("<II")
        return self

    def __pack__(self, stream):
        stream.pack("<II", self.unk1, self.unk2)




class Datacenter:
    def __init__(self):
        self.header = Header()

        self.unk1 = Region(Unk1)()
        self.StringAddr = Address([])
        self.attributes = Region(Region(Attribute(self.StringAddr), writeactual=True),debug=True)()
        self.AttributeAddr = Address(self.attributes)

        self.ElementAddr = Address(self.attributes)
        self.elements = Region(Region(Element(self.AttributeAddr, self.ElementAddr), writeactual=True), debug=True)()
        self.ElementAddr.target = self.elements
        

        self.strings = Region(Utf16String)()
        self.names = Region(Utf16String)()

        self.NameAddr = Address(self.names)
        self.StringAddr.target = self.strings
        self.string_index = Region(self.StringAddr, offby = -1)()
        self.name_index = Region(self.NameAddr, offby = -1)()

        self.strings_meta = Region(Region(Metadata(self.StringAddr)), size=1024, writesize=False)()
        self.names_meta = Region(Region(Metadata(self.NameAddr)), size=512, writesize=False)()

        self.footer = Footer()

    def __unpack__(self, stream):
        stream.unpack(self.header)
        # print(stream.tell())
        stream.unpack(self.unk1)

        print("Unk1:", len(self.unk1))
        # print(stream.tell())

        stream.unpack(self.attributes)
        print("Attributes:", len(self.attributes))
        # print(stream.tell())
        
        stream.unpack(self.elements)
        print("Elements:", len(self.elements))
        # print(stream.tell())
        
        stream.unpack(self.strings)
        # print(stream.tell())
        stream.unpack(self.strings_meta)
        # print(stream.tell())
        stream.unpack(self.string_index)
        # print(stream.tell())

        print("Strings:", len(self.strings))
        print ("String addresses:", len(self.string_index))
    
        
        stream.unpack(self.names)
        # print(stream.tell())
        stream.unpack(self.names_meta)
        # print(stream.tell())
        stream.unpack(self.name_index)
        # print(stream.tell())
        
        print("Names:", len(self.names))
        print ("Name addresses:", len(self.name_index))

        stream.unpack(self.footer)
        # print(stream.tell())
        print("Done!")

    def __pack__(self, stream):
        stream.pack(self.header)
        stream.pack(self.unk1)

        stream.pack(self.attributes)
        print("Attributes:", len(self.attributes))
        
        stream.pack(self.elements)
        print("Elements:", len(self.elements))
        
        stream.pack(self.strings)
        stream.pack(self.strings_meta)
        stream.pack(self.string_index)

        print("Strings:", len(self.strings))
        print ("String addresses:", len(self.string_index))
    
        
        stream.pack(self.names)
        stream.pack(self.names_meta)
        stream.pack(self.name_index)
        
        print("Names:", len(self.names))
        print ("Name addresses:", len(self.name_index))

        stream.pack(self.footer)
        print("Done!")

    def get_root(self):
        return self.elements[0][0]

    def get_name(self, obj):
        return self.name_index[obj.name_index].getstr()

    # def get_string(self, i):
    #     return self.string_index[i].getstr()