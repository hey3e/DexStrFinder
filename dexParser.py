import binascii
import re
import sys


def calValue(f):
    tmp = bytearray(f)
    tmp.reverse()
    return str(binascii.b2a_hex(bytes(tmp)), encoding="utf-8")


def parseDexHeader(f):
    print("[+]dex_header: ")
    f.seek(0x0)
    value = f.read(8)
    magic = str(binascii.b2a_hex(value), encoding="utf-8")
    print("     Magic: " + magic.upper() + " (value: " + str(value) + ")")

    f.seek(0x8)
    checksum = calValue(f.read(4))
    print("     Alder32 checksum of rest of file: " + checksum.upper())

    f.seek(0x0C)
    signature = str(binascii.b2a_hex(f.read(20)), encoding="utf-8")
    print("     SHA-1 signature of rest of file: " + signature.upper())

    f.seek(0x20)
    file_size = calValue(f.read(4))
    print("     File size in bytes: " + str(int(file_size, 16)))

    f.seek(0x24)
    header_size = calValue(f.read(4))
    print("     Header size in bytes: " + str(int(header_size, 16)))

    f.seek(0x28)
    endian_tag = str(binascii.b2a_hex(f.read(4)), encoding="utf-8")
    print("     Endianness tag: " + endian_tag)

    f.seek(0x2C)
    link_size = calValue(f.read(4))
    print("     Size of link section: " + str(int(link_size, 16)))

    f.seek(0x30)
    link_off = calValue(f.read(4))
    print("     File offset of link section: " + hex(int(link_off, 16)))

    f.seek(0x34)
    map_off = calValue(f.read(4))
    print("     File offset of map list: " + hex(int(map_off, 16)))

    f.seek(0x38)
    string_ids_size = calValue(f.read(4))
    print("     Count of strings in the string ID list: " + str(int(string_ids_size, 16)))

    f.seek(0x3C)
    string_ids_off = calValue(f.read(4))
    print("     File offset of string ID list: " + hex(int(string_ids_off, 16)))

    f.seek(0x40)
    type_ids_size = calValue(f.read(4))
    print("     Count of types in the type ID list: " + str(int(type_ids_size, 16)))

    f.seek(0x44)
    type_ids_off = calValue(f.read(4))
    print("     File offset of type ID list: " + hex(int(type_ids_off, 16)))

    f.seek(0x48)
    proto_ids_size = calValue(f.read(4))
    print("     Count of items in the method prototype ID list: " + str(int(proto_ids_size, 16)))

    f.seek(0x4C)
    proto_ids_off = calValue(f.read(4))
    print("     File offset of method prototype ID list: " + hex(int(proto_ids_off, 16)))

    f.seek(0x50)
    field_ids_size = calValue(f.read(4))
    print("     Count of items in the field ID list: " + str(int(field_ids_size, 16)))

    f.seek(0x54)
    field_ids_off = calValue(f.read(4))
    print("     File offset of field ID list: " + hex(int(field_ids_off, 16)))

    f.seek(0x58)
    method_ids_size = calValue(f.read(4))
    print("     Count of items in the method ID list: " + str(int(method_ids_size, 16)))

    f.seek(0x5C)
    method_ids_off = calValue(f.read(4))
    print("     File offset of method ID list: " + hex(int(method_ids_off, 16)))

    f.seek(0x60)
    class_defs_size = calValue(f.read(4))
    print("     Count of items in the class definitions list: " + str(int(class_defs_size, 16)))

    f.seek(0x64)
    class_defs_off = calValue(f.read(4))
    print("     File offset of class definitions list: " + hex(int(class_defs_off, 16)))

    f.seek(0x68)
    data_size = calValue(f.read(4))
    print("     Size of data section in bytes: " + str(int(data_size, 16)))

    f.seek(0x6C)
    data_off = calValue(f.read(4))
    print("     File offset of data section: " + hex(int(data_off, 16)))


def parseStringIds(f):
    # print("[+]dex_string_ids: ")

    string_id_list = []

    f.seek(0x38)
    string_ids_size = int(calValue(f.read(4)), 16)

    f.seek(0x3C)
    string_ids_off = int(calValue(f.read(4)), 16)

    for i in range(string_ids_size):
        f.seek(string_ids_off)
        string_data_off = int(calValue(f.read(4)), 16)
        string_data = getStringData(f, string_data_off)
        string_id_list.append(string_data)
        string_ids_off += 4

    return string_id_list


def getStringData(f, string_data_off):
    try:
        data = bytearray()
        f.seek(string_data_off + 1)
        while True:
            b = int(calValue(f.read(1)), 16)
            if b == 0:
                break
            data.append(b)
        return str(bytes(data), encoding="utf-8")
    except:
        pass


def parseTypeIds(f):
    # print("[+]dex_type_ids: ")

    string_id_list = parseStringIds(f)
    type_id_list = []

    f.seek(0x40)
    type_ids_size = int(calValue(f.read(4)), 16)

    f.seek(0x44)
    type_ids_off = int(calValue(f.read(4)), 16)

    for i in range(type_ids_size):
        f.seek(type_ids_off)
        descriptor_idx = int(calValue(f.read(4)), 16)
        type_id_list.append(string_id_list[descriptor_idx])
        type_ids_off += 4

    return type_id_list


def parseProtoIds(f):
    # print("[+]dex_proto_ids: ")

    string_id_list = parseStringIds(f)
    type_id_list = parseTypeIds(f)
    proto_id_list = []

    f.seek(0x48)
    proto_ids_size = int(calValue(f.read(4)), 16)

    f.seek(0x4C)
    proto_ids_off = int(calValue(f.read(4)), 16)

    for i in range(proto_ids_size):
        f.seek(proto_ids_off)
        shorty_idx = int(calValue(f.read(4)), 16)
        return_type_idx = int(calValue(f.read(4)), 16)
        # print("     String ID of short-form descriptor: " + string_id_list[shorty_idx] +
        #       ", Type ID of the return type: ", type_id_list[return_type_idx])
        proto_id_list.append(string_id_list[shorty_idx])
        proto_ids_off += 12

    return proto_id_list


def parseFieldIds(f):
    print("[+]dex_field_ids: ")

    string_id_list = parseStringIds(f)
    type_id_list = parseTypeIds(f)

    f.seek(0x50)
    field_ids_size = int(calValue(f.read(4)), 16)

    f.seek(0x54)
    field_ids_off = int(calValue(f.read(4)), 16)

    for i in range(field_ids_size):
        f.seek(field_ids_off)
        class_idx = int(calValue(f.read(2)), 16)
        type_idx = int(calValue(f.read(2)), 16)
        name_idx = int(calValue(f.read(4)), 16)
        print("     Type ID of the class that defines this field: " + type_id_list[class_idx] +
              ", Type ID for the type of this field: " + type_id_list[type_idx] +
              ", String ID for the field's name: " + string_id_list[name_idx])
        field_ids_off += 8


def parseMethodIds(f):
    print("[+]dex_method_ids: ")

    string_id_list = parseStringIds(f)
    type_id_list = parseTypeIds(f)
    proto_id_list = parseProtoIds(f)

    f.seek(0x58)
    method_ids_size = int(calValue(f.read(4)), 16)

    f.seek(0x5C)
    method_ids_off = int(calValue(f.read(4)), 16)

    for i in range(method_ids_size):
        f.seek(method_ids_off)
        class_idx = int(calValue(f.read(2)), 16)
        proto_idx = int(calValue(f.read(2)), 16)
        name_idx = int(calValue(f.read(4)), 16)
        print("     Type ID of the class that defines this method: " + type_id_list[class_idx] +
              ", Prototype ID for this method: " + proto_id_list[proto_idx] +
              ", String ID for the method's name: " + string_id_list[name_idx])
        method_ids_off += 8


def parseClass(f):
    print("[+]dex_class_defs: ")

    string_id_list = parseStringIds(f)
    type_id_list = parseTypeIds(f)

    f.seek(0x60)
    class_defs_size = int(calValue(f.read(4)), 16)

    f.seek(0x64)
    class_defs_off = int(calValue(f.read(4)), 16)

    for i in range(class_defs_size):
        f.seek(class_defs_off)
        class_idx = int(calValue(f.read(4)), 16)
        access_flags = hex(int(calValue(f.read(4)), 16))
        superclass_idx = int(calValue(f.read(4)), 16)
        interfaces_off = int(calValue(f.read(4)), 16)
        source_file_idx = int(calValue(f.read(4)), 16)
        annotations_off = int(calValue(f.read(4)), 16)
        static_values_off = int(calValue(f.read(4)), 16)
        print("     Type ID for this class: " + type_id_list[class_idx] +
              ", Access flags: " + str(access_flags) +
              ", Type ID for this class's superclass: " + type_id_list[superclass_idx] +
              ", File offset to interface list: " + str(interfaces_off) +
              ", String ID for the name of the file with this class defined: " + string_id_list[source_file_idx] +
              ", File offset to the annotation structure for this class: " + str(annotations_off) +
              ", File offset to static field data: " + str(static_values_off))

        class_data_off = int(calValue(f.read(4)), 16)
        f.seek(class_data_off)

        class_defs_off += 32


def main():
    f = open(sys.argv[1], "rb", False)
    # parseDexHeader(f)
    # type_id_list = parseTypeIds(f)
    # parseProtoIds(f)
    # parseFieldIds(f)
    # parseMethodIds(f)
    # parseClass(f)
    target = str(sys.argv[2])
    string_id_list = parseStringIds(f)
    result = list(filter(lambda x: re.match(target, str(x)) is not None, string_id_list))
    if len(result) > 0:
        print("[+]FIND IN " + sys.argv[1])
        print(result)


if __name__ == "__main__":
    main()