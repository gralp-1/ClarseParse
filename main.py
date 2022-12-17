import sys
from pprint import pprint as pp

class CipherClass:
    def __init__(self, file_name):
        # Open the file in binary mode and read the data
        with open(file_name, "rb") as f:
            data = f.read()

        # Convert the data to a list of hexadecimal strings
        self.hex_list = [hex(b)[2:].zfill(2).upper() for b in data]
        self.minor_v = 0
        self.major_v = 0
        self.constant_pool_count = 0
        self.constant_tag_kind   = {}
        self.constant_tag_bytes = {}
        self.constant_pool_raw = []
        self.constant_tag_count = {}
        self.constant_pool = []
        self.constant_pool_length_bytes = len(flatten(self.constant_pool_raw))
        # get the full length of the constant_pool_raw


        self.magic_check()
        self.class_info()
        self.block_constant_pool()
        self.parse_constants()

        pp(self.constant_pool)
        pp(self.constant_tag_count)



    def parse_constants(self):
        for constant in self.constant_pool_raw:
            tag = constant[0]
            kind = self.constant_tag_kind[int(tag,16)]
            self.constant_tag_count[kind] = self.constant_tag_count.get(kind, 0) + 1
            match kind:
                case "CONSTANT_NameAndType":
                    self.constant_pool.append({"type": kind, "name_index": hxint(constant[1:3]), "descriptor_index": hxint(constant[3:5])})
                case "CONSTANT_Utf8":
                    # next two bytes are length
                    # then after that the next length bytes are the string
                    length = hxint(constant[1:3])
                    byte_string = bytes.fromhex("".join(constant[3:3+length])).decode("utf-8")
                    print(f"Utf8: {byte_string}")
                case "CONSTANT_Integer" | "CONSTANT_FLOAT":
                    # next 4 bytes are the integer
                    integer = hxint(constant[1:5])
                    print(f"Integer: {integer}")
                case "CONSTANT_Methodref" | "CONSTANT_Fieldref" | "CONSTANT_InterfaceMethodref":
                    self.constant_pool.append({"type": kind, "class_index": hxint(constant[1:3]), "name_and_type_index": hxint(constant[3:5])})
                case "CONSTANT_String":
                    # next 2nd and 3rd bytes are the index of the string
                    string_index = hxint(constant[1:3])
                    print(f"String: {string_index}")

    def magic_check(self):
        if self.hex_list[0:4] != ["CA", "FE", "BA", "BE"]:
            print("Not a valid class file")
            exit()
        self.hex_list = self.hex_list[4:]
    def class_info(self):
        
        with open("constant_pool_type.csv", "r") as f:
            for line in f.readlines()[1:]:
                # Remove the newline character
                line = line[:-1]
                tag, kind, tag_bytes= line.split(",")
                self.constant_tag_kind[int(tag)] = kind
                if tag_bytes != "":
                    self.constant_tag_bytes[int(tag)] = int(tag_bytes)


        # Extract the minor and major version numbers from the hex list
        self.minor_v = hxint(self.hex_list[0:2])
        self.major_v = hxint(self.hex_list[2:4])

        self.constant_pool_count = hxint(self.hex_list[4:6])

        # TODO: after constant pool parse, find the rest of the info

        self.hex_list = self.hex_list[6:]
    def print_info(self):
        print(f"Minor version: {self.minor_v}")
        print(f"Major version: {self.major_v} (Java {self.major_v - 44})")
        print(f"Constant pool count: {self.constant_pool_count}")
    def block_constant_pool(self):
        for _ in range(0, self.constant_pool_count - 1):
            # check if the tag is valid, if not we've reached the end of the constant pool
            #try:
            #    self.constant_tag_kind[int(self.hex_list[0], 16)]
            #except KeyError:
            #    break
            # get the tag type and add it to constant_tag_count
            self.constant_tag_count[self.constant_tag_kind[int(self.hex_list[0], 16)]] = self.constant_tag_count.get(self.constant_tag_kind[int(self.hex_list[0], 16)], 0) + 1
            # check if the tag has a fixed length, if not, the next two bytes are the length
            if self.constant_tag_bytes[int(self.hex_list[0], 16)] == -1:
                bytelen = hxint(self.hex_list[1:3]) + 3
            else:
                bytelen = self.constant_tag_bytes[int(self.hex_list[0], 16)]
            const = self.hex_list[0:bytelen]
            self.constant_pool_raw.append(const)
            self.hex_list = self.hex_list[bytelen:]

def hxint(hex_list):
    return int("".join(hex_list), 16)

def flatten(lst):
    flat_list = []
    for elem in lst:
        if type(elem) == list:
            flat_list.extend(flatten(elem))
        else:
            flat_list.append(elem)
    return flat_list

if __name__ == "__main__":
    file_name = sys.argv[1]
    cipher_class = CipherClass(file_name)
    cipher_class.print_info()