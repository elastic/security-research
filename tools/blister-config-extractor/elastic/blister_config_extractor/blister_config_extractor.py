import binascii
import json
import os
import sys
from optparse import OptionParser
from struct import pack, unpack

import pefile
import yara
from malduck import lznt1

from .Rabbit_Cipher import Rabbit


def p32(a):
    return pack("<I", a)


def u32(a):
    return unpack("<I", a)[0]


def u16(a):
    return unpack("<H", a)[0]


def dexor(data, key):
    decrypted = []
    for i in range(0, len(data)):
        decrypted.append(data[i] ^ key[i & 3])

    return bytes(decrypted)


def decrypt_memory(file):
    print("\033[1;31m[+] FILE: {} \033[0m".format(file))

    try:
        pe = pefile.PE(file)
    except Exception:
        return -1

    if pe.FILE_HEADER.Machine == 0x8664:
        print("[+] Sample is 64bit")
        arch_size = 8
    else:
        print("[+] Sample is 32bit")
        arch_size = 4

    if arch_size == 4:  # 32bit
        key_rule = yara.compile(
            source="rule foo: bar {strings: $a = {64 A1 30 00 00 00 53 57 89 75 F4 8B 40 0C 8B 40 1C C7 45 E8 ?? ?? ?? ?? 8B 58 08 8B 43 3C} condition: $a}"
        )
        tag_rule = yara.compile(
            source="rule foo: bar {strings: $a = {8B 45 04 B9 ?? ?? ?? ?? EB ?? 0F B7 07 8B 7D E0 8B 3C 87} condition: $a}"
        )
    else:  # 64bit
        key_rule = yara.compile(
            source="rule foo: bar {strings: $a = {25 60 00 00 00 44 0F B7 DB 48 8B 48 ?? 48 8B 41 ?? C7 45 48 ?? ?? ?? ?? 4C 8B 40} condition: $a}"
        )
        tag_rule = yara.compile(
            source="rule foo: bar {strings: $a = {8B 7D ?? B8 ?? ?? ?? ?? EB 0F 41 ?? B7 018B 34 87 49 03 F0 EB ??} condition: $a}"
        )

    data = open(file, "rb").read()

    key_offset = key_rule.match(data=data)
    tag_offset = tag_rule.match(data=data)

    if not key_offset or not tag_offset:
        print("[-] Error signature not found")
        print("-" * 100)
        return -1

    key_offset = key_offset[0].strings[0][0]
    tag_offset = tag_offset[0].strings[0][0]

    key = data[key_offset + 20 : key_offset + 20 + 4]
    tag = data[tag_offset + 4 : tag_offset + 4 + 4]

    print("[+] Xor key:", hex(u32(key)))
    print("[+] Packed code tag:", hex(u32(tag)))

    section = None
    for entry in pe.sections:
        if entry.Name.replace(b"\x00", b"") == b".rsrc":
            section = entry
            break

    if section is None:
        print("\033[92m[+] .rsrc section not found in file: {} \033[0m".format(file))
        return

    rsrc_data = section.get_data()
    encrypted_memory_offset = rsrc_data.find(tag)

    decrypted_memory = dexor(
        rsrc_data[encrypted_memory_offset + 4 :], key
    )  # DECRYPTED MEMORY

    key_pattern_rule32 = """
        rule key_pattern_rule
        {
            strings:
                $pattern1 = {FC 22 F3 66 0F B3 C1 8B 4D 08 81 F1 ?? ?? ?? ?? 8B 55 FC 39 0A}
                $pattern2 = {8B 4D 08 ?? ?? ?? ?? ?? ?? ?? 81 F1 ?? ?? ?? ?? 8B 55 FC ?? ?? ?? 39 0A 0F}
            condition: any of them
        }
    """
    key_pattern_rule32 = yara.compile(source=key_pattern_rule32)
    key_pattern_offset32 = key_pattern_rule32.match(data=decrypted_memory)

    key_pattern_rule64 = yara.compile(
        source="rule foo: bar {strings: $a = {?? 41 0F 4A CE 80 C1 ?? 41 0A CA 35 ?? ?? ?? ?? 86 E9 48 8B 4C 24 ?? F6 C1 ??} condition: $a}"
    )
    key_pattern_offset64 = key_pattern_rule64.match(data=decrypted_memory)

    if key_pattern_offset32:  # 32bit samples
        key_pattern_offset = key_pattern_offset32[0].strings[0][0]
        key_pattern = decrypted_memory[
            key_pattern_offset + 12 : key_pattern_offset + 12 + 4
        ]
    elif key_pattern_offset64:  # 64bit samples
        key_pattern_offset = key_pattern_offset64[0].strings[0][0]
        key_pattern = decrypted_memory[
            key_pattern_offset + 12 : key_pattern_offset + 12 + 4
        ]
    else:
        print("[-] key_pattern_rule Error signature not found")
        print("-" * 100)
        return 0

    config_tag = (u32(key)) ^ (u32(key_pattern))

    print("[+] Config tag:", hex(config_tag))

    encrypted_config_offset = rsrc_data.rfind(p32(config_tag))

    if encrypted_config_offset == -1:
        print("Encrypted config not found")
        return -1

    config_size = 0x644

    decrypted_config = dexor(
        rsrc_data[
            encrypted_config_offset + 4 : encrypted_config_offset + 4 + config_size
        ],
        key,
    )

    key = decrypted_config[0x62C : 0x62C + 16]
    iv = decrypted_config[0x63C : 0x63C + 8]
    compressed_data_size = decrypted_config[0x624 : 0x624 + 4]
    uncompressed_data_size = decrypted_config[0x628 : 0x628 + 4]
    flag = u16(decrypted_config[0:2])
    payload_export_hash = decrypted_config[2:6]
    MZ = True
    w_payload_filename_and_cmdline = ""
    sleep_after_injection = True if (flag & 0x100) != 0 else False
    persistance = True if (flag & 1) != 0 else False
    if persistance:
        w_payload_filename_and_cmdline = (
            decrypted_config[6:0x210]
            .split(b"\x00\x00")[0]
            .replace(b"\x00", b"")
            .decode()
        )
    if (flag & 2) != 0:
        injection_method = "Reflective injection"
    elif (flag & 0x40) != 0:
        injection_method = "Execute shellcode"
        MZ = False
    else:
        if (flag & 8) != 0:
            injection_method = "Process hollowing current executable (rundll32.exe in case of a DLL sample)"
        elif (flag & 0x10) != 0:
            injection_method = "Process hollowing IE or Werfault"

    config = {
        "Flag": hex(flag),
        "Payload_export_hash": hex(u32(payload_export_hash)),
        "w_payload_filename": w_payload_filename_and_cmdline,
        "Compressed_data_size": hex(u32(compressed_data_size)),
        "Uncompressed_data_size": hex(u32(uncompressed_data_size)),
        "Rabbit key": binascii.hexlify(key).decode(),
        "Rabbit iv": binascii.hexlify(iv).decode(),
        "Persistance": persistance,
        "Sleep after injection": sleep_after_injection,
        "Injection method": injection_method,
    }

    print("[+] Blister configuration:")
    print(json.dumps(config, indent=4))

    # decrypt payload

    encrypted_payload = rsrc_data[
        encrypted_config_offset
        + 4
        + config_size : encrypted_config_offset
        + 4
        + config_size
        + u32(compressed_data_size)
    ]  # 4 == tag size

    cipher = Rabbit(bytes(key), bytes(iv))

    decrypted_payload = cipher.crypt(bytes(encrypted_payload))

    uncompressed_payload = lznt1(decrypted_payload)

    save_payload_path = "{}_payload".format(file)

    print(
        "\033[92m[+] Payload extracted and saved to: {} \033[0m".format(
            save_payload_path
        )
    )

    if MZ:
        uncompressed_payload = b"MZ" + uncompressed_payload[2:]

    with open(save_payload_path, "wb") as f:
        f.write(uncompressed_payload)


def main():
    print("Author: @Soolidsnake")
    print(
        """
  ____   _  _       _                                    __  _                      _                      _
 |  _ \ | |(_)     | |                                  / _|(_)                    | |                    | |
 | |_) || | _  ___ | |_  ___  _ __    ___  ___   _ __  | |_  _   __ _    ___ __  __| |_  _ __  __ _   ___ | |_  ___   _ __
 |  _ < | || |/ __|| __|/ _ \| '__|  / __|/ _ \ | '_ \ |  _|| | / _` |  / _ \\\\ \/ /| __|| '__|/ _` | / __|| __|/ _ \ | '__|
 | |_) || || |\__ \| |_|  __/| |    | (__| (_) || | | || |  | || (_| | |  __/ >  < | |_ | |  | (_| || (__ | |_| (_) || |
 |____/ |_||_||___/ \__|\___||_|     \___|\___/ |_| |_||_|  |_| \__, |  \___|/_/\_\ \__||_|   \__,_| \___| \__|\___/ |_|
                                                                 __/ |
                                                                |___/
"""  # noqa: W605
    )
    parser = OptionParser()

    parser.add_option("-f", "--file", dest="filename", help="file", metavar="file")
    parser.add_option("-d", "--dir", dest="dirname", help="directory", metavar="dir")
    (options, args) = parser.parse_args()
    file_path = options.filename
    dir_path = options.dirname
    if file_path is None and dir_path is None:
        parser.print_help()
        sys.exit(1)

    if file_path and os.path.isfile(file_path):
        decrypt_memory(file_path)

    if dir_path and os.path.isdir(dir_path):
        for (dirpath, _, filenames) in os.walk(dir_path):
            for file in filenames:
                decrypt_memory(os.path.join(dirpath, file))


if __name__ == "__main__":
    main()
