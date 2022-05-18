# coding: utf-8

import argparse
import os
import string
import struct
import typing

import capstone
import lief
import unicorn
from colorama import Fore, init

init()

STACK_ADDRESS = 0x100000
MEMORY_SIZE = 0x100000
STRING_THRESHOLD = 3
BYTECODE_SIZE = 0x100


def is_x64(elf: lief.ELF.Binary) -> bool:
    machine_type = elf.header.machine_type
    if machine_type == lief.ELF.ARCH.x86_64:
        return True
    elif machine_type == lief.ELF.ARCH.i386:
        return False
    else:
        raise RuntimeError("Unsupported Architecture.")


def print_red(s: str) -> None:
    print(Fore.RED + s + Fore.RESET)


def print_green(s: str) -> None:
    print(Fore.GREEN + s + Fore.RESET)


def new_emulator(x64: bool, stack_address, stack_size) -> unicorn.Uc:
    emulator = unicorn.Uc(
        unicorn.UC_ARCH_X86, unicorn.UC_MODE_64 if x64 else unicorn.UC_MODE_32
    )
    emulator.mem_map(stack_address, stack_size)
    emulator.reg_write(
        unicorn.x86_const.UC_X86_REG_RSP if x64 else unicorn.x86_const.UC_X86_REG_ESP,
        (stack_address + (stack_size // 2)),
    )
    """
    emulator.reg_write(unicorn.x86_const.UC_X86_REG_GS if x64 else unicorn.x86_const.UC_X86_REG_FS,
                       (stack_address + (stack_size // 2)))
    """
    return emulator


def new_disassembler(is_x64: bool) -> capstone.Cs:
    disassembler = capstone.Cs(
        capstone.CS_ARCH_X86, capstone.CS_MODE_64 if is_x64 else capstone.CS_MODE_32
    )
    disassembler.detail = True
    return disassembler


def get_main_va(binary: lief.ELF.Binary, x64: bool) -> int:
    entry_point = bytes(
        binary.get_content_from_virtual_address(binary.header.entrypoint, BYTECODE_SIZE)
    )

    print("[+] Imagebase: 0x{:x}".format(binary.imagebase))
    print("[+] Entrypoint: 0x{:x}".format(binary.header.entrypoint))

    limit = 0
    disassembler = new_disassembler(x64)
    for i, x in enumerate(disassembler.disasm(entry_point, 0)):
        if x.group(capstone.CS_GRP_CALL):
            limit = x.address
            break
    entry_point = entry_point[:limit]

    emulator = new_emulator(x64, STACK_ADDRESS, MEMORY_SIZE)
    emulator.mem_map(binary.imagebase, MEMORY_SIZE)
    emulator.mem_write(binary.header.entrypoint, entry_point)
    emulator.emu_start(
        binary.header.entrypoint, binary.header.entrypoint + len(entry_point)
    )

    if x64:
        main_va = emulator.reg_read(unicorn.x86_const.UC_X86_REG_RDI)
    else:
        main_va = struct.unpack(
            "I",
            emulator.mem_read(emulator.reg_read(unicorn.x86_const.UC_X86_REG_ESP), 4),
        )[0]

    return main_va


def find_strings(memory: bytearray, threshold) -> list[bytes]:
    printable = bytes(string.printable, "utf-8")
    candidates = list()
    candidate = bytearray()
    for i in range(len(memory)):
        if memory[i] in printable:
            candidate.append(memory[i])
        elif candidate:
            if threshold <= len(candidate):
                candidates.append(bytes(candidate))
            candidate = bytearray()
    return candidates


def get_password(file) -> None:
    print_red("[+] FILE: {}".format(file))

    binary = lief.parse(file)
    x64 = is_x64(binary)
    print("[+] Architecture is {}".format("x64" if x64 else "x32"))
    main_va = get_main_va(binary, x64)
    print("[+] Main: 0x{:x}".format(main_va))

    emulator = new_emulator(x64, STACK_ADDRESS, MEMORY_SIZE)
    emulator.mem_map(binary.imagebase, MEMORY_SIZE)

    rodata = binary.get_section(".rodata")
    if rodata:
        emulator.mem_write(
            rodata.virtual_address,
            bytes(
                binary.get_content_from_virtual_address(
                    rodata.virtual_address, rodata.size
                )
            ),
        )

    main_code = bytes(binary.get_content_from_virtual_address(main_va, BYTECODE_SIZE))
    emulator.mem_write(main_va, main_code)
    try:
        emulator.emu_start(main_va, main_va + len(main_code))
    except unicorn.unicorn.UcError:
        pass

    print_green(
        "passwords: {}".format(
            find_strings(
                emulator.mem_read(STACK_ADDRESS, MEMORY_SIZE), STRING_THRESHOLD
            )[-2:]
        )
    )
    print()


def print_header() -> None:
    print("Author: Elastic Security (MARE)")
    print(
        r"""
______ ______ ______ ______
| ___ \| ___ \|  ___||  _  \
| |_/ /| |_/ /| |_   | | | | ___    ___   _ __
| ___ \|  __/ |  _|  | | | |/ _ \  / _ \ | '__|
| |_/ /| |    | |    | |/ /| (_) || (_) || |
\____/ \_|    \_|    |___/  \___/  \___/ |_|
 _____                 __  _          _____       _                      _
/  __ \               / _|(_)        |  ___|     | |                    | |
| /  \/  ___   _ __  | |_  _   __ _  | |__ __  __| |_  _ __  __ _   ___ | |_  ___   _ __
| |     / _ \ | '_ \ |  _|| | / _` | |  __|\ \/ /| __|| '__|/ _` | / __|| __|/ _ \ | '__|
| \__/\| (_) || | | || |  | || (_| | | |___ >  < | |_ | |  | (_| || (__ | |_| (_) || |
 \____/ \___/ |_| |_||_|  |_| \__, | \____//_/\_\ \__||_|   \__,_| \___| \__|\___/ |_|
                               __/ |
                              |___/

"""  # noqa: W605
    )


def for_each_file_in_directory(function: typing.Callable, path: str) -> None:
    if not os.path.isdir(path):
        raise RuntimeError("Path is not a directory")

    for (dirpath, _, filenames) in os.walk(path):
        for file in filenames:
            try:
                function(os.path.join(dirpath, file))
            except Exception as e:
                print_red("[-] Exception: {}".format(e))
                continue


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    options = parser.add_mutually_exclusive_group(required=True)
    options.add_argument("-f", "--file", dest="filename", help="File")
    options.add_argument("-d", "--dir", dest="dirname", help="Directory")
    return parser.parse_args()


def main() -> None:
    print_header()
    args = parse_args()
    if args.filename:
        get_password(args.filename)
    elif args.dirname:
        for_each_file_in_directory(get_password, args.dirname)


if __name__ == "__main__":
    main()
