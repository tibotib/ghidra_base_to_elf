import lief
import sys
import os

from final_elf import FinalElf


def main() :
    path_elf: str                 = "/Users/fouque/thibault/ghidra_base_to_elf/ghidra_base_to_elf2/exemple/windows/test_x64.elf"
    path_xml: str                 = "/Users/fouque/thibault/ghidra_base_to_elf/ghidra_base_to_elf2/exemple/windows/heartbleeder_x64.xml"

    final_elf = FinalElf(path_elf, path_xml)
    final_elf.gen_header()
    final_elf.parse_header()
    final_elf.gen_elf()

if __name__ == "__main__":
    main()
