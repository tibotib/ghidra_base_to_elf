#les fonctions utiles pour geerer l'en-tete
import lief

def ei_ident(info_proc, is_64b)->bytearray :
    """
    retourne e_ident du header(16 premiers bytes)
    """
    ret = bytearray()
    ret.append(0x7f)
    ret.append(ord('E'))
    ret.append(ord('L'))
    ret.append(ord('F'))

    ret += b'\x02' if is_64b else b'\x01'
    ret += b'\x02' if info_proc.attributes['ENDIAN'].value == "big" else b'\x01'
    ret += b'\x01'#on met version 1 tt le temps pcq de tte facon ca ne change rien
    ret += b'\0'#ABI byte qu'on met a 0
    ret += b"\0\0\0\0\0\0\0\0"#on complete
    return ret

def ei_type(info_proc)->bytes :
    return b"\x03\0"

def ei_machine(info_proc)->bytes :
    proc: str = info_proc.attributes['NAME'].value
    if proc == "x86" :
        return b"\x3e\0"

    elif proc == "68000" or proc == "MC68020" or proc == "MC68030":
        return b"\x04\0"

    elif proc == "Coldfire" :
        return b"\x34\0"

    elif proc == "8051" or proc == "mx51" :
        return b"\x5a\0"

    elif proc == "AARCH64" :
        return b"\xb7\0"

    elif proc == "ARM" or proc == "Cortex" :
        return b"\x28\0"

    elif proc == "DATA" :
        return b"\xa0\0"

    elif proc == "HC05" or proc == "M68HC05TB" :
        return b"\x48\0"

    elif proc == "HC08" or proc == "M68HC908QY4" :
        return b"\x9f\0"

    elif proc == "MIPS" or proc == "R6" :
        return b"\x08\0"

    elif proc == "64-32addr" or proc == "64-32addr-R6" :
        return "\x33\0"

    #elif

    elif proc == "Z80" or proc == "Z8401x" or proc == "Z180" or proc == "Z182":
        return b"\xdc\0"

    elif proc == "tricore" :
        return b"\x44\0"

    return b"\x3e\0"#on met cette valeur pour ce pc

def ei_machine_and_entrypoint_64(info_proc)->bytearray :
    """
    ecrit la deuxieme ligne du elf
    """
    ret = bytearray()
    ret += ei_type(info_proc)
    ret += ei_machine(info_proc)
    ret += b"\x01\0\0\0"#la version
    #ret += ei_entrypoint(header_type.entrypoint)#on peux revoir apres
    ret += b"\0\0\0\0\0\0\0\0"
    return ret

def third_line_64()->bytearray :
    e_phoff:bytes      = b"\x40\0\0\0\0\0\0\0"#la section table header offset
    e_shoff: bytes     = b"\0\0\0\0\0\0\0\0"#on sait pas pour l'instant mais on met qd meme a 0
    e_flag: bytes      = b"\0\0\0\0"
    e_phsize: bytes    = b"\x40\0"
    e_phentsize: bytes = b"\x38\0"#ca depend si on est en 32 ou 64 bits mais a voir
    e_phenum: bytes    = b"\0\0"#on met a zero on vera apres
    e_shentsize: bytes = b"\x40\0"
    e_shnum: bytes     = b"\0\0"#nio met a 0 aussi on vera apres
    e_shstrndx: bytes  = b"\0\0"
    return bytearray(e_phoff + e_shoff + e_flag + e_phsize + e_phentsize + e_phenum + e_shentsize + e_shnum + e_shstrndx)

def ei_machine_and_entrypoint_32(info_proc)->str :
    """
    ecrit la deuxieme ligne du elf
    """
    ret = bytearray()
    ret += ei_type(info_proc)
    ret += ei_machine(info_proc)
    ret += b"\x01\x00\x00\x00"#la version
    ret += b"\0\0\0\0"
    return ret

def third_line_32()->bytearray :
    e_phoff: bytes     = b"\x34\0\0\0"#le program table header offset
    e_shoff: bytes     = b"\0\0\0\0"#on sait pas pour l'instant mais on met qd meme a 0
    e_flag: bytes      = b"\0\0\0\0"
    e_ehsize: bytes    = b"\x34\0"
    e_phentsize: bytes = b"\x20\0"
    e_phenum: bytes    = b"\0\0"#on met a zero on vera apres
    e_shentsize: bytes = b"\x28\0"
    e_shnum: bytes     = b"\0\0"#nio met a 0 aussi on vera apres
    e_shstrndx: bytes  = b"\0\0"
    return bytearray(e_phoff + e_shoff + e_flag + e_ehsize + e_phentsize + e_phenum + e_shentsize + e_shnum + e_shstrndx)

def gen_header_elf(file, proc_info, is_64b: bool) :
    """
    genere le header du elf
    """
    ei_ident_bytes: bytearray = ei_ident(proc_info, is_64b)
    file.write(ei_ident_bytes)

    if is_64b :
        ei_sncd_line: bytearray = ei_machine_and_entrypoint_64(proc_info)
        file.write(ei_sncd_line)

        st: bytearray = third_line_64()
        file.write(st)
    else :
        ei_sncd_line: bytearray = ei_machine_and_entrypoint_32(proc_info)
        file.write(ei_sncd_line)

        st: bytearray = third_line_32()
        file.write(st)
