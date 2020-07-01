#les fonctions utiles pour geerer l'en-tete
import lief

def get_ei_class(size)->str :
    if size == 64 :
        return '\x02'
    elif size == 32 :
        return '\x01'
    return '\x00'


def remove_beg(st:str)->list :
    """
    enleve les caracteres
    """
    ls:list = list(st)
    len_str:int = len(st)
    if len(ls) % 2 != 0 :
        ls.remove(ls[1])
    else:
        ls.remove(ls[0])
        ls.remove(ls[0])
    return ls


def rev(st:list)->list :
    """
    retourne une list de caractere en hexa passee en argument
    """
    ret:list = st.copy()
    for i in range(0, len(st), 2) :
        ret[i] = st[len(st) - i - 2]
        ret[i + 1] = st[len(st) - i - 1]
    return ret


def get_int_list(st:list)->list :
    """
    pour obtenir une list de caractere hexa genre 5f en sa valeur int et ca sur tte la list
    """
    ret:list = []
    for i in range(0, len(st), 2) :
        tmp:int = int(st[i], base = 16)  * 16 + int(st[i + 1], base = 16)
        ret.append(tmp)
    return ret


def address(entry:int)->list :#retourne le int en hex
    entry_str:str = hex(entry)
    new_str:list = remove_beg(entry_str)#nouveau str sans le 0x

#    ret:list = ['4', '5', '3', '0', '1', '0']
    ls_rev:list = rev(new_str)#on le retourne
    addr:list = get_int_list(ls_rev)
    return addr

def complete(st:str, ln:int = 8):
    """
    complete st avec des 0 pour qu'il arrive a une len de ln en byte
    """
    ret:str = st
    for i in range(0, ln - len(st)):
        ret += '\x00'
    return ret

def ei_entrypoint(entrypoint:int, nbe_byt:int)->str :

    ls:list = address(entrypoint)
    ret:str = ""
    i:int = 0
    for i in range(0, len(ls)) :
        ret += chr(ls[i])

    ret = complete(ret, nbe_byt)
    return ret

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
    elif proc == "68000" :
        return b"\x04\0"
#    elif proc == "6805" :
#        return
    elif proc == "Z80" or proc == "Z8401x" or proc == "Z180" or proc == "Z182":
        return b"\xdc\0"
    elif proc == "tricore" :
        return b"\x44\0"
#        elif proc == ""
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
    e_phoff:bytes      = "\x40\0\0\0\0\0\0\0"#le section table header offset
    e_shoff: bytes     = "\x78\0\0\0\0\0\0\0"#on sait pas pour l'instant mais on met qd meme a 0
    e_flag: bytes      = "\0\0\0\0"
    e_phsize: bytes    = "\x40\0"
    e_phentsize: bytes = "\x38\0"#ca depend si on est en 32 ou 64 bits mais a voir
    e_phenum: bytes    = "\0\0"#on met a zero on vera apres
    e_shentsize: bytes = "\x40\0"
    e_shnum: bytes     = "\0\0"#nio met a 0 aussi on vera apres
    e_shstrndx: bytes  = "\0\0"
    return bytearray(e_phoff + e_shoff + e_flag + e_ehsize + e_phentsize + e_phenum + e_shentsize + e_shnum + e_shstrndx)

def ei_machine_and_entrypoint_32(info_proc)->str :
    """
    ecrit la deuxieme ligne du elf
    """
    ret = bytearray()
    ret += ei_type(info_proc)
    ret += ei_machine(info_proc)
    ret += b"\x01\x00\x00\x00"#la version
    #ret += ei_entrypoint(cuProg., 4)
#    ret += b"\xa0\x12\x40\x00"
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
