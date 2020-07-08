import lief

def string_to_list(string: str)->list :
    """
    retourne une list d'entiers correspondant a chacune des lettres du str
    """
    ret = []
    for letter in string :
        ret.append(ord(letter))
    return ret

def string_list_to_byte(ls: list) :
    """
    prend une list de string et renvoie une list de int
    """
    ret = []
    for string in ls :
        for ele in string_to_list(string) :
            ret.append(ele)
    return ret

def get_abstract_binary(binary: lief.ELF.Binary):
    """
    permet de manipuler un const lief.ELF.Binary
    """
    return super(binary.__class__, binary)

def transfo_perm(permission: str, seg: lief.ELF.Segment, section: lief.ELF.Section) :
    """
    on transforme les permissions du fichier xml pour les mettre assigner au segment
    """
    #on a pas besoin de mattre de flag ALLOC pour les sections ni R pour les segments (ils sont mis par defaut)
    if permission == "w" :
        seg.add(lief.ELF.SEGMENT_FLAGS.W)
        section.add(lief.ELF.SECTION_FLAGS.WRITE)

    elif permission == "x" :
        seg.add(lief.ELF.SEGMENT_FLAGS.X)
        section.add(lief.ELF.SECTION_FLAGS.EXECINSTR)

    elif permission == "rw" :
        seg.add(lief.ELF.SEGMENT_FLAGS.W)
        section.add(lief.ELF.SECTION_FLAGS.WRITE)

    elif permission == "rx" :
        seg.add(lief.ELF.SEGMENT_FLAGS.X)
        section.add(lief.ELF.SECTION_FLAGS.EXECINSTR)

    elif permission == "wx" :
        seg.add(lief.ELF.SEGMENT_FLAGS.W)
        section.add(lief.ELF.SECTION_FLAGS.WRITE)
        seg.add(lief.ELF.SEGMENT_FLAGS.X)
        section.add(lief.ELF.SECTION_FLAGS.EXECINSTR)

    elif permission == "rwx" :
        seg.add(lief.ELF.SEGMENT_FLAGS.W)
        section.add(lief.ELF.SECTION_FLAGS.WRITE)
        seg.add(lief.ELF.SEGMENT_FLAGS.X)
        section.add(lief.ELF.SECTION_FLAGS.EXECINSTR)

def gen_permissions(section: lief.ELF.Section, info_sec: list, seg: lief.ELF.Segment) :
    """
    on genere les permissions pour le segment et la section
    """
    section_name: str = section.name
    for info in info_sec :
        if get_attributes(info, 'NAME') == section_name :
            perm: str = get_attributes(info, 'PERMISSIONS')
            print("perm = ", perm)
            transfo_perm(perm, seg, section)

def split_segments(elf_exe: lief.ELF.Binary) :
    """
    peret de regrouper les segments entre eux si ils ont les memes caracteristiques mais a revoir pour l'instant
    """
    for i in range(0, len(elf_exe.segments)) :
        segment = elf_exe.segments[i]
        if segment.type != lief.ELF.SEGMENT_TYPES.LOAD :
            continue
        tmp = i
        perm_seg: list = segment.flags
        if tmp + 1 != len(elf_exe.segments) :#si on est pas a la fin
            tmp += 1
            if elf_exe.segments[tmp].flags == perm_seg :
                if (elf_exe.segments[i].virtual_address + elf_exe.segments[tmp].virtual_size) == elf_exe.segments[tmp].virtual_address :
                    segment.virtual_size += elf_exe.segments[tmp].virtual_size
                    elf_exe.segments[tmp].type = lief.ELF.SEGMENT_TYPES.NULL
                    elf_exe.segments[tmp].virtual_address = 0x0
                    elf_exe.segments[tmp].virtual_size = 0x0

def find_start(name_section: str, sections_infos: list)->list :
    """
    retourne une list[virtual_size, virtual_offset] pour une section donnee
    """
    for infos_sec in sections_infos :
        if get_attributes(infos_sec, 'NAME') == name_section :
            return [get_attributes_to_int(infos_sec, 'LENGTH', 16), get_attributes_to_int(infos_sec, 'START_ADDR', 16)]
    return -1

def get_attributes(xml_element, name_attribute: str)->str :
    if xml_element.hasAttribute(name_attribute) :
        return xml_element.attributes[name_attribute].value
    return "Attribute non trouve"

def get_attributes_to_int(xml_element, name_attribute, base)->int :
    attr = get_attributes(xml_element, name_attribute)
    if attr == "Attribute non trouve" :
        return 0x0

    ret: int = 0x0
    try :
        ret = int(attr, base)
    except ValueError:
        return 0x0
    return ret


def write_in_file(elf_exe: lief.ELF.Binary, path: str) :
    """
    Ecrit l'executable(elf_exe) ds un fichier(d'addresse path)
    """
    builder = lief.ELF.Builder(elf_exe)
    builder.build()
    builder.write(path)
