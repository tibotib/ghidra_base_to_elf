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
    #on a pas besoin de mettre de flag ALLOC pour les sections ni R pour les segments (ils sont mis par defaut)
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
        if info.attributes['NAME'].value == section_name :
            perm: str = info.attributes['PERMISSIONS'].value
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
    for i in range(0, len(sections_infos)) :
        if  sections_infos[i].attributes['NAME'].value == name_section :
            tmp_length: int = int(sections_infos[i].attributes['LENGTH'].value, 16)
            if i + 1 != len(sections_infos) and sections_infos[i + 1].attributes['NAME'].value == name_section :
                tmp_length += int(sections_infos[i + 1].attributes['LENGTH'].value, 16)

            return [tmp_length, int(sections_infos[i].attributes['START_ADDR'].value, 16)]
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

def name_symbol(nm: list)-> str :
    for i in range(0, len(nm)) :
        if not(nm[i].isalpha()) and not(nm[i].isnumeric()):
            nm[i] = '_'
    return ''.join(nm)
