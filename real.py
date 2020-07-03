import lief
import sys
import os
from os.path import join, getsize

from header import gen_header_elf
from phdr import gen_phdr, load_phdr
from parseXML import parseXML, get_functions, get_sections_content, set_xmldoc, is_64, is_elf, get_executable_path, entry_point


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

def gen_permissions(section: lief.ELF.Section, sections_infos: tuple, seg: lief.ELF.Segment) :
    """
    on genere les permissions pour le segment et la section
    """
    section_name: str = section.name
    info_sec = sections_infos[1]
    for info in info_sec :
        if info.attributes['NAME'].value == section_name :
            perm: str = info.attributes['PERMISSIONS'].value
            print("perm = ", perm)
            transfo_perm(perm, seg, section)

def split_segments(elf_exe: lief.ELF.Binary) :
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

def set_segments(elf_exe: lief.ELF.Binary, sections_infos: tuple) :
    """
    on donne les prprietes aux segments et aux sections
    """

    for i in range(1, len(elf_exe.sections) - 2) :

        seg = elf_exe.segments[i]#faire gaffe a l'indice a savoir qu'il y a le segment phdr au debut dc des fois on doit faire i + 1
        sec = elf_exe.sections[i]

        gen_permissions(sec, sections_infos, seg)

        virtSize_virtAddr: tuple = find_start(sec.name, sections_infos)
        if virtSize_virtAddr != -1 :
            print("name section = ", sec.name)
            print("addr = ",  hex(sec.offset))
            seg.file_offset = sec.file_offset

            sec.virtual_address  = virtSize_virtAddr[1]
            seg.virtual_address  = virtSize_virtAddr[1]
            seg.physical_address = virtSize_virtAddr[1]

            sec.size             = virtSize_virtAddr[0]
            seg.virtual_size     = virtSize_virtAddr[0]
            seg.physical_size    = virtSize_virtAddr[0]

            sec.alignment        = 8
            seg.alignment        = 8

def gen_shstrtab(elf_exe: lief.ELF.Binary, sh_content: list, sections_infos: tuple) :
    """
    on genere shstrstab et on finalise le header + on rearrange a les segments
    """
    shstrtab_section = lief.ELF.Section(".shstrtab")
    shstrtab_section.clear()
    shstrtab_section.content = string_list_to_byte(sh_content)
    shstrtab_section.type = lief.ELF.SECTION_TYPES.STRTAB

    set_segments(elf_exe, sections_infos)

    for section in elf_exe.sections :
        print(section)

    #split_segments(elf_exe)
    shstrtab_section.entry_size = elf_exe.header.numberof_sections + 1
    shstrtab_section = elf_exe.add(shstrtab_section, False)
    shstrtab_section.alignment = 0x8
    elf_exe.header.section_name_table_idx = elf_exe.header.numberof_sections - 2
    elf_exe.header.section_header_offset = shstrtab_section.offset + shstrtab_section.original_size
    elf_exe.header.entrypoint = entry_point(elf_exe)#faut trouver le point d'entre ds le xml
    for section in elf_exe.sections :
        print(section)

def find_start(name_section: str, sections_infos)->list :
    """
    retourne une list[virtual_size, virtual_offset] pour une section donnee
    """
    all_infos = sections_infos[1]
    for infos_sec in all_infos :
        if infos_sec.attributes['NAME'].value == name_section :
            return [int(infos_sec.attributes['LENGTH'].value, 16), int(infos_sec.attributes['START_ADDR'].value, 16)]
    return -1


def add_null_section(elf_exe: lief.ELF.Binary) :
    """
    on ajoute une section NULL au debut
    """
    new_section = lief.ELF.Section()
    new_section.type = lief.ELF.SECTION_TYPES.NULL
    new_section.content = [0]
    new_section = elf_exe.add(new_section)


def gen_sections(sections_infos: tuple, elf_exe: lief.ELF.Binary)->list :
    """
    genere les sections et les segments par la meme occasion
    Retourne la list de tous les noms de sections
    """
    add_null_section(elf_exe)
    content_sections: dict = sections_infos[0]

    name_section_shstrtab: list = []
    for name_section in content_sections :
        if name_section == '.shstrtab' or name_section == '.symtab' or name_section == '.symstr' or name_section == 'Headers' :
            continue

        name_section_shstrtab.append(name_section)

        newSec              = lief.ELF.Section(name_section)
        newSec.type         = lief.ELF.SECTION_TYPES.PROGBITS
        newSec.content      = list(content_sections[name_section])

        newSec.add(lief.ELF.SECTION_FLAGS.ALLOC)
        newSec = elf_exe.add(newSec, loaded = True)#en mettant loaded a False on ne creer pas de segment

    name_section_shstrtab.append(".symtab")
    name_section_shstrtab.append(".symstr")
    return name_section_shstrtab

def add_null_symbol(elf_exe: lief.ELF.Binary, strtab: list) :
    strtab.append('\0')

    null_symbol         = lief.ELF.Symbol()
    null_symbol.type    = lief.ELF.SYMBOL_TYPES.NOTYPE
    null_symbol.binding = lief.ELF.SYMBOL_BINDINGS.LOCAL
    null_symbol.value   = 0x0
    null_symbol.size    = 0x0
    elf_exe.add_static_symbol(null_symbol)


def gen_symtab(elf_exe: lief.ELF.Binary, path_xml: str) :
    """
    on genere la table des symbole a partir de la base ghidra xml
    """
    all_func:list = get_functions(path_xml)
    print(len(all_func[1]))

    symtab_section             = lief.ELF.Section()
    symtab_section.name        = ".symtab"
    symtab_section.type        = lief.ELF.SECTION_TYPES.SYMTAB
    symtab_section.entry_size  = 16
    symtab_section.alignment   = 8
    symtab_section.link        = len(elf_exe.sections) + 1
    symtab_section.content     = [0] * 16 * (len(all_func[0]) + len(all_func[1]) + len(all_func[2]))

    symstr_section            = lief.ELF.Section()
    symstr_section.name       = ".symstr"
    symstr_section.type       = lief.ELF.SECTION_TYPES.STRTAB
    symstr_section.entry_size = 16
    symstr_section.alignment  = 8

    strtab_list = []#on garde le nom de toutes les sections

    add_null_symbol(elf_exe, strtab_list)

#on traite differamment les seelf_exetions les symbols et les librairies
    #ca c'est les fonctions
    for sym_ghidra in all_func[0] :
    #    tp = sym_ghidra.getSymbolType()
        strtab_list.append("elf_symbol_" + sym_ghidra)
        sym_lief = lief.ELF.Symbol()
        sym_lief.name = "elf_symbol_" + sym_ghidra
#la faut s'addapter et pas tt le temps mettre la meme chose
        sym_lief.type = lief.ELF.SYMBOL_TYPES.FUNC
        sym_lief.binding = lief.ELF.SYMBOL_BINDINGS.GLOBAL
        sym_lief.value = all_func[0][sym_ghidra]
        sym_lief.size = 0
    #    if sym_ghidra.isDynamic() :
    #        sym_lief = elf_exe.add_dynamic_symbol(sym_lief)
    #    else :
        sym_lief = elf_exe.add_static_symbol(sym_lief)
        print(sym_lief)


    #mtn on fait les symbols
    for sym_ghidra in all_func[1] :
    #    tp = sym_ghidra.getSymbolType()
    #    strtab_list.append("elf_symbol_" + sym_ghidra.getName() + '\0')
        strtab_list.append("elf_symbol_" + sym_ghidra)
        sym_lief = lief.ELF.Symbol()
        sym_lief.name = "elf_symbol_" + sym_ghidra
#la faut s'addapter et pas tt le temps mettre la meme chose
        sym_lief.type = lief.ELF.SYMBOL_TYPES.FUNC
        sym_lief.binding = lief.ELF.SYMBOL_BINDINGS.GLOBAL
        sym_lief.value = all_func[1][sym_ghidra]
    #    if sym_ghidra.isDynamic() :
    #        sym_lief = elf_exe.add_dynamic_symbol(sym_lief)
    #    else :
        sym_lief = elf_exe.add_static_symbol(sym_lief)
        print(sym_lief)

#et la c'est les liens vers les librairies
    for sym_ghidra in all_func[2] :
    #    tp = sym_ghidra.getSymbolType()
    #    strtab_list.append("elf_symbol_" + sym_ghidra.getName() + '\0')
        strtab_list.append("elf_symbol_" + sym_ghidra)
        sym_lief = lief.ELF.Symbol()
        sym_lief.name = "elf_symbol_" + sym_ghidra
#la faut s'addapter et pas tt le temps mettre la meme chose
        sym_lief.type = lief.ELF.SYMBOL_TYPES.OBJECT
        sym_lief.binding = lief.ELF.SYMBOL_BINDINGS.GLOBAL
        sym_lief.value = all_func[2][sym_ghidra]
#        sym_lief.imported = True
#        sym_lief.size = 0
    #    if sym_ghidra.isDynamic() :
    #        sym_lief = elf_exe.add_dynamic_symbol(sym_lief)
    #    else :
        sym_lief = elf_exe.add_static_symbol(sym_lief)
        print(sym_lief)
    symstr_section.content = string_list_to_byte(strtab_list)
    symtab_section = elf_exe.add(symtab_section, False)
    symstr_section = elf_exe.add(symstr_section, False)




def write_in_file(elf_exe: lief.ELF.Binary, path: str) :
    """
    Ecrit l'executable(elf_exe) ds un fichier(d'addresse path)
    """
    builder = lief.ELF.Builder(elf_exe)
    print(2)
    builder.build()
    print(3)
    builder.write(path)

def gen_elf_from_elf(elf_exe: lief.ELF.Binary, path_xml: str, path_elf: str) :
    """
    on genere un elf a partir d'un executable elf
    On a dc juste besoin de revoir la symtab
    """
#    if elf_exe.has(lief.ELF.SECTION_TYPES.SYMTAB) :
#        elf_exe.remove_section(".symtab")
#        elf_exe.remove_section(".symtab")

#    gen_symtab(elf_exe, path_xml)
    #gen_shstrtab
    write_in_file(elf_exe, path_elf)

def gen_elf_file(elf_exe: lief.ELF.Binary, path_xml: str, path_elf: str, is_64: bool) :
    """
    genere un fichier elf a partir d'une base ghidra
    """
    gen_phdr(elf_exe, is_64)#puis on creer un phdr
    sections_infos: tuple = get_sections_content(path_xml)
    name_sections = gen_sections(sections_infos, elf_exe)#en fait lorsqu'on cree les sections les on creer aussi des segments
    #name_sections permet de creer .shstrtab a la fin(la section qui contient le nom de toutes les sections)
    gen_symtab(elf_exe, path_xml)
    gen_shstrtab(elf_exe, name_sections, sections_infos)

    for seg in elf_exe.segments :
        print(seg)
    write_in_file(elf_exe, path_elf)

def main() :
    path_elf: str                 = "/home/fouque/idaExample.elf"
    path_xml: str                 = "/home/fouque/exportGhidra/idafree70_windows.xml"
    set_xmldoc(path_xml)
    proc_info = parseXML('PROCESSOR')[0]

    if is_elf() :
        elf_exe = lief.parse(get_executable_path(path_xml))
        print(elf_exe)
        gen_elf_from_elf(elf_exe, path_xml, path_elf)
        exit()

    is_64b:bool = True if is_64(proc_info) == 64 else False#pour eviter les connexions avec le serveur ghidra
    #on ecrit le header ds file et apres on parse ce fichier
    file = open(path_elf, "wb")
    gen_header_elf(file, proc_info, is_64b)#on genere un header elf ds un fichier
    file.close()

    elf_exe = lief.parse(path_elf)#on manipule le fichier ds lequel on a mis le header que l'on a creer

    gen_elf_file(elf_exe, path_xml, path_elf, is_64b)




if __name__ == "__main__":
    main()
