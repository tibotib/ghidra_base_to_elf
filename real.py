import lief
import sys
import os
from os.path import join, getsize

from header import gen_header_elf, address
from phdr import gen_phdr
from parseXML import parseXML, get_functions, get_sections_content, set_xmldoc, is_64, is_elf, get_executable_path


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

def remove_all_flags(seg: lief.ELF.Segment) :
    for fl in [lief.ELF.SEGMENT_FLAGS.R, lief.ELF.SEGMENT_FLAGS.W, lief.ELF.SEGMENT_FLAGS.X] :
        if seg.has(fl) :
            seg.remove(fl)

def transfo_perm(permission: str, seg: lief.ELF.Segment) :
    """
    on transforme les permissions du fichier xml pour les mettre assigner au segment
    """
    remove_all_flags(seg)
    if permission == "r" :
        seg.add(lief.ELF.SEGMENT_FLAGS.R)
    elif permission == "w" :
        seg.add(lief.ELF.SEGMENT_FLAGS.W)
    elif permission == "x" :
        seg.add(lief.ELF.SEGMENT_FLAGS.X)
    elif permission == "rw" :
        seg.add(lief.ELF.SEGMENT_FLAGS.R)
        seg.add(lief.ELF.SEGMENT_FLAGS.W)
    elif permission == "rx" :
        seg.add(lief.ELF.SEGMENT_FLAGS.R)
        seg.add(lief.ELF.SEGMENT_FLAGS.X)
    elif permission == "wx" :
        seg.add(lief.ELF.SEGMENT_FLAGS.W)
        seg.add(lief.ELF.SEGMENT_FLAGS.X)
    elif permission == "rwx" :
        seg.add(lief.ELF.SEGMENT_FLAGS.R)
        seg.add(lief.ELF.SEGMENT_FLAGS.W)
        seg.add(lief.ELF.SEGMENT_FLAGS.X)

def gen_permissions(section_name: str, sections_infos: tuple, seg: lief.ELF.Segment) :
    info_sec = sections_infos[1]
    for info in info_sec :
        if info.attributes['NAME'].value == section_name :
            perm: str = info.attributes['PERMISSIONS'].value
            print("perm = ", perm)
            transfo_perm(perm, seg)

def gen_shstrtab(elf_exe: lief.ELF.Binary, sh_content: list, sections_infos: tuple) :
    """
    on genre shstrstab et on finalise le header + on rearrange a les segments
    """
    shstrtab_section = lief.ELF.Section(".shstrtab")
    shstrtab_section.clear()
    shstrtab_section.content = string_list_to_byte(sh_content)
    shstrtab_section.type = lief.ELF.SECTION_TYPES.STRTAB

#ici on peut reparcourir les sections avec leur segment associe (si il y en a qu'un par section)

#    for i in range(0, len(elf_exe.sections)) :

#        seg = elf_exe.segments[i + 1]#pcq il y a le phdr au tout debut
#        sec = elf_exe.sections[i]

#        virtSize_virtAddr: tuple = find_start(sec.name, sections_infos)
#        if virtSize_virtAddr != -1 :
#            print("name section = ", sec.name)
#            print("addr = ",  hex(virtSize_virtAddr[1]))
#            seg.virtual_address = virtSize_virtAddr[1]
#            seg.virtual_size = virtSize_virtAddr[0]
#            seg.physical_size = virtSize_virtAddr[0]

#        gen_permissions(sec.name, sections_infos, seg)

    shstrtab_section.entry_size = elf_exe.header.numberof_sections + 1
    shstrtab_section = elf_exe.add(shstrtab_section)
    elf_exe.header.section_name_table_idx = elf_exe.header.numberof_sections - 2
    elf_exe.header.section_header_offset = shstrtab_section.offset + shstrtab_section.original_size
    elf_exe.header.entrypoint = 0x4012a0#faut trouver le point d'entre ds le xml


def find_start(name_section: str, sections_infos)->list :
    """
    retourne une list[virtual_size, virtual_offset] pour une section donnee
    """
    all_infos = sections_infos[1]
    for infos_sec in all_infos :
        if infos_sec.attributes['NAME'].value == name_section :
            return [int(infos_sec.attributes['LENGTH'].value, 16), int(infos_sec.attributes['START_ADDR'].value, 16) - 0x3000]
    return -1


def gen_sections(section_infos: tuple, elf_exe: lief.ELF.Binary)->list :
    """
    genere les sections et les segments par la meme occasion
    Retourne la list de tous les noms de sections
    """
    content_sections: dict = section_infos[0]

    name_section_shstrtab: list = []
    for name_section in content_sections :
        if name_section == '.shstrtab' or name_section == '.symtab' or name_section == '.symstr' or name_section == 'Headers':
            continue

        name_section_shstrtab.append(name_section)

        newSec              = lief.ELF.Section(name_section)
        newSec.type         = lief.ELF.SECTION_TYPES.PROGBITS
        newSec.content      = list(content_sections[name_section])
        #if newSec.name == ".text" :
        newSec.add(lief.ELF.SECTION_FLAGS.ALLOC)
        newSec.add(lief.ELF.SECTION_FLAGS.WRITE)
#        newSec.

        of: tuple =  find_start(newSec.name, section_infos)
        if of != -1 :
            print("of0 = ", of[0])
            print("sz = ", newSec.size)
            newSec.alignment = newSec.size
            newSec.size = of[0]
            newSec.offset = of[1]
            newSec.virtual_address = of[1]

        newSec = elf_exe.add(newSec, loaded = False)#en mettant loaded a False on ne creer pas de segment

    #gen_segments(elf_exe)
    name_section_shstrtab.append(".symtab")
    name_section_shstrtab.append(".symstr")
    return name_section_shstrtab

def gen_segments(elf_exe: lief.ELF.Binary) :
    #pour l'instant j'ai essayer de creer un segment par section pour apres ameliorer
    for section in  elf_exe.sections :
        seg = lief.ELF.Segment()
        seg.type = lief.ELF.SEGMENT_TYPES.LOAD
        print("file_offset = ", hex(section.offset))
        print("size = ", hex(section.size))
        seg.file_offset = section.offset
        seg.physical_address = section.file_offset
        seg.virtual_address = section.virtual_address
        seg.virtual_size = section.size
        seg.physical_size = section.size
        seg.alignment = section.size
        elf_exe.add(seg, section.size)

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

#on traite differamment les sections les symbols et les librairies
    #ca c'est les fonctions
    for sym_ghidra in all_func[0] :
    #    tp = sym_ghidra.getSymbolType()
        strtab_list.append("elf_symbol_" + sym_ghidra)
        sym_lief = lief.ELF.Symbol()
        sym_lief.name = "elf_symbol_" + sym_ghidra
#la faut s'addapter et pas tt le temps mettre la meme chose
        sym_lief.type = lief.ELF.SYMBOL_TYPES.FUNC
        sym_lief.binding = lief.ELF.SYMBOL_BINDINGS.GLOBAL
        sym_lief.value = all_func[0][sym_ghidra] - 0x3000
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
        sym_lief.value = all_func[1][sym_ghidra] - 0x3000
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
        sym_lief.value = all_func[2][sym_ghidra] - 0x3000
#        sym_lief.imported = True
#        sym_lief.size = 0
    #    if sym_ghidra.isDynamic() :
    #        sym_lief = elf_exe.add_dynamic_symbol(sym_lief)
    #    else :
        sym_lief = elf_exe.add_static_symbol(sym_lief)
        #print(sym_lief)

    symstr_section.content = string_list_to_byte(strtab_list)
    symtab_section = elf_exe.add(symtab_section)
    symstr_section = elf_exe.add(symstr_section)




def write_in_file(elf_exe: lief.ELF.Binary, path: str) :
    """
    Ecrit l'executable(elf_exe) ds un fichier(d'addresse path)
    """
    builder = lief.ELF.Builder(elf_exe)
    builder.build()
    builder.write(path)

def gen_elf_from_elf(elf_exe: lief.ELF.Binary, path_xml: str, path_elf: str) :
    """
    on genere un elf a partir d'un executable elf
    On a dc juste besoin de revoir la symtab
    """
    if elf_exe.has(lief.ELF.SECTION_TYPES.SYMTAB) :
        elf_exe.remove_section(".symtab")
        #elf_exe.remove_section(".symstr")

    gen_symtab(elf_exe, path_xml)
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
    #gen_segments(elf_exe, sections_infos)
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
