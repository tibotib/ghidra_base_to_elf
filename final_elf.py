import lief
from header import gen_header_elf
from util import string_list_to_byte, gen_permissions, find_start, write_in_file, name_symbol
from parseXML import XmlParser



class FinalElf :
    def __init__(self, path_elf: str, path_xml: str) :
        self.path_elf:  str                = path_elf
        self.path_xml:  str                = path_xml
        self.xmlparser: XmlParser          = XmlParser(self.path_xml)


    def gen_header(self) :
        """
        on ecrit le header dans file et apres on parse ce fichier
        """
        proc_info    = self.xmlparser.get_processor()
        is_64b: bool = self.xmlparser.is_64(proc_info)

        file = open(self.path_elf, "wb")
        gen_header_elf(file, proc_info, is_64b)
        file.close()


    def parse_header(self) :
        """
        on parse le header creer avec lief pr pouvoir construire le fichier elf
        """
        self.elf_exe = lief.parse(self.path_elf)


    def gen_elf(self) :
        """
        apres avoir initialise l'objet on peut creer un elf
        """
        sections_infos: tuple   = self.xmlparser.get_sections_content(self.path_xml)
        name_sections: list     = self.gen_sections(sections_infos[0])
        #name_sections permet de creer .shstrtab a la fin(la section qui contient le nom de toutes les sections)
        self.gen_symtab()
        self.gen_shstrtab(sections_infos[1], name_sections)


        self.write_and_rearrange()
    #    self.write_in_file()

    def add_null_section(self) :
        """
        on ajoute une section NULL avant d'ajouter toutes les sections
        """
        new_section           = lief.ELF.Section()
        new_section.type      = lief.ELF.SECTION_TYPES.NULL
        new_section.size      = 0x0
        new_section.offset    = 0x0
        new_section.content   = [0]
        new_section.alignment = 0

        new_section.add(lief.ELF.SECTION_FLAGS.NONE)
        new_section = self.elf_exe.add(new_section, False)


    def gen_sections(self, content_sections: dict)->list :
        """
        genere les sections et les segments par la meme occasion
        Retourne la list de tous les noms de sections
        """
        name_section_shstrtab: list = []
        self.add_null_section()

        for name_section in content_sections :
            print("name_section = ", name_section)
            if name_section == '.shstrtab' or name_section == '.symtab' or name_section == '.symstr' or name_section == 'Headers' or name_section == '_elfSectionHeaders':
                continue

            name_section_shstrtab.append(name_section)

            newSec              = lief.ELF.Section(name_section)
            newSec.type         = lief.ELF.SECTION_TYPES.PROGBITS
            newSec.content      = list(content_sections[name_section])

            newSec.add(lief.ELF.SECTION_FLAGS.ALLOC)
            newSec = self.elf_exe.add(newSec, loaded = True)#en mettant loaded a False on ne cree pas de segment

        name_section_shstrtab.append(".symtab")
        name_section_shstrtab.append(".symstr")
        return name_section_shstrtab


    def add_null_symbol(self) :
        """
        on ajoute un symbol null au debut de la symtab
        """
        null_symbol         = lief.ELF.Symbol()
        null_symbol.type    = lief.ELF.SYMBOL_TYPES.NOTYPE
        null_symbol.binding = lief.ELF.SYMBOL_BINDINGS.WEAK
        null_symbol.value   = 0x0
        null_symbol.size    = 0x0
        self.elf_exe.add_static_symbol(null_symbol)


    def gen_symtab(self) :
        """
        on genere une table des symbols
        """
        proc_info    = self.xmlparser.get_processor()
        is_64b: bool = self.xmlparser.is_64(proc_info)

        all_func: list             = self.xmlparser.get_functions(self.path_xml)

        symtab_section             = lief.ELF.Section()
        symtab_section.name        = ".symtab"
        symtab_section.type        = lief.ELF.SECTION_TYPES.SYMTAB
        symtab_section.offset      = 0x0
        symtab_section.link        = len(self.elf_exe.sections) + 1

        symstr_section            = lief.ELF.Section()
        symstr_section.name       = ".symstr"
        symstr_section.type       = lief.ELF.SECTION_TYPES.STRTAB
        symstr_section.alignment  = 1

        strtab_list = []#on garde le nom de toutes les symbols
        self.add_null_symbol()

        #ca c'est les fonctions
        for sym_ghidra in all_func[0] :
            tmp_name: str = name_symbol(list("elf_symbol_" + sym_ghidra))
            strtab_list.append(tmp_name)

            symtab_section.content     += [0] * len(tmp_name)
            sym_lief                    = lief.ELF.Symbol()
            sym_lief.name               = tmp_name
            sym_lief.type               = lief.ELF.SYMBOL_TYPES.FUNC
            sym_lief.binding            = lief.ELF.SYMBOL_BINDINGS.GLOBAL
            sym_lief.value              = all_func[0][sym_ghidra]
            sym_lief.size               = 0
            sym_lief                    = self.elf_exe.add_static_symbol(sym_lief)
            print(sym_lief)

        #mtn on fait les symbols
        for sym_ghidra in all_func[1] :
            tmp_name: str = name_symbol(list("elf_symbol_" + sym_ghidra))
            strtab_list.append(tmp_name)

            symtab_section.content     += [0] * len(tmp_name)
            sym_lief                    = lief.ELF.Symbol()
            sym_lief.name               = tmp_name
            sym_lief.type               = lief.ELF.SYMBOL_TYPES.FUNC
            sym_lief.binding            = lief.ELF.SYMBOL_BINDINGS.GLOBAL
            sym_lief.value              = all_func[1][sym_ghidra]
            sym_lief                    = self.elf_exe.add_static_symbol(sym_lief)
            sym_lief.size               = 0
            print(sym_lief)

    #et la c'est les liens vers les librairies
        for sym_ghidra in all_func[2] :
            tmp_name: str     = name_symbol(list("elf_symbol_" + sym_ghidra))
            strtab_list.append(tmp_name)

            symtab_section.content     += [0] * len(tmp_name)
            sym_lief                    = lief.ELF.Symbol()
            sym_lief.name               = tmp_name
            sym_lief.type               = lief.ELF.SYMBOL_TYPES.FUNC
            sym_lief.binding            = lief.ELF.SYMBOL_BINDINGS.GLOBAL
            sym_lief.value              = all_func[2][sym_ghidra]
            sym_lief.size               = 0
            sym_lief.imported           = True
            sym_lief                    = self.elf_exe.add_static_symbol(sym_lief)
            print(sym_lief)

        if is_64b :
            symtab_section.entry_size = 24
        else:
            symtab_section.entry_size = 16
        symtab_section            = self.elf_exe.add(symtab_section, False)
        symstr_section            = self.elf_exe.add(symstr_section, False)

    def gen_shstrtab(self, sections_infos: list, sh_content: list) :
        """
        on genere shstrstab et on finalise le header + on rearrange a les segments
        """
        sh_content.append(".shstrtab")
        shstrtab_section                           = lief.ELF.Section(".shstrtab")
    #    shstrtab_section.content                   =
        shstrtab_section.type                      = lief.ELF.SECTION_TYPES.STRTAB

        self.set_segments(sections_infos)#en meme temps on set les permissions pr les segments
        #split_segments(elf_exe)
        shstrtab_section.entry_size                 = self.elf_exe.header.numberof_sections + 1
    #    shstrtab_section.alignment                  = 0x1
        shstrtab_section                            = self.elf_exe.add(shstrtab_section, False)

        self.elf_exe.header.section_name_table_idx = self.elf_exe.header.numberof_sections - 2
        self.elf_exe.header.entrypoint             = self.xmlparser.entry_point(self.elf_exe)
        #self.elf_exe.header.section_header_size           = 0x28

        for section in self.elf_exe.sections :
            print(section)


    def set_segments(self, sections_infos: list) :
        """
        on donne les prprietes aux segments et aux sections
        """

        for i in range(1, len(self.elf_exe.sections) - 2) :

            seg = self.elf_exe.segments[i - 1]#faire gaffe a l'indice a savoir qu'il y a le segment phdr au debut dc des fois on doit faire i + 1
            sec = self.elf_exe.sections[i]

            gen_permissions(sec, sections_infos, seg)

            virtSize_virtAddr: tuple = find_start(sec.name, sections_infos)
    #        file_offset:       int   = self.xmlparser.get_file_offset(sec.name)

            if virtSize_virtAddr != -1 :
                print("name section = ", sec.name)
                print("addr = ",  hex(sec.offset))

                seg.file_offset  = sec.file_offset

                sec.virtual_address  = virtSize_virtAddr[1]
                seg.virtual_address  = virtSize_virtAddr[1]
                seg.physical_address = virtSize_virtAddr[1]

                sec.size             = virtSize_virtAddr[0]
                seg.virtual_size     = virtSize_virtAddr[0]
                seg.physical_size    = virtSize_virtAddr[0]

            #    sec.alignment        = 8
            #    seg.alignment        = 8


    def write_and_rearrange(self) :
        """
        on ajoute des petites modifs pcq sinon on a 2 symstr section mais il faudrait trouver une autre solution
        """
        self.write_in_file()
        exe = lief.parse(self.path_elf)

        rem_shstrtab: lief.ELF.Section
        for section in exe.sections :
            if section.name == ".shstrtab" :
                rem_shstrtab = section

            elif section.name == ".symstr" and section.alignment == 0x1000 :
                section.name = ".shstrtab"

        exe.remove(rem_shstrtab)
        write_in_file(exe, self.path_elf)

    def write_in_file(self) :
        """
        Ecrit l'executable(elf_exe) ds un fichier(d'addresse path)
        """
        builder = lief.ELF.Builder(self.elf_exe)
        builder.build()
        builder.write(self.path_elf)
