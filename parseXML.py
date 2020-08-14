from xml.dom import minidom

class XmlParser :

    def __init__(self, path_xml: str) :
        """
        on parcour une seule fois le xml et apres on utilise get_element pour trouver un element
        """
        self.xmldoc = minidom.parse(path_xml)


    def get_element(self, element:str) :
        """
        renvoi les elements portant le nom de element
        """
        return self.xmldoc.getElementsByTagName(element)


    def get_bytes_in_file(self, file_byte, from_offset: int, lenght: int)->bytes :
        """
        retourne une suite de bits ds le fichier file_byte depuis l'address from_offset et de longueur length
        """
        file_byte.seek(from_offset)
        return file_byte.read(lenght)


    def entry_point(self, elf_exe)->int :
        """
        retourne l'entry point du programme
        """
        entry_point = self.get_element('PROGRAM_ENTRY_POINT')
        return int(entry_point[0].attributes['ADDRESS'].value, 16)


    def is_elf(self)->bool :
        """
        return true if the file is an elf
        """
        return get_element('PROGRAM')[0].attributes['EXE_FORMAT'].value == "Executable and Linking Format (ELF)"


    def is_64(self, proc_info)->bool :
        """
        true si la machine est une 64 bits sinon false
        """
        language: str = proc_info.attributes['LANGUAGE_PROVIDER'].value
        size: int = get_size_from_language(language)
        return size == 64


    def get_executable_path(self, path_xml, infos_content)->str :
        """
        retourne le path de l'executable
        """
        return get_directory_path(path_xml) + infos_content[0].attributes['FILE_NAME'].value


    def get_sections_content(self, path_xml)->tuple :
        """
        retourne un tuple( dict{section_name: str : content_bytes: bytes}, infos_all_sections: list)
        """
        all_sections  = self.get_element('MEMORY_SECTION') #infos sur la section
        infos_content = self.get_element('MEMORY_CONTENTS')

        path_file_byte: str = self.get_executable_path(path_xml, infos_content)
        file_byte = open(path_file_byte, "rb")

        section_content: dict = {}#on associe le nom de la section avec son contenu(bytes)
        compt_sec: int = 0

        for i in range(0, len(all_sections)) :
            content: bytes
            if all_sections[i].hasChildNodes() :#ca veut dire que la section n'est pas vide
                content = self.get_bytes_in_file(file_byte, int(infos_content[compt_sec].attributes['FILE_OFFSET'].value, 16), int(all_sections[i].attributes['LENGTH'].value, 16))
                compt_sec += 1

            else :#si elle est vide alors on met la rempli de 0
                content: bytes = bytes(int(all_sections[i].attributes['LENGTH'].value, 16))

            section_content.update( {all_sections[i].attributes['NAME'].value : content} )

        file_byte.close()
        return section_content, all_sections


    def get_functions(self, path:str)->list :
        """
        retourne une list [fonctions, symbol, fonction librairies]
        """
        item_list: list = []
        item_list.append(self.get_element('FUNCTION'))
        item_list.append(self.get_element('SYMBOL'))
        item_list.append(self.get_element('EXT_LIBRARY_REFERENCE'))

        ret:list = [{}, {}, {}]
        for i in range(0, 3) :#ds chaque dict on associe le nom du symbol avec son address virtuelle
            for s in item_list[i]:
                if i == 0 :
                    ret[i].update( {s.attributes['NAME'].value : int(s.attributes['ENTRY_POINT'].value, 16) } )
                elif i == 1 :
                    ret[i].update( {s.attributes['NAME'].value : int(s.attributes['ADDRESS'].value, 16) } )
                else :
                    ret[i].update( {str(s.attributes['LIB_LABEL'].value)  : int(s.attributes['ADDRESS'].value, 16)} )
#str(s.attributes['LIB_PROG_NAME'].value) +
        return ret


    def get_processor(self) :
        return self.get_element('PROCESSOR')[0]

    def get_file_offset(self, name: str)->int  :
        all_sections  = self.get_element('MEMORY_SECTION') #infos sur la section
        infos_content = self.get_element('MEMORY_CONTENTS')

        for i in range(0, len(all_sections)) :
            if all_sections[i].hasChildNodes() and all_sections[i].attributes['NAME'].value == name :#ca veut dire que la section n'est pas vide
                return int(infos_content[i].attributes['FILE_OFFSET'].value, 16)
        return 0x0


def get_size_from_language(language: str)->int :
    """
    retourne le nbe de bits avec lesquelles la machine est codée (32 ou 64)
    """
    nbe_occ: int = 0

    for char in language :
        if char == ':' :
            nbe_occ += 1
            continue
        if nbe_occ == 2 :
            if char == '3' :
                return 32
            return 64
    return -1


def get_directory_path(path_xml: str)->str :
    """
    pour obtenir le repertoire ou se situe le .bytes
    """
    path_copy = list(path_xml)
    i = len(path_copy) - 1

    while i != -1 :
        if path_copy[i] == '/' or path_copy[i] == '\x5c' :#\x5c = \
            break
        del path_copy[i]
        i -= 1

    return ''.join(path_copy)
