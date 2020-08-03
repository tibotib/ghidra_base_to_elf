from xml.dom import minidom
from util import get_attributes_to_int, get_attributes

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
        return get_attributes_to_int(entry_point[0], 'ADDRESS', 16)


    def is_elf(self)->bool :
        """
        return true if the file is an elf
        """
        return get_attributes(self.get_element('PROGRAM')[0], 'EXE_FORMAT') == "Executable and Linking Format (ELF)"


    def is_64(self)->bool :
        """
        true si la machine est une 64 bits sinon false
        """
        language: str = self.get_element('LANGUAGE_PROVIDER')
        size: int     = get_size_from_language(language)
        return size == 64


    def get_executable_path(self, path_xml: str, infos_content: tuple)->str :
        """
        retourne le path de l'executable
        """
        attr: str = get_attributes(infos_content[0], 'FILE_NAME')
        if attr == "Attribute non trouve" :
            print("erreur ds l' ouverture du path")

        else :
            return get_directory_path(path_xml) + attr


    def get_sections_content(self, path_xml)->tuple :
        """
        retourne un tuple( dict{section_name: str : content_bytes: bytes}, infos_all_sections: list)
        """
        all_sections  = self.get_element('MEMORY_SECTION') #infos sur la section
        infos_content = self.get_element('MEMORY_CONTENTS')#infos sur les positions des bytes de la section dans le fichier

        path_file_byte: str = self.get_executable_path(path_xml, infos_content)
        file_byte           = open(path_file_byte, "rb")

        section_content: dict = {}#on associe le nom de la section avec son contenu(bytes)
        compt_sec: int = 0#compte le nbe d iterations si la section n est pas vide

        for i in range(0, len(all_sections)) :
            content: bytes
            if all_sections[i].hasChildNodes() :#ca veut dire que la section n'est pas vide
                content = self.get_bytes_in_file(file_byte, get_attributes_to_int(infos_content[compt_sec], 'FILE_OFFSET', 16), get_attributes_to_int(all_sections[i], 'LENGTH', 16))
                compt_sec += 1

            else :#si elle est vide alors on met la rempli de 0
                content: bytes = bytes(get_attributes_to_int(all_sections[i], 'LENGTH', 16))

            section_content.update( {get_attributes(all_sections[i], 'NAME') : content} )

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
                    ret[i].update( {get_attributes(s, 'NAME') : get_attributes_to_int(s, 'ENTRY_POINT', 16) } )
                elif i == 1 :
                    ret[i].update( {get_attributes(s, 'NAME') : get_attributes_to_int(s, 'ADDRESS', 16) } )
                else :
                    ret[i].update( {get_attributes(s, 'NAME') + get_attributes(s, 'LIB_LABEL')  : get_attributes_to_int(s, 'ADDRESS', 16)} )

        return ret

    def get_processor_name(self) :
        return get_attributes(self.get_element('PROCESSOR')[0], 'NAME')

    def get_processor_endian(self) :
        return get_attributes(self.get_element('PROCESSOR')[0], 'ENDIAN')


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
