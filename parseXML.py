from xml.dom import minidom

def set_xmldoc(path_xml: str) :
    """
    on parcour une seule fois le xml et apres on utilise parseXML pour trouver un element
    """
    global xmldoc
    xmldoc = minidom.parse(path_xml)

def parseXML(element:str) :
    """
    parcour un fichier xml et renvoi les elements portant le nom de element(arg2)
    """
    return xmldoc.getElementsByTagName(element)

def get_bytes_in_file(file_byte, from_offset: int, lenght: int)->bytes :
    file_byte.seek(from_offset)
    return file_byte.read(lenght)

def get_size_from_language(language: str)->int :
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
        if path_copy[i] == '/' or path_copy[i] == '\x5c' :
            break
        del path_copy[i]
        i -= 1

    return ''.join(path_copy)

def entry_point(elf_exe)->int :
    entry_point = parseXML('PROGRAM_ENTRY_POINT')
    return int(entry_point[0].attributes['ADDRESS'].value, 16)


def get_executable_path(path_xml)->str :
    infos_content = parseXML('MEMORY_CONTENTS')
    return get_directory_path(path_xml) + infos_content[0].attributes['FILE_NAME'].value


def is_elf()->bool :
    """
    return true if the file is an elf
    """
    return parseXML('PROGRAM')[0].attributes['EXE_FORMAT'].value == "Executable and Linking Format (ELF)"


def is_64(proc_info)->bool :
    """
    return true if the processor is 64 bits
    """
    language: str = proc_info.attributes['LANGUAGE_PROVIDER'].value
    size: int = get_size_from_language(language)
    return size == 64


def get_sections_content(path_xml)->tuple :
    """
    retourne un tuple(dict{section_name : content_bytes}, infos_all_sections)
    """
    all_sections = parseXML('MEMORY_SECTION')
    infos_content = parseXML('MEMORY_CONTENTS')
    path_file_byte: str = get_directory_path(path_xml) + infos_content[0].attributes['FILE_NAME'].value
    file_byte = open(path_file_byte, "rb")

    section_content: dict = {}#on associe le nom de la section avec son contenu
    compt_sec: int = 0
    for i in range(0, len(all_sections)) :
        content: bytes
        if all_sections[i].hasChildNodes() :
            print("child node OK")
            content = get_bytes_in_file(file_byte, int(infos_content[compt_sec].attributes['FILE_OFFSET'].value, 16), int(all_sections[i].attributes['LENGTH'].value, 16))
            compt_sec += 1
        else :
            print("child node NOT OK")
            content: bytes = bytes(int(all_sections[i].attributes['LENGTH'].value, 16))
        section_content.update( {all_sections[i].attributes['NAME'].value : content} )

    file_byte.close()
    return section_content, all_sections


def get_functions(path:str)->list :
    """
    retourne une list [fonctions, symbol, fonction librairies]
    """
    item_list: list = []
    item_list.append(parseXML('FUNCTION'))
    item_list.append(parseXML('SYMBOL'))
    item_list.append(parseXML('EXT_LIBRARY_REFERENCE'))

    ret:list = [{}, {}, {}]
    for i in range(0, 3) :#on prend len(item_list) - 1 pcq on prend memory_section a part
        for s in item_list[i]:
            if i == 0 :
                ret[i].update( {s.attributes['NAME'].value : int(s.attributes['ENTRY_POINT'].value, 16) } )
            elif i == 1 :
                ret[i].update( {s.attributes['NAME'].value : int(s.attributes['ADDRESS'].value, 16) } )
            else :
                ret[i].update( {str(s.attributes['LIB_PROG_NAME'].value) + str(s.attributes['LIB_LABEL'].value)  : int(s.attributes['ADDRESS'].value, 16)} )

    return ret
