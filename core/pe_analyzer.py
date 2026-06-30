import pefile


def analyze_pe_imports(file_path):
    """
    Parses the PE file and extracts the Import Address Table (IAT).
    Lists which DLLs and functions the executable is calling.
    """
    try:

        pe = pefile.PE(file_path)

        imports_dict = {}


        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:

                dll_name = entry.dll.decode('utf-8', errors='ignore')
                imports_dict[dll_name] = []


                for imported_function in entry.imports:
                    if imported_function.name:

                        func_name = imported_function.name.decode('utf-8', errors='ignore')
                        imports_dict[dll_name].append(func_name)

        return imports_dict

    except pefile.PEFormatError:
        print(f"[-] Error: {file_path} is not a valid PE file.")
        return None
    except FileNotFoundError:
        print(f"[-] Error: File {file_path} not found.")
        return None