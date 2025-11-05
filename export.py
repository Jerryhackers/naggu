import pefile
import os

def get_exported_functions(dll_path):
    # Load the DLL using pefile
    try:
        pe = pefile.PE(dll_path)
    except FileNotFoundError:
        print(f"Error: The file {dll_path} was not found.")
        return []
    except pefile.PEFormatError:
        print(f"Error: {dll_path} is not a valid PE file.")
        return []

    # Check if the DLL has exports
    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        print(f"Error: No export directory found in {dll_path}.")
        return []

    # Extract exported functions
    exports = []
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        function_name = exp.name.decode() if exp.name else f"Unknown_{exp.ordinal}"
        exports.append(function_name)

    return exports

def generate_export_functions(functions, dll_path):
    export_functions = []
    dll_path = dll_path.replace("\\", "\\\\")  # Ensure backslashes are escaped
    for i, function in enumerate(functions, start=1):
        export_function = f'#pragma comment(linker,"/export:{function}={dll_path}.{function},@{i}")'
        export_functions.append(export_function)
    return export_functions

def main():
    # Ask the user for the DLL path
    dll_path = input("Enter the path to the DLL file: ")

    if not os.path.exists(dll_path):
        print(f"Error: The file {dll_path} does not exist.")
        return

    # Get the exported functions
    exported_functions = get_exported_functions(dll_path)

    if exported_functions:
        # Generate and print the export functions in the required format
        formatted_exports = generate_export_functions(exported_functions, dll_path)
        for export in formatted_exports:
            print(export)

    if __name__ == "__main__":
    main()