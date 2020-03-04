import os
import requests
import filecmp
from os.path import relpath


clean_path = 'C:\\inetpub\\wwwroot\\Kentico11\\CMS\\'
modified_path = 'C:\\inetpub\\wwwroot\\xxx\\CMS\\'  # Path to the test project

def find_paths(path):
    files = []
    for r, _, f in os.walk(path):
        for file in f:
            if ('.aspx' in file) or ('.ascx' in file):
                files.append(os.path.join(r, file))
    return files

def compare_files(file1, file2):
    """Compares files by their content."""
    return filecmp.cmp(file1, file2)


print("[+] The program started!")

clean = [relpath(file, clean_path) for file in find_paths(clean_path)]
modified = [relpath(file, modified_path) for file in find_paths(modified_path)]

print("\n[+] Finding new and changed files!")

diff_files = []
for path in modified:
    # Path is not in clean installation 
    if path not in clean:
        diff_files.append(path)
    else:
        # File is in clean installation, check for changes
        if not compare_files(
            os.path.join(clean_path, path),
            os.path.join(modified_path, path)
        ):
            diff_files.append(path)


# Vulnerable string lookup
vuln_strings = [ "getstring", "eval", "scripthelper.getscript", 
    "httpcontext.current.request", "lbl" ]
filtered = []
for file in diff_files:
    with open(os.path.join(modified_path, file), encoding='utf-8', errors='ignore') as f:
        data = f.read().replace('\n', '')
        for string in vuln_strings:
            if string in data.lower():
                filtered.append(file)
                break # The vuln-string ocurrence found, no need to continue searching

tmplen = len(diff_files)
tmplen2 = len(filtered)


print("\n[+] Adding all findings in to the file!")

with open("AllCustomFiles.txt", 'w', encoding='utf-8') as output:
    output.write('\n'.join(filtered))

print("\n[+] Finished!")
print("\t%s different files, %s files potentially vulnerable" % (len(diff_files), len(filtered)))
print("\tWritten to: AllCustomFiles.txt")
