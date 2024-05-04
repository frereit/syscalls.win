import pefile


def is_syscall(img, symbol):
    addr = symbol.address
    if not symbol.name.startswith(b"Nt"):
        return False
    if (
        img[addr] == 0x4C
        and img[addr + 1] == 0x8B
        and img[addr + 2] == 0xD1
        and img[addr + 3] == 0xB8
    ):
        return True
    return False


def get_syscall_numbers(filepath) -> dict:
    pe = pefile.PE(filepath)
    if pe.FILE_HEADER.Machine != pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
        return {}
    img = pe.get_memory_mapped_image()
    d = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    pe.parse_data_directories(directories=d)
    res = {}
    for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if symbol.name is None:
            continue
        if not is_syscall(img, symbol):
            continue
        addr = symbol.address
        syscall_nr_hi = img[addr + 5]
        syscall_nr_lo = img[addr + 4]
        syscall_nr = syscall_nr_hi * 256 + syscall_nr_lo
        res[symbol.name.decode()] = syscall_nr
    return res


if __name__ == "__main__":
    import sys
    import json

    print(json.dumps(get_syscall_numbers(sys.argv[1]), indent=4))
