import os
import json
import tarfile
import shutil
import hashlib
import subprocess
from io import StringIO
import traceback
import sqlite3
import unicodedata
import re
import time

import pandas as pd
import requests

from utils.docker_pull import pull
from utils.syscall_dumper import get_syscall_numbers

DLL_DATABASE_NAME = "dlls.db"


def slugify(value, allow_unicode=False):
    """
    Taken from https://github.com/django/django/blob/master/django/utils/text.py
    Convert to ASCII if 'allow_unicode' is False. Convert spaces or repeated
    dashes to single dashes. Remove characters that aren't alphanumerics,
    underscores, or hyphens. Convert to lowercase. Also strip leading and
    trailing whitespace, dashes, and underscores.
    """
    value = str(value)
    if allow_unicode:
        value = unicodedata.normalize("NFKC", value)
    else:
        value = (
            unicodedata.normalize("NFKD", value)
            .encode("ascii", "ignore")
            .decode("ascii")
        )
    value = re.sub(r"[^\w\s-]", "", value.lower())
    return re.sub(r"[-\s]+", "-", value).strip("-_")


def download_all(repositories):
    dlls_db_conn = sqlite3.connect(DLL_DATABASE_NAME)
    cur = dlls_db_conn.cursor()
    cur.row_factory = sqlite3.Row

    for repository in repositories:
        print(f"[*] Pulling {repository}")
        # https://mcr.microsoft.com/v2/windows/nanoserver/tags/list
        resp = requests.get(
            "https://mcr.microsoft.com/v2/{}/tags/list".format(repository)
        )
        imgparts = repository.split("/")
        image = imgparts[-1]
        if len(imgparts) == 1:
            repo = ""
        else:
            repo = "/".join(imgparts[:-1])

        for tag in resp.json()["tags"]:
            # search db for tag
            cur.execute(
                "SELECT * FROM images WHERE image = ?", (f"{repository}:{tag}",)
            )
            if cur.fetchone() is not None:
                print(f"[*] Skipping already downloaded {image}:{tag}")
                continue
            start = time.time()
            print(f"[*] Pulling {repository}:{tag}")
            tmpdir = f"_tmp_{slugify(repository)}_{slugify(tag)}"
            try:
                outdir = pull(image, "mcr.microsoft.com", repo, tag, tmpdir)
            except Exception as err:
                shutil.rmtree(tmpdir, ignore_errors=True)
                print(f"[-] Failed to pull {repository}:{tag}: {err}")
                print(traceback.format_exc())
                continue
            with open(os.path.join(outdir, "manifest.json")) as f:
                manifest = json.load(f)
            ntdll = None
            for i, layer in enumerate(manifest[0]["Layers"]):
                with tarfile.open(os.path.join(outdir, layer)) as layer_tar:
                    for member in layer_tar.getmembers():
                        if member.name == "Files/Windows/System32/ntdll.dll":
                            print(
                                f"[+] Found ntdll.dll for {repository}:{tag} at {member.name} in layer {i}"
                            )
                            if ntdll is not None:
                                print(f"[!] Overwriting previously found DLL.")
                            ntdll = layer_tar.extractfile(member)
                            ntdll = ntdll.read()
            shutil.rmtree(outdir)
            if not ntdll:
                print(f"[-] No ntdll found for {repository}:{tag}")
                continue
            # os.makedirs(f"{repository}/{tag}", exist_ok=True)
            # ntdll_path = os.path.join(f"{repository}/{tag}", "ntdll.dll")
            # with open(ntdll_path, "wb") as f:
            #    f.write(ntdll)

            hash = hashlib.sha256(ntdll).hexdigest()

            cur.execute(
                "INSERT INTO images (image, dll_sha256) VALUES (?, ?)",
                (f"{repository}:{tag}", hash),
            )
            dlls_db_conn.commit()

            # search db for hash
            cur.execute("SELECT * FROM dlls WHERE sha256 = ?", (hash,))
            if cur.fetchone() is not None:
                print(f"[*] {repository}:{tag} contains known ntdll.")
                continue

            ntdll_path = os.path.join("dlls", f"{hash}.dll")
            with open(ntdll_path, "wb") as f:
                f.write(ntdll)
            raw_csv = subprocess.run(
                f"exiftool {ntdll_path} -csv".split(), stdout=subprocess.PIPE
            ).stdout.decode()
            df = pd.read_csv(StringIO(raw_csv), sep=",")
            cur.execute(
                "INSERT INTO dlls VALUES (?, ?, ?, ?, ?, ?)",
                (
                    hash,
                    df["ProductVersion"][0],
                    df["FileVersion"][0],
                    len(ntdll),
                    df["FileOS"][0],
                    df["MachineType"][0],
                ),
            )

            syscall_numbers = get_syscall_numbers(ntdll_path)
            for syscall in syscall_numbers:
                cur.execute(
                    "INSERT INTO syscalls VALUES (NULL, ?, ?, ?)",
                    (syscall, syscall_numbers[syscall], hash),
                )
            print(
                f"[+] Fully parsed {repository}:{tag} in {time.time() - start:.1f} seconds"
            )
            dlls_db_conn.commit()


if __name__ == "__main__":
    images = [
        "windows/nanoserver",
        "windows/insider",
        "windows/servercore",
        "windows/server",
        "windows",
    ]
    download_all(images)
