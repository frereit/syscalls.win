import sqlite3
import os

from flask import Flask, render_template, request, jsonify, send_file

DLL_DATABASE_NAME = "dlls.db"

app = Flask(__name__)
app.secret_key = os.urandom(32)


def as_list(titles, fields):
    out = []
    for field in fields:
        field_dict = {}
        for title, val in zip(titles, field):
            field_dict[title] = val
        out.append(field_dict)
    return out


@app.route("/images")
def images():

    fields = []
    titles = ["Docker image", "NTDLL version", "NTDLL hash"]

    if request.args.get("format") != "json":
        titles.append("Download")
    with sqlite3.connect(DLL_DATABASE_NAME) as connection:
        connection.row_factory = sqlite3.Row
        cur = connection.cursor()

        cur.execute("SELECT image, dll_sha256 FROM images")

        images = cur.fetchall()

        for image in images:
            # get dll
            cur.execute(
                "SELECT product_version FROM dlls WHERE sha256 = ?",
                (image["dll_sha256"],),
            )
            dll = cur.fetchone()
            if request.args.get("format") != "json":
                field = [
                    image["image"],
                    dll["product_version"],
                    f"<a href=/dlls?q={image['dll_sha256']}>{image['dll_sha256']}</a>",
                ]
                if "Download" in titles:
                    field.append(
                        f"<a href=/download/{image['dll_sha256']}>Download</a>"
                    )
                fields.append(field)
            else:
                fields.append(
                    [image["image"], dll["product_version"], image["dll_sha256"]]
                )

    if request.args.get("format") == "json":
        titles = ["docker_image", "ntdll_version", "ntdll_hash"]
        return jsonify(as_list(titles, fields))

    return render_template(
        "table.html", title="All recorded images", fields=fields, titles=titles
    )


@app.route("/")
@app.route("/dlls")
def dlls():
    titles = []
    fields = []
    with sqlite3.connect(DLL_DATABASE_NAME) as connection:
        connection.row_factory = sqlite3.Row
        cur = connection.cursor()

        titles = []
        if request.args.get("format") != "json":
            titles.append("Download")

        titles += ["sha256 hash", "Product Version", "File Size (bytes)"]

        cur.execute(
            "SELECT sha256, product_version, file_size FROM dlls WHERE machine_type = ?",
            ("AMD AMD64",),
        )
        dlls = cur.fetchall()

        if len(dlls) == 0:
            if request.args.get("format") == "json":
                return jsonify([])
            return render_template(
                "table.html", title="All recorded DLLs", fields=[], titles=titles
            )
        if request.args.get("format") != "json":
            titles.append("Syscall numbers")

        for dll in dlls:
            field = []
            if "Download" in titles:
                field.append(f"<a href=/download/{dll['product_version']}>Download</a>")
            field += [dll[k] for k in dll.keys()]
            if "Syscall numbers" in titles:
                field.append(f"<a href=/syscalls/{dll['sha256']}>Syscall numbers</a>")
            fields.append(field)
    if request.args.get("format") == "json":
        return jsonify(as_list(titles, fields))
    return render_template(
        "table.html",
        title="All recorded DLLs",
        fields=fields,
        titles=titles,
        subtitle="",
    )


@app.route("/syscalls")
def syscalls():
    titles = []
    fields = []
    dll_syscalls = {}
    with sqlite3.connect(DLL_DATABASE_NAME) as connection:
        connection.row_factory = sqlite3.Row
        cur = connection.cursor()

        # get all dlls
        cur.execute(
            "SELECT sha256, product_version FROM dlls WHERE machine_type=?",
            ("AMD AMD64",),
        )
        dlls = list(cur.fetchall())
        if len(dlls) == 0:
            if request.args.get("format") == "json":
                return jsonify([])
            return render_template(
                "base.html",
                title="All recorded syscall numbers",
                subtitle="No data available yet.",
            )

        # get all syscalls
        for dll in dlls:
            dll_syscalls[dll["product_version"]] = {}
            cur.execute("SELECT * FROM syscalls WHERE dll_sha256 = ?", (dll["sha256"],))
            syscalls = cur.fetchall()
            for syscall in syscalls:
                dll_syscalls[dll["product_version"]][syscall["syscall_name"]] = syscall[
                    "syscall_num"
                ]

    if request.args.get("format") == "json":
        return jsonify(dll_syscalls)

    cur.execute("SELECT DISTINCT syscall_name FROM syscalls")
    titles = ["Syscall"] + [
        f"<a href=/dlls?q={ver}>{ver}</a>" for ver in dll_syscalls.keys()
    ]
    syscall_names = set([syscall["syscall_name"] for syscall in cur.fetchall()])
    for syscall_name in syscall_names:
        row = []
        for ver, syscalls in dll_syscalls.items():
            row.append(syscalls.get(syscall_name, "N/A"))
        fields.append([syscall_name] + row)
    return render_template(
        "table.html", title="All recorded syscall numbers", fields=fields, titles=titles
    )


def get_sha256_for_identifier(identifier):
    with sqlite3.connect(DLL_DATABASE_NAME) as connection:
        connection.row_factory = sqlite3.Row
        cur = connection.cursor()
        # 1. try to search for sha256
        cur.execute(
            "SELECT sha256, product_version FROM dlls WHERE sha256 = ?", (identifier,)
        )
        sha256 = cur.fetchone()
        if sha256 is not None:
            return sha256["sha256"], sha256["product_version"]
        # 2. try to search for product_version
        cur.execute(
            "SELECT sha256, product_version FROM dlls WHERE product_version = ?",
            (identifier,),
        )
        sha256 = cur.fetchall()
        if len(sha256) == 1:
            return sha256[0]["sha256"], sha256[0]["product_version"]
        elif len(sha256) > 1:
            raise ValueError(
                f"Multiple dlls found for {identifier}: {', '.join([s['sha256'] for s in sha256])}"
            )
        raise ValueError(f"No dll found for '{identifier}'")


@app.route("/syscalls/<identifier>")
def syscalls_search(identifier):
    titles = []
    fields = []

    try:
        sha256, product_version = get_sha256_for_identifier(identifier)
    except ValueError as err:
        return jsonify({"error": f"Couldn't determine DLL from identifier: {err}"})

    with sqlite3.connect(DLL_DATABASE_NAME) as connection:
        connection.row_factory = sqlite3.Row
        cur = connection.cursor()

        titles = ["syscall", "number"]
        cur.execute("SELECT * FROM syscalls WHERE dll_sha256 = ?", (sha256,))
        syscalls = cur.fetchall()
        for syscall in syscalls:
            fields.append((syscall["syscall_name"], syscall["syscall_num"]))

    if request.args.get("format") == "json":
        return jsonify(dict(fields))
    return render_template(
        "table.html",
        title=f"Syscalls for NTDLL {product_version}",
        subtitle=sha256,
        fields=fields,
        titles=titles,
    )


@app.route("/download/<identifier>")
def download(identifier):
    try:
        sha256, _ = get_sha256_for_identifier(identifier)
    except ValueError as err:
        return jsonify({"error": f"Couldn't determine DLL from identifier: {err}"})

    return send_file(
        os.path.join("dlls", sha256 + ".dll"),
        as_attachment=True,
        download_name="ntdll.dll",
    )
