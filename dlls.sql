DROP TABLE IF EXISTS images;
DROP TABLE IF EXISTS dlls;
DROP TABLE IF EXISTS syscalls;

CREATE TABLE images (
    id INTEGER PRIMARY KEY,
    image TEXT UNIQUE NOT NULL,
    dll_sha256 INTEGER,
    FOREIGN KEY (dll_sha256) REFERENCES dlls(sha256)
);

CREATE TABLE dlls (
    sha256 TEXT PRIMARY KEY,
    product_version TEXT NOT NULL,
    file_version TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    file_os TEXT NOT NULL,
    machine_type TEXT NOT NULL
);

CREATE TABLE syscalls (
    id INTEGER PRIMARY KEY,
    syscall_name TEXT NOT NULL,
    syscall_num INTEGER NOT NULL,
    dll_sha256 TEXT NOT NULL,
    FOREIGN KEY (dll_sha256) REFERENCES dlls(sha256)
);
