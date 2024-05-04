# syscall database

A simple database for Windows Syscall numbers, taken from the Windows Docker images. This is a project that I hacked together a while ago and am now finally publishing.

It runs at [https://syscalls.win](https://syscalls.win). If you're having problems with the website, [send me a toot](https://infosec.exchange/@fre).

The website is a very simple frontend for a SQLite Database, which is populated by an update script that runs every night. The update script checks all Windows Docker images, finds any new ones, and extracts the ntdll.dll within. It then finds the Syscall numbers for the ntdll.dll. Currently only x64 is supported. If you want support for other architectures, you need to add it in [utils/syscall_dumper.py](utils/syscall_dumper.py). Feel free to open a PR if you do so :).

## Setup

1. Install Dependencies

```bash
$ apt install sqlite3 exiftool python3
$ python3 -m venv .venv
$ source .venv/bin/activate
$ pip install -r requirements.txt
```

2. Initalize the SQLite Database and create the data directory.

> This clears the database.
{.warning}

```
$ sqlite3 dlls.db < dlls.sql
$ mkdir dlls
```

3. Start the Flask Web-App. For example with uWSGI + nginx (`pip install usgi`):

```nginx
location / {
        include uwsgi_params;
        uwsgi_pass unix:/var/www/syscalls/syscalls.sock;
}
```

and a systemd Service:

```
[Unit]
Description=uWSGI instance to run syscalls web app
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/syscalls
Environment="PATH=/var/www/syscalls/.venv/bin"
ExecStart=/var/www/syscalls/.venv/bin/uwsgi --ini syscalls.ini

[Install]
WantedBy=multi-user.target
```

4. Setup a cronjob to run update_db.py periodically, if not already running. For example, every day at 4 AM:

```cron
0 4 * * * /usr/bin/flock -n /tmp/syscalls.lock sh -c "cd /var/www/syscalls && ./.venv/bin/python update_db.py && rm -rf _tmp_*"
```
