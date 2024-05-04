# thanks https://github.com/NotGlop/docker-drag/blob/master/docker_pull.py
import os
import sys
import json
import hashlib
import shutil
import requests
import tarfile
import urllib3

urllib3.disable_warnings()


def pull(
    img,
    registry="registry-1.docker.io",
    repo="library",
    tag=None,
    imgdir=None,
    print_progress_bar=False,
):
    repository = "{}/{}".format(repo, img)

    auth_url = "https://auth.docker.io/token"
    reg_service = "registry.docker.io"

    # Get Docker token (this function is useless for unauthenticated registries like Microsoft)
    def get_auth_head(type):
        resp = requests.get(
            "{}?service={}&scope=repository:{}:pull".format(
                auth_url, reg_service, repository
            ),
            verify=False,
        )
        access_token = resp.json()["token"]
        auth_head = {"Authorization": "Bearer " + access_token, "Accept": type}
        return auth_head

    # Docker style progress bar
    def progress_bar(ublob, nb_traits):
        sys.stdout.write("\r" + ublob[7:19] + ": Downloading [")
        for i in range(0, nb_traits):
            if i == nb_traits - 1:
                sys.stdout.write(">")
            else:
                sys.stdout.write("=")
        for i in range(0, 49 - nb_traits):
            sys.stdout.write(" ")
        sys.stdout.write("]")
        sys.stdout.flush()

    # Fetch manifest v2 and get image layer digests
    auth_head = get_auth_head(
        "application/vnd.docker.distribution.manifest.v2+json")
    print(f"[*] Pulling with {registry}, {repository}, {tag}")
    resp = requests.get(
        "https://{}/v2/{}/manifests/{}".format(registry, repository, tag),
        headers=auth_head,
        verify=False,
    )
    if resp.status_code != 200:
        raise ValueError(
            "[-] Cannot fetch manifest for {} [HTTP {}]".format(
                repository, resp.status_code
            )
        )
        print("[-] HTTP {}".format(resp.status_code))
        print(resp.content)
        resp = requests.get(
            "https://{}/v2/{}/manifests/{}".format(registry, repository, tag),
            verify=False,
        )
        if resp.status_code == 200:
            print(
                "[+] Manifests found for this tag (use the @digest format to pull the corresponding image):"
            )
            manifests = resp.json()["manifests"]
            for manifest in manifests:
                for key, value in manifest["platform"].items():
                    sys.stdout.write("{}: {}, ".format(key, value))
                print("digest: {}".format(manifest["digest"]))
        exit(1)
    layers = resp.json()["layers"]

    # Create tmp folder that will hold the image
    if imgdir is None:
        imgdir = "tmp_{}_{}".format(img, tag.replace(":", "@"))
    os.makedirs(imgdir, exist_ok=True)
    print("Creating image structure in: " + imgdir)

    config = resp.json()["config"]["digest"]
    confresp = requests.get(
        "https://{}/v2/{}/blobs/{}".format(registry, repository, config),
        headers=auth_head,
        verify=False,
    )
    file = open("{}/{}.json".format(imgdir, config[7:]), "wb")
    file.write(confresp.content)
    file.close()

    content = [{"Config": config[7:] + ".json", "RepoTags": [], "Layers": []}]
    content[0]["RepoTags"].append(
        "/".join([registry, repo]) + "/" + img + ":" + tag)

    empty_json = '{"created":"1970-01-01T00:00:00Z","container_config":{"Hostname":"","Domainname":"","User":"","AttachStdin":false, \
        "AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false, "StdinOnce":false,"Env":null,"Cmd":null,"Image":"", \
        "Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":null}}'

    # Build layer folders
    parentid = ""
    for layer in layers:
        ublob = layer["digest"]
        # FIXME: Creating fake layer ID. Don't know how Docker generates it
        fake_layerid = hashlib.sha256(
            (parentid + "\n" + ublob + "\n").encode("utf-8")
        ).hexdigest()
        layerdir = imgdir + "/" + fake_layerid
        os.makedirs(layerdir, exist_ok=True)

        # Creating VERSION file
        file = open(layerdir + "/VERSION", "w")
        file.write("1.0")
        file.close()

        # Creating layer.tar.gz file
        sys.stdout.write(ublob[7:19] + ": Downloading...")
        sys.stdout.flush()
        auth_head = get_auth_head(
            "application/vnd.docker.distribution.manifest.v2+json"
        )  # refreshing token to avoid its expiration
        bresp = requests.get(
            "https://{}/v2/{}/blobs/{}".format(registry, repository, ublob),
            headers=auth_head,
            stream=True,
            verify=False,
        )
        if bresp.status_code != 200:  # When the layer is located at a custom URL
            bresp = requests.get(
                layer["urls"][0], headers=auth_head, stream=True, verify=False
            )
            if bresp.status_code != 200:
                shutil.rmtree(imgdir)
                raise ValueError(
                    "Cannot download layer {} [HTTP {}]".format(
                        ublob[7:19], bresp.status_code
                    )
                )
        # Stream download and follow the progress
        bresp.raise_for_status()
        unit = int(bresp.headers["Content-Length"]) / 50
        acc = 0
        nb_traits = 0
        if print_progress_bar:
            progress_bar(ublob, nb_traits)
        with open(layerdir + "/layer.tar.gz", "wb") as file:
            for chunk in bresp.iter_content(chunk_size=8192):
                if chunk:
                    file.write(chunk)
                    acc = acc + 8192
                    if acc > unit:
                        nb_traits = nb_traits + 1
                        if print_progress_bar:
                            progress_bar(ublob, nb_traits)
                        acc = 0
        print(
            "\r{}: Pull complete [{}]".format(
                ublob[7:19], bresp.headers["Content-Length"]
            )
        )
        content[0]["Layers"].append(fake_layerid + "/layer.tar.gz")

        # Creating json file
        file = open(layerdir + "/json", "w")
        # last layer = config manifest - history - rootfs
        if layers[-1]["digest"] == layer["digest"]:
            # FIXME: json.loads() automatically converts to unicode, thus decoding values whereas Docker doesn't
            json_obj = json.loads(confresp.content)
            if "history" in json_obj:
                del json_obj["history"]
            try:
                del json_obj["rootfs"]
            except Exception:  # Because Microsoft loves case insensitiveness
                if "rootfS" in json_obj:
                    del json_obj["rootfS"]
        else:  # other layers json are empty
            json_obj = json.loads(empty_json)
        json_obj["id"] = fake_layerid
        if parentid:
            json_obj["parent"] = parentid
        parentid = json_obj["id"]
        file.write(json.dumps(json_obj))
        file.close()

    file = open(imgdir + "/manifest.json", "w")
    file.write(json.dumps(content))
    file.close()

    content = {"/".join([registry, repo]) + "/" + img: {tag: fake_layerid}}
    file = open(imgdir + "/repositories", "w")
    file.write(json.dumps(content))
    file.close()

    return imgdir


def main():
    if len(sys.argv) != 2:
        print(
            "Usage:\n\tdocker_pull.py [registry/][repository/]image[:tag|@digest]\n")
        exit(1)

    # Look for the Docker image to download
    repo = "library"
    tag = "latest"
    imgparts = sys.argv[1].split("/")
    try:
        img, tag = imgparts[-1].split("@")
    except ValueError:
        try:
            img, tag = imgparts[-1].split(":")
        except ValueError:
            img = imgparts[-1]
    # Docker client doesn't seem to consider the first element as a potential registry unless there is a '.' or ':'
    if len(imgparts) > 1 and ("." in imgparts[0] or ":" in imgparts[0]):
        registry = imgparts[0]
        repo = "/".join(imgparts[1:-1])
    else:
        registry = "registry-1.docker.io"
        if len(imgparts[:-1]) != 0:
            repo = "/".join(imgparts[:-1])
        else:
            repo = "library"
    imgdir = pull(img, registry, repo, tag)

    # Create image tar and clean tmp folder
    docker_tar = repo.replace("/", "_") + "_" + img + ".tar"
    sys.stdout.write("Creating archive...")
    sys.stdout.flush()
    tar = tarfile.open(docker_tar, "w")
    tar.add(imgdir, arcname=os.path.sep)
    tar.close()
    shutil.rmtree(imgdir)
    print("\rDocker image pulled: " + docker_tar)


if __name__ == "__main__":
    main()
