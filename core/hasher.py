import hashlib

def calculate_hashes(file_path):
    md5_hasher =  hashlib.md5()
    sha256_hasher = hashlib.sha256()
    sha1_hasher = hashlib.sha1()

    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hasher.update(chunk)
                sha256_hasher.update(chunk)
                sha1_hasher.update(chunk)
    except FileNotFoundError:
        print(f"Error: {file_path} not found")
        return None

    return {
        "md5": md5_hasher.hexdigest(),
        "sha256": sha256_hasher.hexdigest(),
        "sha1": sha1_hasher.hexdigest()
    }
