import zipfile, os

ROOT = r"C:\Users\zhang\projects\sh-blocker"
SRC = os.path.join(ROOT, "carrier_dm-module")
OUT = os.path.join(ROOT, "dist", "CarrierDMBlocker-KernelSU-2.0.zip")

FILES = [
    ("module.prop", "module.prop"),
    ("post-fs-data.sh", "post-fs-data.sh"),
    ("service.sh", "service.sh"),
    ("action.sh", "action.sh"),
    ("uninstall.sh", "uninstall.sh"),
    ("skip_mount", "skip_mount"),
    ("dbfix.dex", "dbfix.dex"),
]

os.makedirs(os.path.dirname(OUT), exist_ok=True)
if os.path.exists(OUT):
    os.remove(OUT)

with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
    for src, arc in FILES:
        p = os.path.join(SRC, src)
        data = open(p, "rb").read()
        if src.endswith(".sh") or src == "module.prop":
            assert b"\r\n" not in data, "CRLF found in " + src
        zi = zipfile.ZipInfo(arc)
        zi.external_attr = (0o755 << 16) | 0x8000
        zi.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(zi, data)
        print("%-18s %6d" % (arc, len(data)))

print("built", OUT, os.path.getsize(OUT))
