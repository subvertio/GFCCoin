"""
GFC Content Fingerprints - "is this the same content?" for repost detection

A seed's fingerprints are strings "<kind>:<value>":

- sha256:<hex>   exact file bytes, for every content type
- img:<32 hex>   128-bit difference hash (dHash, rows + columns of a 9x9 grayscale
                 thumbnail). Survives resizing, re-encoding (PNG <-> JPEG), mild
                 compression and small colour shifts. Not crops, rotations, mirroring
                 or heavy edits.
- geo:<n>:<sketch>
                 3D geometry (.glb / .gltf with embedded buffers). Every mesh vertex
                 position is normalised to the model's bounding box (so moving or
                 uniformly scaling the model changes nothing), quantised to a
                 GEO_GRID^3 grid, de-duplicated, and summarised as a bottom-k MinHash
                 sketch of that point set. Re-exporting the same geometry (other
                 vertex order, seams split or merged, other index buffers, materials,
                 textures or names) gives the same set. Not rotations, remeshing,
                 decimation, Draco/meshopt compression or node-transform-only edits.

Video and audio only get sha256 for now (see docs/anti-repost.md for the plan).

Thresholds are deliberately conservative: a false "repost" label on someone's
original work is worse than a missed repost.
"""

import base64
import hashlib
import io
import json
import struct
from pathlib import Path
from typing import List, Optional

# --- Images ---
IMAGE_HASH_BITS = 128
IMAGE_MAX_DISTANCE = 8          # Hamming bits out of 128 (unrelated images average ~64)
IMAGE_MIN_SIDE = 32             # tiny images (icons, emoji) are too generic to claim
IMAGE_MIN_SET_BITS = 16         # flat/near-uniform images hash to almost all 0s or 1s:
IMAGE_MAX_SET_BITS = IMAGE_HASH_BITS - IMAGE_MIN_SET_BITS  # too generic to claim
IMAGE_MAX_PIXELS = 60_000_000   # refuse decompression bombs

# --- 3D geometry ---
GEO_GRID = 512                  # quantisation steps along the longest bounding-box side
GEO_SKETCH_SIZE = 64            # bottom-k sketch length
GEO_MIN_POINTS = 200            # simple primitives (cubes, planes, spheres) are too generic to claim
GEO_MIN_SIMILARITY = 0.9        # estimated Jaccard similarity of the two point sets
GEO_MAX_COUNT_RATIO = 1.05      # unique point counts must be within 5%
GEO_MAX_VERTICES = 5_000_000    # parsing limit

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tiff", ".tga"}
GLTF_EXTS = {".glb", ".gltf"}


NEAR_DUP_MAX_BYTES = 64 * 1024 * 1024


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fingerprints_for_file(path: Path) -> List[str]:
    """All fingerprints of a stored seed file (sha256 always, plus a near-duplicate one if supported)."""
    prints = [f"sha256:{sha256_file(path)}"]
    ext = path.suffix.lower()
    if path.stat().st_size > NEAR_DUP_MAX_BYTES:
        return prints  # the near-duplicate pass reads the whole file into memory
    try:
        if ext in IMAGE_EXTS:
            value = image_hash(path.read_bytes())
            if value:
                prints.append(f"img:{value}")
        elif ext in GLTF_EXTS:
            value = geometry_print(path.read_bytes(), ext)
            if value:
                prints.append(f"geo:{value}")
    except Exception:
        pass  # unreadable/odd files still get exact matching
    return prints


def kind_of(fp: str) -> str:
    return fp.split(":", 1)[0]


def matches(a: str, b: str) -> bool:
    """True if two fingerprints of the same kind say "same content"."""
    kind = kind_of(a)
    if kind != kind_of(b):
        return False
    if kind == "img":
        return image_distance(a[4:], b[4:]) <= IMAGE_MAX_DISTANCE
    if kind == "geo":
        return geometry_similar(a[4:], b[4:])
    return a == b


# ============================================================================
# IMAGES: 128-bit dHash
# ============================================================================

def image_hash(data: bytes) -> Optional[str]:
    """128-bit dHash as 32 hex chars, or None if the image can't be read or is too generic."""
    from PIL import Image, ImageOps
    Image.MAX_IMAGE_PIXELS = IMAGE_MAX_PIXELS
    with Image.open(io.BytesIO(data)) as img:
        if min(img.size) < IMAGE_MIN_SIDE:
            return None
        img.draft("L", (64, 64))  # fast JPEG decode at reduced size
        img = ImageOps.exif_transpose(img)
        if img.mode in ("RGBA", "LA", "PA") or (img.mode == "P" and "transparency" in img.info):
            # Transparent pixels hide arbitrary colour data: flatten onto white
            img = img.convert("RGBA")
            background = Image.new("RGBA", img.size, (255, 255, 255, 255))
            img = Image.alpha_composite(background, img)
        small = img.convert("L").resize((9, 9), Image.Resampling.LANCZOS)
        px = list(small.getdata())
    bits = 0
    for y in range(8):          # horizontal gradients
        for x in range(8):
            bits = (bits << 1) | (px[y * 9 + x] > px[y * 9 + x + 1])
    for y in range(8):          # vertical gradients
        for x in range(8):
            bits = (bits << 1) | (px[y * 9 + x] > px[(y + 1) * 9 + x])
    set_bits = bin(bits).count("1")
    if not IMAGE_MIN_SET_BITS <= set_bits <= IMAGE_MAX_SET_BITS:
        return None
    return f"{bits:032x}"


def image_distance(a: str, b: str) -> int:
    try:
        return bin(int(a, 16) ^ int(b, 16)).count("1")
    except ValueError:
        return IMAGE_HASH_BITS


# ============================================================================
# 3D: normalised, quantised vertex-set sketch
# ============================================================================

_COMPONENTS = {"SCALAR": 1, "VEC2": 2, "VEC3": 3, "VEC4": 4}
_FLOAT = 5126


def geometry_print(data: bytes, ext: str) -> Optional[str]:
    """'<unique point count>:<sketch hex>' for a glTF model, or None if unsupported or too simple."""
    gltf, bin_chunk = _parse_gltf(data, ext)
    if gltf is None:
        return None
    positions = _positions(gltf, bin_chunk)
    if not positions:
        return None
    lo = [min(p[i] for p in positions) for i in range(3)]
    hi = [max(p[i] for p in positions) for i in range(3)]
    extent = max(hi[i] - lo[i] for i in range(3))
    if not extent > 0:
        return None
    scale = GEO_GRID / extent
    points = {tuple(int(round((p[i] - lo[i]) * scale)) for i in range(3)) for p in positions}
    if len(points) < GEO_MIN_POINTS:
        return None
    hashes = sorted(int.from_bytes(hashlib.blake2b(struct.pack("<3i", *p), digest_size=8).digest(), "big")
                    for p in points)
    sketch = "".join(f"{h:016x}" for h in hashes[:GEO_SKETCH_SIZE])
    return f"{len(points)}:{sketch}"


def geometry_similar(a: str, b: str) -> bool:
    try:
        count_a, sketch_a = a.split(":", 1)
        count_b, sketch_b = b.split(":", 1)
        count_a, count_b = int(count_a), int(count_b)
        set_a = {sketch_a[i:i + 16] for i in range(0, len(sketch_a), 16)}
        set_b = {sketch_b[i:i + 16] for i in range(0, len(sketch_b), 16)}
    except ValueError:
        return False
    if min(count_a, count_b) < GEO_MIN_POINTS or max(count_a, count_b) > GEO_MAX_COUNT_RATIO * min(count_a, count_b):
        return False
    # Bottom-k estimate of Jaccard similarity: of the k smallest hashes of A u B, how many are in both
    union_bottom = sorted(set_a | set_b)[:GEO_SKETCH_SIZE]
    if not union_bottom:
        return False
    shared = sum(1 for h in union_bottom if h in set_a and h in set_b)
    return shared / len(union_bottom) >= GEO_MIN_SIMILARITY


def _parse_gltf(data: bytes, ext: str):
    """(gltf json, BIN chunk bytes or None), or (None, None) if this isn't readable glTF 2.0."""
    if ext == ".glb" or data[:4] == b"glTF":
        if len(data) < 20 or data[:4] != b"glTF":
            return None, None
        version, length = struct.unpack_from("<II", data, 4)
        if version != 2:
            return None, None
        offset, gltf, bin_chunk = 12, None, None
        while offset + 8 <= min(length, len(data)):
            chunk_len, chunk_type = struct.unpack_from("<II", data, offset)
            chunk = data[offset + 8: offset + 8 + chunk_len]
            if chunk_type == 0x4E4F534A and gltf is None:      # JSON
                gltf = json.loads(chunk.decode("utf-8"))
            elif chunk_type == 0x004E4942 and bin_chunk is None:  # BIN
                bin_chunk = chunk
            offset += 8 + chunk_len + (-chunk_len % 4)
        return (gltf, bin_chunk) if isinstance(gltf, dict) else (None, None)
    gltf = json.loads(data.decode("utf-8"))
    return (gltf, None) if isinstance(gltf, dict) else (None, None)


def _buffer_bytes(gltf: dict, index: int, bin_chunk: Optional[bytes]) -> Optional[bytes]:
    buffers = gltf.get("buffers") or []
    if not 0 <= index < len(buffers):
        return None
    uri = buffers[index].get("uri")
    if uri is None:
        return bin_chunk if index == 0 else None
    if isinstance(uri, str) and uri.startswith("data:") and ";base64," in uri:
        return base64.b64decode(uri.split(";base64,", 1)[1])
    return None  # external .bin files aren't uploaded with the seed


def _positions(gltf: dict, bin_chunk: Optional[bytes]) -> list:
    """Vertex positions of every mesh primitive (node transforms are ignored)."""
    accessors = gltf.get("accessors") or []
    views = gltf.get("bufferViews") or []
    cache, seen, out = {}, set(), []
    for mesh in gltf.get("meshes") or []:
        for prim in mesh.get("primitives") or []:
            if "extensions" in prim:
                return []  # Draco / meshopt compressed: not decoded here
            idx = (prim.get("attributes") or {}).get("POSITION")
            if not isinstance(idx, int) or idx in seen or not 0 <= idx < len(accessors):
                continue
            seen.add(idx)
            acc = accessors[idx]
            if acc.get("componentType") != _FLOAT or acc.get("type") != "VEC3" or "sparse" in acc:
                continue
            view_idx = acc.get("bufferView")
            if not isinstance(view_idx, int) or not 0 <= view_idx < len(views):
                continue
            view = views[view_idx]
            buf_idx = view.get("buffer", 0)
            if buf_idx not in cache:
                cache[buf_idx] = _buffer_bytes(gltf, buf_idx, bin_chunk)
            buf = cache[buf_idx]
            count = int(acc.get("count", 0))
            if buf is None or count <= 0 or len(out) + count > GEO_MAX_VERTICES:
                continue
            start = int(view.get("byteOffset", 0)) + int(acc.get("byteOffset", 0))
            stride = int(view.get("byteStride", 0)) or 12
            if start < 0 or stride < 12 or start + stride * (count - 1) + 12 > len(buf):
                continue
            for i in range(count):
                out.append(struct.unpack_from("<3f", buf, start + i * stride))
    return [p for p in out if all(c == c and abs(c) != float("inf") for c in p)]  # drop NaN/inf
