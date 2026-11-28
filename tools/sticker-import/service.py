"""Read-only Telegram pack importer. The bot credential never leaves this service."""
import ctypes as c
import gzip
import ctypes.util
import io
import json
import os
import re
import subprocess
import tempfile
from functools import lru_cache
from pathlib import Path
from urllib.request import urlopen
from urllib.parse import urlencode

from flask import Flask, abort, jsonify, Response
from PIL import Image

app = Flask(__name__)
token = os.environ["TELEGRAM_BOT_TOKEN"]


def fetch(url, limit):
    with urlopen(url, timeout=20) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("size limit")
    return data


def telegram(method, **params):
    url = f"https://api.telegram.org/bot{token}/{method}?" + urlencode(params)
    return json.loads(fetch(url, 3_000_000))["result"]


@lru_cache(maxsize=64)
def lookup(name, epoch):
    return telegram("getStickerSet", name=name)


def pack(name):
    import time
    if not re.fullmatch(r"[A-Za-z0-9_]{1,64}", name):
        abort(400)
    try:
        result = lookup(name, int(time.time() // 600))
    except Exception:
        abort(502, "Telegram could not supply this set")
    if result["sticker_type"] not in ("regular", "custom_emoji"):
        abort(422)
    return result


@app.get("/health")
def health():
    return jsonify(service="core-sticker-import")


@app.get("/packs/<name>")
def manifest(name):
    p = pack(name)
    return jsonify(name=p["name"], title=p["title"], custom=p["sticker_type"] == "custom_emoji",
                   items=[dict(id=s["file_unique_id"], emoji=s.get("emoji") or "✨") for s in p["stickers"]])


def tgs_frames(data):
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
        body = stream.read(2_000_001)
    if len(body) > 2_000_000:
        raise ValueError("size limit")
    lib = c.CDLL(ctypes.util.find_library("rlottie") or "librlottie.so")
    ptr = c.c_void_p
    lib.lottie_animation_from_data.argtypes = [c.c_char_p] * 3
    lib.lottie_animation_from_data.restype = ptr
    lib.lottie_animation_get_totalframe.argtypes = [ptr]
    lib.lottie_animation_get_totalframe.restype = c.c_size_t
    lib.lottie_animation_get_framerate.argtypes = [ptr]
    lib.lottie_animation_get_framerate.restype = c.c_double
    lib.lottie_animation_render.argtypes = [ptr, c.c_size_t, ptr, c.c_size_t, c.c_size_t, c.c_size_t]
    lib.lottie_animation_destroy.argtypes = [ptr]
    animation = lib.lottie_animation_from_data(body, b"", b"")
    if not animation:
        raise ValueError("invalid TGS")
    try:
        count = min(240, lib.lottie_animation_get_totalframe(animation))
        fps = max(1, min(60, lib.lottie_animation_get_framerate(animation)))
        stride = max(1, round(fps / 20))
        frames = []
        for index in range(0, count, stride):
            pixels = c.create_string_buffer(256 * 256 * 4)
            lib.lottie_animation_render(animation, index, pixels, 256, 256, 256 * 4)
            frames.append(Image.frombytes("RGBA", (256, 256), pixels.raw, "raw", "BGRa"))
        result = io.BytesIO()
        frames[0].save(result, format="GIF", save_all=True, append_images=frames[1:],
                       duration=round(1000 * stride / fps), disposal=2, loop=0)
        return result.getvalue()
    finally:
        lib.lottie_animation_destroy(animation)


@lru_cache(maxsize=48)
def artwork(file_id, animated, video):
    path = telegram("getFile", file_id=file_id)["file_path"]
    data = fetch(f"https://api.telegram.org/file/bot{token}/{path}", 2_000_000)
    if animated:
        return tgs_frames(data)
    if video:
        with tempfile.TemporaryDirectory() as tmp:
            src, dst = Path(tmp, "in.webm"), Path(tmp, "out.gif")
            src.write_bytes(data)
            subprocess.run(["ffmpeg", "-v", "error", "-c:v", "libvpx-vp9", "-i", str(src), "-t", "4",
                            "-vf", "fps=20,scale=256:256:force_original_aspect_ratio=decrease,split[a][b];[a]palettegen[p];[b][p]paletteuse",
                            str(dst)], check=True, timeout=20)
            return dst.read_bytes()
    return data


@app.get("/packs/<name>/<item>")
def asset(name, item):
    sticker = next((s for s in pack(name)["stickers"] if s["file_unique_id"] == item), None)
    if not sticker:
        abort(404)
    try:
        data = artwork(sticker["file_id"], sticker["is_animated"], sticker["is_video"])
    except Exception:
        abort(502, "Unable to render sticker")
    return Response(data, mimetype="image/gif" if data.startswith(b"GIF") else "image/webp",
                    headers={"Cache-Control": "public, max-age=86400"})
