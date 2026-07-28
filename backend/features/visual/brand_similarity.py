"""
Brand visual similarity - Phase 4 (Visual Detection).

Compares a suspicious screenshot against a small reference set of known,
legitimate brand login/landing pages using perceptual hashing (imagehash).
"""
import io
import os

import imagehash
from PIL import Image

REFERENCE_DIR = os.path.join(os.path.dirname(__file__), "reference_brands")

CLONE_THRESHOLD = 12
NEAR_IDENTICAL_THRESHOLD = 5


def _load_reference_hashes() -> dict:
    hashes = {}
    if not os.path.isdir(REFERENCE_DIR):
        return hashes

    for filename in os.listdir(REFERENCE_DIR):
        if not filename.lower().endswith((".png", ".jpg", ".jpeg")):
            continue
        brand_name = os.path.splitext(filename)[0]
        try:
            path = os.path.join(REFERENCE_DIR, filename)
            with Image.open(path) as img:
                hashes[brand_name] = imagehash.phash(img)
        except Exception:
            continue

    return hashes


_REFERENCE_HASHES = _load_reference_hashes()


def compare_to_brands(screenshot_bytes: bytes) -> dict:
    if not _REFERENCE_HASHES:
        return {
            "closest_brand": None,
            "hash_distance": None,
            "visual_similarity_score": None,
            "is_likely_clone": False,
            "all_distances": {},
        }

    try:
        image = Image.open(io.BytesIO(screenshot_bytes))
        target_hash = imagehash.phash(image)
    except Exception:
        return {
            "closest_brand": None,
            "hash_distance": None,
            "visual_similarity_score": None,
            "is_likely_clone": False,
            "all_distances": {},
        }

    distances = {
        brand: target_hash - ref_hash
        for brand, ref_hash in _REFERENCE_HASHES.items()
    }

    closest_brand = min(distances, key=distances.get)
    closest_distance = distances[closest_brand]

    max_meaningful_distance = 32
    similarity_score = round(
        max(0.0, 1 - (closest_distance / max_meaningful_distance)), 4
    )

    return {
        "closest_brand": closest_brand,
        "hash_distance": closest_distance,
        "visual_similarity_score": similarity_score,
        "is_likely_clone": closest_distance <= CLONE_THRESHOLD,
        "all_distances": distances,
    }
