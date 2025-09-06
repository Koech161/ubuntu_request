import os
import re
import base64
import hashlib
import requests
import binascii
from urllib.parse import urlparse

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp"}
SAVED_HASHES = set()

def sanitize_filename(name):
    return re.sub(r'[^\w\-_\.]', '_', name)

def hash_bytes(data):
    return hashlib.sha256(data).hexdigest()

def save_image(data, ext, suggested_name):
    img_hash = hash_bytes(data)
    if img_hash in SAVED_HASHES:
        print(f"⏭ Skipped duplicate image: {suggested_name}")
        return

    SAVED_HASHES.add(img_hash)

    filename = sanitize_filename(suggested_name)
    if not filename.endswith(f".{ext}"):
        filename += f".{ext}"

    filepath = os.path.join("Fetched_Images", filename)
    counter = 1
    while os.path.exists(filepath):
        filename = f"{os.path.splitext(suggested_name)[0]}_{counter}.{ext}"
        filepath = os.path.join("Fetched_Images", filename)
        counter += 1

    with open(filepath, 'wb') as f:
        f.write(data)

    print(f"✓ Saved: {filename} ({len(data)} bytes)")

def process_data_uri(data_uri):
    match = re.match(r'data:image/(?P<ext>\w+);base64,(?P<data>.+)', data_uri)
    if not match:
        print("✗ Invalid base64 image format.")
        return

    ext = match.group('ext')
    b64_data = match.group('data')

    try:
        # Fix padding if needed
        missing_padding = len(b64_data) % 4
        if missing_padding:
            b64_data += '=' * (4 - missing_padding)
        data = base64.b64decode(b64_data)
    except (binascii.Error, ValueError) as e:
        print(f"✗ Base64 decode error: {e}")
        return

    if len(data) > MAX_FILE_SIZE:
        print("✗ Skipped base64 image: too large.")
        return

    save_image(data, ext, f"base64_image")

def process_url(url):
    try:
        response = requests.get(url, timeout=10, stream=True)
        response.raise_for_status()

        content_type = response.headers.get('Content-Type', '')
        content_length = response.headers.get('Content-Length')

        if not content_type.startswith('image/'):
            print(f"✗ Not an image: {url} (Content-Type: {content_type})")
            return

        if content_type not in ALLOWED_IMAGE_TYPES:
            print(f"✗ Unsupported image type: {content_type}")
            return

        if content_length and int(content_length) > MAX_FILE_SIZE:
            print(f"✗ Image too large (Content-Length: {content_length})")
            return

        data = response.content
        if len(data) > MAX_FILE_SIZE:
            print(f"✗ Image too large after download: {url}")
            return

        ext = content_type.split('/')[-1]
        parsed_url = urlparse(url)
        filename = os.path.basename(parsed_url.path) or "downloaded_image"

        save_image(data, ext, filename)

    except requests.exceptions.RequestException as e:
        print(f"✗ Error fetching {url}: {e}")

def main():
    print("Welcome to the Secure Ubuntu Image Fetcher")
    print("Enter one or more image URLs or base64 data URIs (comma-separated):")
    
    input_data = input("> ").strip()
    urls = re.findall(r'data:image/\w+;base64,[^,]+|https?://[^\s,]+', input_data)

    os.makedirs("Fetched_Images", exist_ok=True)

    for url in urls:
        if url.startswith("data:image/"):
            process_data_uri(url)
        elif url.startswith("http://") or url.startswith("https://"):
            process_url(url)
        else:
            print(f"✗ Unsupported input: {url}")

    print("\nFinished fetching images.\n")

if __name__ == "__main__":
    main()
