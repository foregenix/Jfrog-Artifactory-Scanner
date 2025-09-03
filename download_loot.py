#!/usr/bin/env python3

import os
import argparse
from urllib.parse import urlparse
import urllib3
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

http = urllib3.PoolManager(
    num_pools=20,
    maxsize=20,
    block=True,
    timeout=urllib3.Timeout(connect=10.0, read=30.0),
    cert_reqs='CERT_NONE'
)

def get_file_size(url, headers=None):
    try:
        resp = http.request('HEAD', url, headers=headers or {})
        if resp.status == 200:
            return int(resp.headers.get('Content-Length', 0))
    except Exception as e:
        print(f"[!] Error in get_file_size: {e}")
    return 0

def supports_range_requests(url, headers=None):
    try:
        test_headers = (headers or {}).copy()
        test_headers['Range'] = 'bytes=0-0'
        resp = http.request('GET', url, headers=test_headers)
        return resp.status == 206
    except Exception as e:
        print(f"[!] Error in supports_range_requests: {e}")
    return False

def download_chunk(url, start, end, chunk_id, temp_dir, headers=None, pbar=None, max_retries=3):
    chunk_headers = (headers or {}).copy()
    chunk_headers['Range'] = f'bytes={start}-{end}'
    chunk_headers.pop('Accept-Encoding', None)

    chunk_file = os.path.join(temp_dir, f'chunk_{chunk_id}')
    
    for attempt in range(1, max_retries + 1):
        try:
            with http.request('GET', url, preload_content=False, headers=chunk_headers) as resp:
                if resp.status not in (206, 200):
                    print(f"[!] Chunk {chunk_id} HTTP {resp.status} for range {start}-{end} (Attempt {attempt})")
                    continue

                with open(chunk_file, 'wb') as f:
                    for data in resp.stream(8192):
                        if data:
                            f.write(data)
                            if pbar:
                                pbar.update(len(data))
                return True
        except Exception as e:
            print(f"[!] Chunk {chunk_id} failed on attempt {attempt}: {e}")
            time.sleep(1.5 * attempt)

    return False

def combine_chunks(temp_dir, output_path, num_chunks):
    with open(output_path, 'wb') as output_file:
        for i in range(num_chunks):
            chunk_file = os.path.join(temp_dir, f'chunk_{i}')
            if os.path.exists(chunk_file):
                with open(chunk_file, 'rb') as chunk:
                    output_file.write(chunk.read())
                os.remove(chunk_file)

def axel_like_download(url, base_output_dir, num_connections=4, max_size_mb=100):
    parsed = urlparse(url)
    path_parts = parsed.path.strip("/").split("/")
    
    if not path_parts or path_parts[-1] == "":
        filename = "downloaded_file"
    else:
        filename = path_parts[-1]
    
    sub_dir = os.path.join(base_output_dir, *path_parts[:-1])
    os.makedirs(sub_dir, exist_ok=True)

    output_path = os.path.join(sub_dir, filename)
    temp_dir = os.path.join(sub_dir, f'.{filename}_temp')

    if os.path.isfile(output_path):
        print(f"[+] Skipping {output_path} (already exists)")
        return True

    os.makedirs(temp_dir, exist_ok=True)

    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }

        file_size = get_file_size(url, headers)
        if file_size == 0:
            print(f"[!] Could not determine file size for {url}")
            return single_connection_download(url, output_path, headers)

        # Skip files larger than 100MB
        MAX_SIZE = max_size_mb * 1024 * 1024
        if file_size > MAX_SIZE:
            #print(f"[!] Skipping {url} (size {file_size:,} bytes exceeds {max_size_mb}MB limit)")
            print(f"\033[92m[!] Skipping {url} (size {file_size:,} bytes exceeds {max_size_mb}MB limit)\033[0m")
            return False

        if not supports_range_requests(url, headers):
            print(f"[!] Server doesn't support range requests, using single connection")
            return single_connection_download(url, output_path, headers)

        print(f"[+] Starting {num_connections}-connection download of {filename} ({file_size:,} bytes)")

        chunk_size = (file_size + num_connections - 1) // num_connections
        chunks = [(i * chunk_size, min((i + 1) * chunk_size - 1, file_size - 1), i) for i in range(num_connections)]

        with tqdm(
            desc=f"Downloading {filename}",
            total=file_size,
            unit='B',
            unit_scale=True,
            unit_divisor=1024,
            leave=True,
            dynamic_ncols=True
        ) as pbar:
            with ThreadPoolExecutor(max_workers=num_connections) as executor:
                futures = [
                    executor.submit(download_chunk, url, start, end, chunk_id, temp_dir, headers, pbar)
                    for start, end, chunk_id in chunks
                ]
                success = all(future.result() for future in as_completed(futures))

        if success:
            combine_chunks(temp_dir, output_path, num_connections)
            print(f"[+] Downloaded: {output_path}")
            try: os.rmdir(temp_dir)
            except: pass
            return True
        else:
            print(f"[!] Some chunks failed for {output_path}")
            return False

    except Exception as e:
        print(f"[!] Error downloading {url}: {e}")
        return False
    finally:
        try:
            for file in os.listdir(temp_dir):
                os.remove(os.path.join(temp_dir, file))
            os.rmdir(temp_dir)
        except:
            pass

def single_connection_download(url, output_path, headers):
    try:
        with http.request('GET', url, preload_content=False, headers=headers) as resp:
            if resp.status != 200:
                print(f"[!] Failed to download {url} (HTTP {resp.status})")
                return False

            total_size = int(resp.headers.get('Content-Length', 0))

            with open(output_path, 'wb') as f:
                with tqdm(
                    desc=f"Downloading {os.path.basename(output_path)}",
                    total=total_size,
                    unit='B',
                    unit_scale=True,
                    unit_divisor=1024,
                    leave=True,
                    dynamic_ncols=True
                ) as pbar:
                    for chunk in resp.stream(64 * 1024):
                        if chunk:
                            f.write(chunk)
                            pbar.update(len(chunk))
        return True
    except Exception as e:
        print(f"[!] Error in single connection download: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Multi-threaded file downloader")
    parser.add_argument("-f", "--file", required=True, help="File containing list of URLs")
    parser.add_argument("-o", "--output", default=".", help="Directory to save downloaded files")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Number of download threads")
    parser.add_argument(
        "--max-size",
        type=int,
        default=100,
        help="Maximum file size to download in MB (default: 100)"
    )
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    with open(args.file, "r") as f:
        urls = list(set(line.strip() for line in f if line.strip()))

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(axel_like_download, url, args.output, args.threads, args.max_size) for url in urls]
        for _ in as_completed(futures):
            pass

if __name__ == "__main__":
    main()
