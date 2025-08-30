import asyncio,importlib

# Fake detections (this simulates what your fingerprinting module would return)
cl = importlib.import_module("app.scans_advanced.cve_lookup")
sample_detections = [
    {
        "product": "Apache",
        "version": "2.4.49",
        "evidence": "Server header: Apache/2.4.49"
    },
    {
        "product": "OpenSSL",
        "version": "1.0.1",
        "evidence": "Detected in TLS handshake"
    },
    {
        "product": "nginx",
        "version": "1.18.0",
        "evidence": "Server header: nginx/1.18.0"
    },
]

def sync_test():
    print("=== Running sync CVE lookup ===")
    results = cl.lookup(sample_detections)
    if results:
        for r in results:
            print(r)
    else:
        print("No high/critical CVEs found.")

async def async_test():
    print("\n=== Running async run() ===")
    results = await cl.run("http://testphp.vulnweb.com/")
    for r in results:
        print(r)

if __name__ == "__main__":
    # Test the lookup directly
    sync_test()

    # Optionally also test the async run wrapper
    asyncio.run(async_test())
