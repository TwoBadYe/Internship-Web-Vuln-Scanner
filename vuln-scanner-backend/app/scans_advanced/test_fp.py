# app/scans_advanced/test_fp.py
import asyncio, importlib, httpx, os

async def main():
    print("cwd:", os.getcwd())
    fp = importlib.import_module("app.scans_advanced.fingerprint")
    print("fingerprint module:", fp.__file__)
    # show available attrs for quick debug
    print("module attrs:", [a for a in dir(fp) if not a.startswith("_")])
    if hasattr(fp, "run"):
        async with httpx.AsyncClient(verify=False, timeout=20.0) as client:
            results = await fp.run("http://testphp.vulnweb.com/", client)
            print("\n--- Fingerprinting Results ---")
            for r in results:
                print(r)
    else:
        print("No run() function found in module")

if __name__ == "__main__":
    asyncio.run(main())
