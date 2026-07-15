import os

def get_paths():
    infile = input("Input file (winmain_rome_addresses.txt): ") or "winmain_rome_addresses.txt"
    if infile.startswith("file://"):
        infile = infile[7:]
    base, ext = os.path.splitext(infile)
    outfile = f"{base}_dedup{ext}"
    return infile, outfile

def deduplicate_file(infile, outfile):
    with open(infile, "r") as f:
        lines = set(f.readlines())
    with open(outfile, "w") as f:
        f.writelines(lines)

def main():
    infile, outfile = get_paths()
    deduplicate_file(infile, outfile)
    print("Done")

if __name__ == "__main__":
    main()
