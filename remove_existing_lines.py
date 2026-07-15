existing = input("List of lines to remove (old.txt): ") or "old.txt"
out_file = input("List to remove from (functions_listed.txt): ") or "functions_listed.txt"

def remove_duplicate_lines():
    try:
        with open(existing, "r", encoding="utf-8") as file:
            exclude_lines = set(file.read().splitlines())
    except FileNotFoundError:
        exclude_lines = set()
    try:
        with open(out_file, "r", encoding="utf-8") as file:
            source_lines = file.read().splitlines()
    except FileNotFoundError:
        return
    unique_lines = [line for line in source_lines if line not in exclude_lines]
    with open(out_file, "w", encoding="utf-8") as file:
        file.write("\n".join(unique_lines) + "\n")

if __name__ == "__main__":
    remove_duplicate_lines()
    print("Done")
