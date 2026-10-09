import os

FOLDER_PATH = r"C:\Users\GAYATHRI\Downloads\spring cloud\spring cloud"

TEXT_EXTENSIONS = {
    ".java",
    ".xml",
    ".properties",
    ".yml",
    ".yaml",
    ".json",
    ".txt",
    ".md",
    ".sql",
    ".html",
    ".css",
    ".js",
    ".py"
}

for root, dirs, files in os.walk(FOLDER_PATH):

    print("\n" + "=" * 100)
    print("FOLDER:", root)
    print("=" * 100)

    for file in files:

        file_path = os.path.join(root, file)

        print("\nFILE:", file_path)

        extension = os.path.splitext(file)[1].lower()

        if extension in TEXT_EXTENSIONS:

            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                print("-" * 100)
                print(content)
                print("-" * 100)

            except Exception as e:
                print("Could not read file:", e)

        else:
            print("[Binary/unsupported file - skipped]")