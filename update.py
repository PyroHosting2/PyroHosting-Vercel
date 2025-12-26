import subprocess
import sys
import os

TYPES = {
    "1": "🐛 Bugfix",
    "2": "✨ Feature",
    "3": "🔄 Update",
    "4": "🚑 Hotfix",
    "5": "📝 Change",
}

def pause():
    try:
        import msvcrt
        print("\nDrücke eine Taste zum Fortfahren...")
        msvcrt.getch()
    except ImportError:
        try:
            input("\nEnter zum Fortfahren...")
        except EOFError:
            pass

def run(cmd):
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        print(f"❌ Fehler bei: {cmd}")
        pause()
        sys.exit(1)

def ensure_git_repo():
    result = subprocess.run(
        "git rev-parse --is-inside-work-tree",
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=True
    )
    if result.returncode != 0:
        print("❌ Kein Git-Repository gefunden.")
        print("➡ Starte das Script im Root deines Git-Projekts.")
        pause()
        sys.exit(1)

print("=" * 30)
print("  Git Update / Publish Tool")
print("=" * 30)
print()

# ✅ WICHTIG: Git-Check ganz am Anfang
ensure_git_repo()

print("Was hast du gemacht?")
for k, v in TYPES.items():
    print(f"[{k}] {v}")

choice = input("\nAuswahl (1-5): ").strip()
if choice not in TYPES:
    print("❌ Ungültige Auswahl.")
    pause()
    sys.exit(1)

desc = input("Beschreibe kurz das Update: ").strip()
if not desc:
    print("❌ Beschreibung darf nicht leer sein.")
    pause()
    sys.exit(1)

commit_msg = f"{TYPES[choice]}: {desc}"

print("\n" + "=" * 30)
print("Commit Message:")
print(commit_msg)
print("=" * 30)

pause()

run("git add .")
run(f'git commit -m "{commit_msg}"')
run("git push")

print("\n✅ Erfolgreich gepusht!")
pause()
