import os, sys

home_dir = os.getenv('APPDATA')
log_file = os.path.join(home_dir, "Armory\\ArmoryQt.exe.log")

sys.stdout = open(“my_stdout.log”, “w”)
sys.stderr = open(“my_stderr.log”, “w”)
