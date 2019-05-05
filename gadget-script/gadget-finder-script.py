import glob, os
import subprocess

# CHANGE VAR to change directory
#DIRECTORY_TO_ANALYZE = '/mnt/f/Results/TscanCode/v500'
DIRECTORY_TO_ANALYZE = '/mnt/f/UnrealClangTest/Platformer-v500'
gadgets = 0

# Gadgets to ignore, since they do nothing
not_actual_gadgets = [
    "nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop ; ret",
    "nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop ; ret",
    "nop ; nop ; nop ; nop ; nop ; nop ; nop ; ret",
    "nop ; nop ; nop ; nop ; nop ; nop ; ret",
    "nop ; nop ; nop ; nop ; nop ; ret",
    "nop; nop ; nop ; nop ; ret",
    "nop ; nop ; nop ; ret",
    "nop ; nop ; ret",
    "nop ; ret",
]


def print_gadget_count(file):

    # Uncomment for ROPGadget.py -> https://github.com/JonathanSalwan/ROPgadget
    # out = subprocess.Popen(['python',
    #                         '/mnt/f/ROPgadget/ROPgadget.py',
    #                         '--binary',
    #                        file,
    #                         '--rawArch=x86',
    #                         '--rawMode=64',
    #                         '--nojop'],
    #                        stdout=subprocess.PIPE,
    #                        stderr=subprocess.STDOUT)



    out = subprocess.Popen(['python',
                            '/mnt/f/Ropper/Ropper.py',
                            '--raw',
                            '-a',
                            'x86_64',
                            '--type',
                            'rop',
                            '--file',
                            file],
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)

    stdout, stderr = out.communicate()

    gadgets = 0
    for line in stdout.splitlines():
        if line.strip() == "":
            continue
        if "0x" not in line.split()[0]:
            continue
        elif "ret" in line.split()[2]:
            # Eliminate simple ret instructions
            continue
        elif line.split(":")[1].strip() in not_actual_gadgets:
            continue
        else:
            gadgets += 1
    print(file + " -> Gadget Count: " + str(gadgets))
    return gadgets

total_size = 0
total_gadgets = 0

# find object files to analze
os.chdir(DIRECTORY_TO_ANALYZE)
for file in glob.glob("*.o"):
    total_gadgets += print_gadget_count(file)
    total_size += os.path.getsize(file)

print("\nTotal Gadgets = " + str(total_gadgets))
print("Total File Size (in KB) = " + str(total_size/1000.00))