import os
import sys
import subprocess

def poorly_formatted( x,y ):
    z=x+y
    subprocess.Popen("echo " + str(z), shell=True)
    return  z

print(poorly_formatted(1, 2))
