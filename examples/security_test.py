
import os
import pickle
import subprocess

user_input = input("Enter a command: ")
os.system(user_input)

data = pickle.loads(b"example")
subprocess.run(["echo", "Hello"])
