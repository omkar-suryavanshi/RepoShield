
import os

def read_user_file(filename):
    path = "files/" + filename
    with open(path, "r") as file:
        return file.read()

user_file = input("Enter filename: ")
print(read_user_file(user_file))
