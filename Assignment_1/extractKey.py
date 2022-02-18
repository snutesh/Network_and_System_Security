import sys
import string
exec(open('decryptText.py').read())

print("\n")

remove = string.punctuation
remove = remove.replace("@", "")
remove = remove.replace("#", "")
remove = remove.replace("$", "")

file1 = open("plain_text.txt","r")
plain_text = file1.read()
path = sys.argv[1]
file2 = open(path)
cipher_text = file2.read()
key_dict = {}

key_dict = dict.fromkeys(string.ascii_lowercase, None)


for i in range(len(plain_text)):
	ch1 = plain_text[i]
	ch2 = cipher_text[i]

	if ch1 not in remove:
		key_dict[ch1] = ch2
ans=[]
for i,j in key_dict.items():
	if j==None:
		ans.append("x")
	else:	
		ans.append(j)
print("".join(ans))	
file1.close()
file2.close()