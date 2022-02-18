import sys
import re
import random
import string
from math import log10

tri_grams = {}
file1 = open('trigrams.txt')
for line in file1:
	key, val = line.split(' ')
	tri_grams[key] = int(val)
	key_len = len(key)
sum_all = sum(tri_grams.values())
list1 = list(tri_grams.keys())
for key in list1:
	temp2 = float(tri_grams[key])/sum_all
	tri_grams[key] = log10(temp2)
net_val = log10(0.01/sum_all)

def preprocessing():
	remove = string.punctuation
	remove = remove.replace("@", "")
	remove = remove.replace("#", "")
	remove = remove.replace("$", "")
	pattern = r"[{}]".format(remove)
	temp = re.sub(pattern, "", temp)
	cipher_words = temp.split(' ')

def getplaintext():
	plain_text2 = ""
	i = 0
	j = 0
	punt_list = list(remove)
	while j<len(plain_text):
		ch1 = cipher_text[i]
		ch2 = plain_text[j]
		if ch1 not in punt_list:
			plain_text2 = plain_text2 + "".join(ch2)
			i = i + 1
			j = j + 1
		else:
			plain_text2 = plain_text2 + "".join(ch1)
			i = i + 1

def fit_score(text):
	score = 0
	range_cal = len(text) - key_len + 1
	for i in range(range_cal):
		tri_gram = text[i:i+key_len].upper()
		if tri_gram in tri_grams:
			score = score + tri_grams[tri_gram]
		else:
			score = score + net_val
	return score

path = sys.argv[1]
file2 = open(path, 'r')
cipher_text = file2.read()
temp = cipher_text
remove = string.punctuation
remove = remove.replace("@", "")
remove = remove.replace("#", "")
remove = remove.replace("$", "")
pattern = r"[{}]".format(remove)
temp = re.sub(pattern, "", temp)
cipher_words = temp.split(' ')

cipher = list(set(temp.replace(' ', '')))
key = string.ascii_lowercase

def cal_score(key):
    dic_dec = dict(zip(cipher, key))
    grades = 0
    for word in cipher_words:
        temp_str = [dic_dec.get(l, '') for l in word]
        decipher_word = "".join(temp_str)
        temp_score = fit_score(decipher_word)
        grades = grades + temp_score
    return grades

def decryption(cipher, key, cipher_words):
    decr = dict(zip(cipher, key))
    message = " ".join(["".join([decr.get(l, '') for l in word]) for word in cipher_words])
    return message

def randomize(key):
    swap_key = list(key)
    a = random.randint(0, len(key)-1)
    b = random.randint(0, len(key)-1)
    swap_key[b], swap_key[a] = swap_key[a], swap_key[b]
    return "".join(swap_key)

random_score = 1.0
count = 0
plain_text = ""
grades = -1000000
limit = 0.9998
max_grades = grades
while count < 10000:
    new_key = randomize(key)
    p = cal_score(new_key)
    if p > grades:
        if p > max_grades:
            max_grades = p
            plain_text = decryption(cipher, new_key, cipher_words)
        key = new_key
        grades = p
        count = 0
    else:
        if random.random() < random_score:
            grades = p
            key = new_key
        count = count + 1
    random_score = random_score * limit

plain_text2 = ""
i = 0
j = 0
punt_list = list(remove)
while j<len(plain_text):
	ch1 = cipher_text[i]
	ch2 = plain_text[j]
	if ch1 not in punt_list:
		plain_text2 = plain_text2 + "".join(ch2)
		i = i + 1
		j = j + 1
	else:
		plain_text2 = plain_text2 + "".join(ch1)
		i = i + 1

file3 = open('plain_text.txt','w')
file3.write(plain_text2)


key_dict = {}

key_dict = dict.fromkeys(string.ascii_lowercase, None)


for i in range(len(plain_text2)):
	ch1 = plain_text2[i]
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