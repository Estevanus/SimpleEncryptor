import sys
import random


seed = "test-1"#pake sebagai password jo noh ini ee
encode = "ascii"
penutubHeader = 0, 1
panjangByte = 1


filename = 'source.ossec'
output_filename = 'source1.txt'

pb = penutubHeader[0].to_bytes(penutubHeader[1], 'little')
maxLength = 2**(panjangByte * 8)

def dekompres(b):
	print(' -------------------------------------------- ')
	print(' -------------------------------------------- ')
	print("hasil dekripsinya ialah >>" + str(b))

	b1 = b.split(pb)
	print("hasil splitnya ialah>>" + str(b1))

	state = False
	peta = []
	peta2d = []
	seb = 0
	l = []
	for i in b1[0]:
		l.append(i)
		if state == False:
			state = True
			seb = i
		else:
			state = False
			peta2d.append([seb, i])
			for j in range(i):
				peta.append(seb)
	print(' -------------------------------------------- ')
	print(' -------------------------------------------- ')
	print("map >>" + str(peta))
	print("byte of map>>" + str(b1[0]))
	#print("map >>" + str(peta2d))

	cek = len(peta), len(b1[1])
	print(cek)

	print(' -------------------------------------------- ')
	print(' ---------------decompressing---------------- ')
	print(' -------------------------------------------- ')

	l = []
	for i in range(len(b1[1])):
		for j in range(peta[i]):
			l.append(b1[1][i])
			
	print("sebelum di join>>" + str(l))
	hasil = bytearray(l)
	print('sesudah di join>>' + str(hasil))
	print(' -------------------------------------------- ')
	return hasil

def startDecrypt():
	#creating a dictionary base on seed/password
	sb = seed.encode(encode)
	random.seed(sb)
	l = []
	for i in range(maxLength):
		l.append(i)
	kamus = {}
	for i in range(maxLength):
		terpilih = int(random.random() * len(l))
		kamus[l[terpilih]] = i
		del l[terpilih]
		
	#print("kamus>>" + str(kamus))
		
		
	size = sys.getsizeof
	f = open(filename, 'rb')
	source = f.read()
	f.close()

	print("source >> " + str(source))
	print("ukuran sourcenya ialah " + str(size(source)) + " bytes")
	print("panjang alfabetnya ialah " + str(len(source)))



	#memulai proses dekripsi
	l = []
	for i in source:
		l.append(kamus[i])
		
	b = bytearray(l)
	hasil = dekompres(b)
	print('writing to text file...')

	f = open(output_filename, 'wb')
	f.write(hasil)
	f.close()

	print('done')
	
if len(sys.argv) > 0:
	if sys.argv[1] == "help":
		pass
		#show help
	else:
		if len(sys.argv) == 4:
			filename = sys.argv[1]
			output_filename = sys.argv[2]
			seed = sys.argv[3]
			
			#print([filename, output_filename, seed])
			startDecrypt()
		else:
			print("you need to specified source file, output file, and password")
else:
	print("you need to specified source file, output file, and password")
	

