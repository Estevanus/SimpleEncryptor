import sys
import random
from math import sqrt

seed = "test-1"#pake sebagai password jo noh ini ee
encode = "ascii"
penutubHeader = 0, 1
panjangByte = 1

filename = 'source.txt'
output_filename = 'source.ossec'

pb = penutubHeader[0].to_bytes(penutubHeader[1], 'little')
maxLength = 2**(panjangByte * 8)

def compreser(source):

	peta = []
	isi = []
	#isi = None
	seb = None
	for b in source:
		if seb == None:
			seb = b
			if isi == []:
				isi = [b]
				#isi = b.to_bytes(panjangByte, 'little')
				peta.append(1)
			else:
				isi.append(b)
				#isi += b.to_bytes(panjangByte, 'little')
				peta.append(1)
		else:
			if isi == None:
				isi = [b]
				#isi = b.to_bytes(panjangByte, 'little')
				peta.append(1)
			else:
				if b != seb:
					isi.append(b)
					#isi += b.to_bytes(panjangByte, 'little')
					peta.append(1)
				else:
					if peta[len(peta) - 1] < maxLength:
						peta[len(peta)-1] += 1
					else:
						peta.append(1)
			seb = b
			
	print(' -------------------------------------------- ')
	print(' -------------------------------------------- ')
	print("proses pendataan pertama:")
	print("peta >>" + str(peta))
	print("isi >>" + str(isi))
	print(' -------------------------------------------- ')
	print("memulai proses kompresi yang ke 2...")
	print(' -------------------------------------------- ')


	d2peta = []
	seb = 0
	for i in peta:
		if seb != i:
			d2peta.append([i, 1])
		else:
			if d2peta[len(d2peta) - 1][1] < maxLength:
				d2peta[len(d2peta) - 1][1] += 1
			else:
				d2peta.append([i, 1])
		seb = i
				
	print(' -------------------------------------------- ')
	print(' -------------------------------------------- ')
	print("proses pendataan ke-2 selesai")
	#print("peta >>" + str(peta))
	print("2D peta >>" + str(d2peta))
	print("isi >>" + str(isi))
	peta2dnormalized = []
	for i in d2peta:
		for j in i:
			peta2dnormalized.append(j)
	print("bytes of 2dpeta>>" + str(peta2dnormalized))

	'''
	for mo kase gabung dp integer nantinya pake fungsi bytearray(list_of_integers)
	'''
	comp = bytearray(peta2dnormalized) + pb + bytearray(isi)
	print("panjang peta = " + str(len(peta)))
	print("panjang isi = " + str(len(isi)))
	return comp

def startEncrypt():
	#creating a dictionary base on seed/password
	sb = seed.encode(encode)
	random.seed(sb)
	l = []
	for i in range(maxLength):
		l.append(i)
	kamus = {}
	for i in range(maxLength):
		terpilih = int(random.random() * len(l))
		kamus[i] = l[terpilih]
		del l[terpilih]
		
	#print("kamus>>" + str(kamus))


	size = sys.getsizeof

	f = open(filename, 'rb')
	source = f.read()
	f.close()

	#print("source >> " + str(source))
	print("ukuran sourcenya ialah " + str(size(source)) + " bytes")
	print("panjang alfabetnya ialah " + str(len(source)))


	comp = compreser(source)
	
	#memulai proses compresi tambahan
	pa = len(comp)
	squareLength = int(sqrt(pa))
	sisah = pa % squareLength
	
	
	
	print(' -------------------------------------------- ')
	print("compressed>>" + str(comp))


	enc = []
	for i in comp:
		enc.append(kamus[i])
		
	hasil_enkripsi = b'' + bytearray(enc)
	print(' -------------------------------------------- ')
	print(' -------------------------------------------- ')
	print("hasil setelah terenkripsi ialah " + str(hasil_enkripsi))

	f = open(output_filename, 'wb')
	f.write(hasil_enkripsi)
	f.close()
	print('done encrypting')



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
			startEncrypt()
		else:
			print("you need to specified source file, output file, and password")
else:
	print("you need to specified source file, output file, and password")








