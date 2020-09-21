import sys
import json
import os

class CipherSuites:
	def __init__(self, file):
		self.f = None
		self.offset = 0
		css_path = os.path.dirname(os.path.abspath(__file__)) + '/ciphersuites.json'
		with open(css_path, 'r') as f:
			self.ciphersuites = json.load(f)
		self.f = open(file, 'rb')
		return

	def setOffset(self, offset):
		self.offset = offset
		return

	def getOffset(self):
		return self.offset

	def searchOffset(self):
		candidate_offset = 0
		candidate_size = 0
		self.f.seek(0, 0)
		while True:
			val = self.f.read(1)
			if (len(val) != 1):
				break
			if val == b'\x00':
				offset = self.f.tell()
				size = self.f.read(1)
				if (len(size) != 1):
					break
				size = int.from_bytes(size, byteorder='big')/2
				cs_size = self.__getCipherSuitesSize()
				if size <= cs_size:
					if candidate_size < size:
						candidate_size = size
						candidate_offset = offset
				self.f.seek(offset, 0)
		self.offset = candidate_offset

	def printCipherSuites(self):
		self.f.seek(self.offset, 0)
		num = int.from_bytes(self.f.read(1), byteorder='big')
		for i in range(int(num/2)):
			code_h = "0x"+self.f.read(1).hex().upper()
			code_l = "0x"+self.f.read(1).hex().upper()
			cs = self.__getCipherSuite(code_h, code_l)
			print(cs['code'], end=" ")
			print(cs['name']+" ", end="")
			print(cs['version'], end=" ")
			print(cs['status'], end="\n")
		return

	def __getCipherSuite(self, code_h, code_l):
		for cs in self.ciphersuites:
			if cs['code'][0] == code_h and cs['code'][1] == code_l:
				return cs
		return None

	def __getCipherSuitesSize(self):
		size = 0
		last_vals = [0xff, 0xff]
		while True:
			vals = self.f.read(2)
			if len(vals) != 2:
				break
			if last_vals == vals:
				continue
			last_vals = vals
			code_h = "0x"+'{:02x}'.format(vals[0]).upper()
			code_l = "0x"+'{:02x}'.format(vals[1]).upper()
			if self.__getCipherSuite(code_h, code_l) != None:
				size += 1
			else:
				break
		return size

def main():
		if len(sys.argv) == 2:
			try:
				cs = CipherSuites(sys.argv[1])
				cs.searchOffset()
				cs.printCipherSuites()
			except FileNotFoundError:
				print('file not found')
		else:
			print('usage: python3 {} packet.bin'.format(__file__))

if __name__ == "__main__":
	main()

