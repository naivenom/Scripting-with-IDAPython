def help():
	print("""Classes:
		recon()
			Methods:
				.S() 	  ==> 		Segments
				.f()	  ==>		Functions Name
				.s()	  ==> 		Strings
				.df(addr) ==> 		Disassembly functions
				.ds(addr) ==> 		Disassembly string data references to Code
				.Ff(addr) ==> 		Find function through a memory address
				.Fs(string)=> 		Find a particulary string and disasm it
		discover()
			Methods:
				Inherit recon class methods
				.Db(addr) ==> 		Run Debugger and set breakpoint a specific address
				.es(string)==> 		Start enumeration discover through string point
				.ej(addr,string) ==>Continue enumeration discover throught jump instruction point """)


class recon():

	def __init__(self):
		self.ea = BeginEA()

	def S(self):
		for segments in Segments():
			print idc.SegName(segments), idc.SegStart(segments), idc.SegEnd(segments)

	def f(self):
		for func in Functions(SegStart(self.ea), SegEnd(self.ea)):
			print(hex(func), GetFunctionName(func))
		

	def s(self):
		sc = Strings()
		for s in sc:
			print "%x: len=%d type=%d --> '%s'" % (s.ea, s.length, s.type, str(s))

	def df(self,addr):
		func = idaapi.get_func(addr)
		print "Start: 0x%x, End: 0x%x\n" % (func.startEA, func.endEA)
		diss = list(FuncItems(addr))
		for i in diss:
			print "%x" % i , GetDisasm(i)
		
		
		
	def ds(self,addr):
		print hex(addr), idc.GetDisasm(addr), "\n"
		print("DataRefsTo:")
		for a in DataRefsTo(addr):
			print hex(a), GetDisasm(a)

	def Ff(self,addr):
		for seg in Segments():
			for func in Functions(seg, SegEnd(seg)):
				functionName = GetFunctionName(func)
				for (start, end) in Chunks(func):
					for head in Heads(start, end):
						if hex(head)[:-1] == hex(addr):
							print "Function Name: ", functionName
							#, ":", hex(head)[:-1], ":", GetDisasm(head)

	def Fs(self,string):
		self.ea = MinEA()
		end = MaxEA()
		while self.ea < end:
			self.ea = idc.FindText(self.ea, SEARCH_DOWN, 0, 0, string)
			if self.ea == idc.BADADDR:
				break
			else:
				if idc.isCode(idc.GetFlags(self.ea)) == True:
					print "CODE: ", hex(self.ea), idc.GetDisasm(self.ea)
				if idc.isData(idc.GetFlags(self.ea)) == True:
					print "DATA: ", hex(self.ea), idc.GetDisasm(self.ea)
				if idc.isTail(idc.GetFlags(self.ea)) == True:
					print "TAIL: ", hex(self.ea), idc.GetDisasm(self.ea)
				if idc.isUnknown(idc.GetFlags(self.ea)) == True:
					print "UNKNOWN: ", hex(self.ea), idc.GetDisasm(self.ea)
			self.ea = idc.NextHead(self.ea)

class discover():

	def __init__(self):
		self.ea = BeginEA()

	def Db(self,addr):
		idc.RunTo(self.ea)
		idc.AddBpt(addr) #breakpoint	
		idc.GetDebuggerEvent(WFNE_SUSP,-1)
		idc.RunTo(addr)

	def es(self,string):
		self.ea = MinEA()
		end = MaxEA()
		while self.ea < end:
			self.ea = idc.FindText(self.ea, SEARCH_DOWN, 0, 0, string)
			if self.ea == idc.BADADDR:
				break
			else:
				if idc.isCode(idc.GetFlags(self.ea)) == True:
					print hex(self.ea), idc.GetDisasm(self.ea)
					addr_ = hex(self.ea)
					print "[+]Address: ", addr_[:-1]
					for seg in Segments():
						for func in Functions(seg, SegEnd(seg)):
							functionName = GetFunctionName(func)
							for (start, end) in Chunks(func):
								for head in Heads(start, end):
									if hex(head)[:-1] == addr_[:-1]:
										print "[+]Function Name: ", functionName
										self.ea = MinEA()
										end = MaxEA()
										while self.ea < end:
											self.ea = idc.FindText(self.ea, SEARCH_DOWN, 0, 0, "call")
											if self.ea == idc.BADADDR:
												break
											else:
												try:
													if idc.GetDisasm(self.ea) == "call    "+functionName:
														print "[+]Reference to call function: ", hex(self.ea),idc.GetDisasm(self.ea)
														for a in CodeRefsTo(self.ea,0):
															print "[+]Reference to location:\t", hex(a), GetDisasm(a)
														SecondAddr_ = hex(a)
														print "[+]Discover second address maybe is interesting...", SecondAddr_[:-1]

												except:
													if idc.GetDisasm(self.ea) != "call    "+functionName:
														print "Sorry it isnt called function"
														
												#print idc.GetDisasm(self.ea)
											
											self.ea = idc.NextHead(self.ea)

				

			self.ea = idc.NextHead(self.ea)

	def ej(self,addr,jump):
		self.ea = MinEA()
		end = MaxEA()
		while self.ea < end:
			self.ea = idc.FindText(self.ea, SEARCH_DOWN, 0, 0, jump)
			if self.ea == idc.BADADDR:
				break
			else:
				if idc.isCode(idc.GetFlags(self.ea)) == True:
					if hex(self.ea) == hex(addr):
						print hex(self.ea), idc.GetDisasm(self.ea)
						addr_ = hex(self.ea)
						print "[+]Address: ", addr_[:-1]
						for seg in Segments():
							for func in Functions(seg, SegEnd(seg)):
								functionName = GetFunctionName(func)
								for (start, end) in Chunks(func):
									for head in Heads(start, end):
										if hex(head)[:-1] == addr_[:-1]:
											print "[+]Function Name: ", functionName
											func = idaapi.get_func(self.ea)
											print "Start: 0x%x, End: 0x%x" % (func.startEA, func.endEA)
											diss = list(FuncItems(addr))
											print "[+]Disassembly:"
											for i in diss:
												print "%x" % i , GetDisasm(i)
			self.ea = idc.NextHead(self.ea)
		

if __name__ == '__main__':
	#recon()
	#discover()
	help()
	
