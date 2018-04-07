def help():
	print("""Classes:
		recon()
			Methods:
				.segments()==> 	Segments
				.functions()==>	Functions Name
				.strings()==> 	Strings
				.disamFunction(addr) ==> Disassembly functions
				.disamString(addr) ==> Disassembly string data references to Code
				.FindFunction(addr) ==> Find function through a memory address
				.FindString(string)=> Find a particulary string and disasm it
		discover()
			Methods:
				Inherit recon class methods
				.Dbg(addr) ==> 	Run Debugger and set breakpoint a specific address
				.staticString(string)==> Start enumeration discover through string point
				.staticJump(addr,string) ==> Continue enumeration discover throught jump instruction point
				.dbgCalls(addr) ==> Discover debugging calls and get value of Registers
				.dbgRegisters(addr,register) ==> Discover debugging a specific Register in a particular function""")


class recon():

	def __init__(self):
		self.ea = BeginEA()

	def segments(self):
		for segments in Segments():
			print idc.SegName(segments), idc.SegStart(segments), idc.SegEnd(segments)

	def functions(self):
		for func in Functions(SegStart(self.ea), SegEnd(self.ea)):
			print(hex(func), GetFunctionName(func))
		

	def strings(self):
		sc = Strings()
		for s in sc:
			print "%x: len=%d type=%d --> '%s'" % (s.ea, s.length, s.type, str(s))

	def disamFunction(self,addr):
		func = idaapi.get_func(addr)
		print "Start: 0x%x, End: 0x%x\n" % (func.startEA, func.endEA)
		diss = list(FuncItems(addr))
		for i in diss:
			print "%x" % i , GetDisasm(i)
		
		
		
	def disamString(self,addr):
		print hex(addr), idc.GetDisasm(addr), "\n"
		print("DataRefsTo:")
		for a in DataRefsTo(addr):
			print hex(a), GetDisasm(a)

	def FindFunction(self,addr):
		for seg in Segments():
			for func in Functions(seg, SegEnd(seg)):
				functionName = GetFunctionName(func)
				for (start, end) in Chunks(func):
					for head in Heads(start, end):
						if hex(head)[:-1] == hex(addr):
							print "Function Name: ", functionName
							#, ":", hex(head)[:-1], ":", GetDisasm(head)

	def FindString(self,string):
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

	def Dbg(self,addr):
		idc.RunTo(self.ea)
		idc.AddBpt(addr) #breakpoint	
		idc.GetDebuggerEvent(WFNE_SUSP,-1)
		idc.RunTo(addr)

	def staticString(self,string):
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

	def staticJump(self,addr,jump):
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

	def dbgCalls(self,addr):
		count = 0
		for seg in Segments():
			for func in Functions(seg, SegEnd(seg)):
				functionName = GetFunctionName(func)
				for (start, end) in Chunks(func):
					for head in Heads(start, end):
						if hex(head)[:-1] == hex(addr):
							print "Function Name: ", functionName
							#, ":", hex(head)[:-1], ":", GetDisasm(head)
							diss = list(FuncItems(addr))
							print "[+]Call:"
							for i in diss:
								#print "%x" % i , GetDisasm(i).split()
								if GetDisasm(i).split()[0] == "call":
									if GetDisasm(i).split()[1][:1] == "s":
										print hex(i), GetDisasm(i)
										print "[+]Call %d fuction" % count
										idc.GetDebuggerEvent(WFNE_SUSP,-1)
										idc.RunTo(i)
										idc.AddBpt(i) #breakpoint
										idaapi.step_into()	
										idc.GetDebuggerEvent(WFNE_SUSP,-1)
										print("EAX: ",hex(idc.GetRegValue('EAX')))
										print(hex(idc.GetRegValue('EAX')),GetDisasm(idc.GetRegValue('EAX')))
										print("ESI: ",hex(idc.GetRegValue('ESI')))
										print(hex(idc.GetRegValue('ESI')),GetDisasm(idc.GetRegValue('ESI')))
										print("EBX: ",hex(idc.GetRegValue('EBX')))
										print(hex(idc.GetRegValue('EBX')),GetDisasm(idc.GetRegValue('EBX')))
										print("EDX: ",hex(idc.GetRegValue('EDX')))
										print(hex(idc.GetRegValue('EDX')),GetDisasm(idc.GetRegValue('EDX')))
										print("EBP: ",hex(idc.GetRegValue('EBP')))
										print(hex(idc.GetRegValue('EBP')),GetDisasm(idc.GetRegValue('EBX')))
										print("EDI: ",hex(idc.GetRegValue('EDI')))
										print(hex(idc.GetRegValue('EDI')),GetDisasm(idc.GetRegValue('EDI')))
										print("EIP: ",hex(idc.GetRegValue('EIP')))
										print(hex(idc.GetRegValue('EIP')),GetDisasm(idc.GetRegValue('EIP')))
										print("ESP: ",hex(idc.GetRegValue('ESP')))
										print(hex(idc.GetRegValue('ESP')),GetDisasm(idc.GetRegValue('ESP')))
										idc.GetDebuggerEvent(WFNE_SUSP,-1)
										count+=1
	
	def dbgRegisters(self,addr,register):
		count = 0
		for seg in Segments():
			for func in Functions(seg, SegEnd(seg)):
				functionName = GetFunctionName(func)
				for (start, end) in Chunks(func):
					for head in Heads(start, end):
						if hex(head)[:-1] == hex(addr):
							print "Function Name: ", functionName
							diss = list(FuncItems(addr))
							print "[+]%s:" %register
							for i in diss:
								#print "%x" % i , GetDisasm(i).split()
								try:
									if GetDisasm(i).split()[1] == register or GetDisasm(i).split()[1] == register+"," or GetDisasm(i).split()[2] == register or GetDisasm(i).split()[2] == "["+register+"]":
										print "%x" % i , GetDisasm(i)
										print "[+]Instruction %d %s" % (count,register)
										idc.GetDebuggerEvent(WFNE_SUSP,-1)
										idc.RunTo(i)
										idc.AddBpt(i) #breakpoint
										idaapi.step_into()	
										idc.GetDebuggerEvent(WFNE_SUSP,-1)
										print("%s: "%register,hex(idc.GetRegValue(register)))
										print(hex(idc.GetRegValue(register)),GetDisasm(idc.GetRegValue(register)))
										count+=1
								except IndexError:
									pass
								
										
										
										

		

if __name__ == '__main__':
	#recon()
	#discover()
	help()
