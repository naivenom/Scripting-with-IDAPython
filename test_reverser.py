def _main():
	ea = idc.ScreenEA()
	print "0x%x %s" % (ea,ea)


def _debug(addr):
	idc.RunTo(BeginEA())
	idc.AddBpt(addr) #breakpoint	
	idc.GetDebuggerEvent(WFNE_SUSP,-1)
	idc.RunTo(addr)


def _help():
	print("""Functions:
		_debug(addr)
		_sum(addr)
		_check(addr)""")

def _sum(addr): 
	#get len of user
	GetDebuggerEvent(WFNE_SUSP, -1)    
	print("Value of length is: ")
	len_ = idc.GetRegValue('EAX')
	print(len_)
	print(type(len_))
	for i in range(0,len_): #loop to get byte to byte sum
		idc.GetDebuggerEvent(WFNE_SUSP,-1)
		idc.RunTo(addr)
	idaapi.step_into()
	GetDebuggerEvent(WFNE_SUSP, -1)    
	print("Value of sum is: ")
	print(idc.GetRegValue('EAX'))
	GetDebuggerEvent(WFNE_SUSP, -1)  
	idc.RunTo(0x00d3110e)

def _check(addr):
	idc.GetDebuggerEvent(WFNE_SUSP,-1)
	idc.RunTo(addr)
	idaapi.step_into()
	GetDebuggerEvent(WFNE_SUSP, -1) 
	#shl eax,1 ==> multiply by two
	ebp_ = idc.GetRegValue('ebp')
	ebp_8 = ebp_+8
	print("Value of password is: ")
	password = idc.Dword(ebp_8)
	print(password/2)

	

if __name__ == '__main__':
	#_main()
	#_debug(addr)
	#_sum(addr)
	#_check(addr)
	_help()

	"""PoC
	_debug(0x00D310C8) 		mov     [ebp+var_90], eax
	_sum(0x00d31108) 		mov     [ebp+var_88], eax
	_check(0x00D31018)		cmp     [ebp+arg_0], eax
	"""
