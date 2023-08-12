# Name: VTableDump.py
# Version: 1.0.0
# Author: RenardDev (zeze839@gmail.com)

# IDA imports
import ida_idaapi
import ida_ida
import ida_name
import ida_bytes
import ida_pro
import ida_auto
import ida_hexrays
import idaapi
import idc

# Python imports
import re

def IsNotValidAddress(address):
	if (address == 0) | (address == ida_idaapi.BADADDR):
		return True
	return False

def FindVTableFunctions(address):
	functions = []
	vtable_size = 0
	min_address = ida_ida.inf_get_min_ea()
	max_address = ida_ida.inf_get_max_ea()
	while True:
		if ida_idaapi.get_inf_structure().is_64bit():
			function_ptr = ida_bytes.get_qword(address + vtable_size)
		else:
			function_ptr = ida_bytes.get_dword(address + vtable_size)
		if IsNotValidAddress(function_ptr) | ida_bytes.is_data(ida_bytes.get_flags(function_ptr)) | (function_ptr >= max_address) | (function_ptr <= min_address):
			break
		functions.append(function_ptr)
		if ida_idaapi.get_inf_structure().is_64bit():
			vtable_size += 8
		else:
			vtable_size += 4
	return functions

class VTableDump(ida_idaapi.plugin_t):
	flags = ida_idaapi.PLUGIN_MOD
	wanted_name = 'VTableDump'
	wanted_hotkey = 'Ctrl+Shift+M'
	comment = 'VTableDump - Signature Generator.\n'
	help = ''

	def init(self):
		if ida_pro.IDA_SDK_VERSION < 770:
			idc.msg('[VTableDump] Error: Optimal IDA version for VTableDump is 7.7.\n')
			return ida_idaapi.PLUGIN_SKIP
		return ida_idaapi.PLUGIN_KEEP

	def term(self):
		pass

	def run(self, arg):
		if ida_auto.auto_is_ok() != True:
			idc.msg('[VTableDump] Error: The analysis is not finished!\n')
			return

		if ida_hexrays.init_hexrays_plugin() != True:
			idc.msg('[VTableDump] Error: Failed to initialize hexrays plugin!\n')
			return

		current_address = idc.here()
		if ida_bytes.is_data(ida_bytes.get_flags(current_address)) != True:
			idc.msg('[VTableDump] Error: The cursor is not on the data!\n')
			return

		ready_functions = []

		class_name = 'UnknownClass'

		functions = FindVTableFunctions(current_address)
		if functions:
			sub_functions = 1
			non_decompilable = 1
			for function in functions:
				try:
					decompiled_function = ida_hexrays.decompile(function)
				except ida_hexrays.DecompilationFailure:
					idc.msg('[VTableDump] Error: Failed to decompile VTable!\n')
					return
				if decompiled_function:
					#calling_convention = ''
					#function_type_data = idaapi.func_type_data_t()
					#if decompiled_function.type.get_func_details(function_type_data):
					#	if function_type_data.cc == idaapi.CM_CC_CDECL:
					#		calling_convention = '__cdecl'
					#	elif function_type_data.cc == idaapi.CM_CC_STDCALL:
					#		calling_convention = '__stdcall'
					#	elif function_type_data.cc == idaapi.CM_CC_THISCALL:
					#		calling_convention = '__fastcall'
					#	elif function_type_data.cc == idaapi.CM_CC_FASTCALL:
					#		calling_convention = '__fastcall'

					return_type = decompiled_function.type.get_rettype().dstr()
					args = [ decompiled_function.type.get_nth_arg(x) for x in range(1, decompiled_function.type.get_nargs()) ]

					return_type = '*'.join(return_type.rsplit(' *'))
					if return_type == '_BOOL4':
						return_type = 'bool'
					elif return_type == '_DWORD*':
						return_type = 'void*'

					function_name = ida_name.get_demangled_name(function, ida_name.M_PRCMSK | ida_name.MT_LOCALNAME, 0, ida_name.GN_DEMANGLED | ida_name.GN_STRICT | ida_name.GN_LOCAL)
					function_name_parts = function_name.rsplit('::')
					if function_name_parts:
						function_name = function_name_parts[-1]
					if function_name == '`scalar deleting destructor\'':
						function_name = function_name_parts[0]
						class_name = function_name
						function_string = f'virtual ~{function_name}() = 0;\n'
						found_dup = 0
						for func_str in ready_functions:
							if func_str == function_string:
								found_dup += 1
						if found_dup:
							function_string = f'virtual ~{function_name}{found_dup + 1}() = 0;\n'
						ready_functions.append(function_string)
						continue
					elif (function_name[0] == '~') & (function_name_parts[0] == function_name_parts[-1][1:]):
						class_name = function_name[1:]
						function_string = f'virtual {function_name}() = 0;\n'
						found_dup = 0
						for func_str in ready_functions:
							if func_str == function_string:
								found_dup += 1
						if found_dup:
							function_string = f'virtual {function_name}{found_dup + 1}() = 0;\n'
						ready_functions.append(function_string)
						continue
					elif function_name[:4] == 'sub_':
						function_name = f'NonAssociated_{sub_functions}'
						sub_functions += 1

					function_type = ida_name.get_demangled_name(function, 0, 0, ida_name.GN_DEMANGLED | ida_name.GN_STRICT)
					function_type_args = re.search(r'\((.*)\)', function_type)
					if function_type_args:
						function_type_args = function_type_args.group(1)
						if function_type_args == 'void':
							function_type_args = ''
						else:
							function_type_args = '**'.join(function_type_args.rsplit(' **'))
							function_type_args = '*'.join(function_type_args.rsplit(' *'))
							function_type_args = '&'.join(function_type_args.rsplit(' &'))
							function_type_args = ', '.join(function_type_args.rsplit(','))
					else:
						function_type_args = ''

					#if calling_convention != '__fastcall':
					#	function_string = f'virtual {return_type} {calling_convention} {function_name}('
					#else:
					#	function_string = f'virtual {return_type} {function_name}('

					function_string = f'virtual {return_type} {function_name}('

					if function_type_args:
						function_string += function_type_args + ') = 0;\n'
					else:
						for i, arg in enumerate(args):
							arg_type = arg.dstr()
							if i >= len(args) - 1:
								function_string += f'{arg_type}'
							else:
								function_string += f'{arg_type}, '
						function_string += ') = 0;\n'

					ready_functions.append(function_string)
					continue

				ready_functions.append(f'virtual void NonDecompilable_{non_decompilable}() = 0;\n')
				non_decompilable += 1

		class_begin = 'class ' + class_name + ' {\npublic:\n'

		for functions_string in ready_functions:
			class_begin += '\t' + functions_string

		class_end = class_begin + '};\n'

		idc.msg(class_end)

_VTableDump = None
bPluginMode = False
def PLUGIN_ENTRY():
	global _VTableDump
	global bPluginMode
	if _VTableDump == None:
		_VTableDump = VTableDump()
	bPluginMode = True
	return _VTableDump

if __name__ == '__main__':
	if bPluginMode != True:
		if ida_pro.IDA_SDK_VERSION < 770:
			idc.msg('[VTableDump] Error: Optimal IDA version for VTableDump is 7.7.\n')
		else:
			VTableDump().run(0)
