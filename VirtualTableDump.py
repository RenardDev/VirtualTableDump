# Name: VirtualTableDump.py
# Version: 3.8.0
# Author: RenardDev (zeze839@gmail.com)

# IDA
import ida_ida
import ida_idaapi
import ida_name
import ida_bytes
import ida_pro
import ida_auto
import ida_search
import ida_hexrays
import idautils
import idaapi
import ida_nalt
import ida_funcs
import ida_typeinf
import idc

# Python
from pathlib import Path
import re
import os

DATABASE_FILE = Path(idc.get_idb_path())
DATABASE_DIRECTORY = DATABASE_FILE.parent
DATABASE_INFO = ida_idaapi.get_inf_structure()

MIN_EA = DATABASE_INFO.min_ea
MAX_EA = DATABASE_INFO.max_ea

FILE_TYPE = DATABASE_INFO.filetype
IS_64 = DATABASE_INFO.is_64bit()

if FILE_TYPE == idc.FT_PE:
	IMAGEBASE = ida_nalt.get_imagebase()
elif (FILE_TYPE == idc.FT_ELF) | (FILE_TYPE == idc.FT_MACHO):
	TYPE_INFO_ADDRESSES = [
		ida_name.get_name_ea(ida_idaapi.BADADDR, '__ZTVN10__cxxabiv117__class_type_infoE'), # Single
		ida_name.get_name_ea(ida_idaapi.BADADDR, '__ZTVN10__cxxabiv120__si_class_type_infoE'), # Single parent
		ida_name.get_name_ea(ida_idaapi.BADADDR, '__ZTVN10__cxxabiv121__vmi_class_type_infoE') # Multiple parents
	]

def IsNotValidAddress(address:int) -> bool:
	if (address == 0) | (address == ida_idaapi.BADADDR) | (address >= MAX_EA) | (address < MIN_EA):
		return True
	return False

def FormatTypeName(type_name:str) -> str:
	type_name = re.sub('`[^`\']*\'', '', type_name)
	type_name = type_name.replace('::', '_')
	type_name = type_name.replace('(', '_')
	type_name = type_name.replace('<', '_')
	type_name = type_name.replace(',', '_')
	type_name = type_name.replace('>', '_')
	type_name = type_name.replace('&', '_')
	type_name = type_name.replace(')', '_')
	type_name = re.sub('\\s+', '', type_name)
	type_name = re.sub('\\(.*\\*\\)\\(.*\\)', '', type_name)
	type_name = type_name.replace('*', '')
	type_name = re.sub('\\_+', '_', type_name)
	type_name = type_name.removeprefix('__')
	type_name = type_name.removeprefix('_')
	type_name = type_name.removesuffix('__')
	type_name = type_name.removesuffix('_')
	return type_name

def FixDubTypes(types, known_types = None):
	if known_types == None:
		known_types = []
	new_types = []
	for type, name, bases in types:
		if bases:
			FixDubTypes(bases, known_types)
		is_dup = False
		for known_type, known_name, known_bases in known_types:
			if known_type == type:
				is_dup = True
				break
		if is_dup != True:
			new_types.append((type, name, bases))
			known_types.append((type, name, bases))
	return new_types

def SearchBaseTypes(search_type:int, main_type:int = 0):
	types = []

	if main_type != 0:
		if main_type == search_type:
			return types

	if FILE_TYPE == idc.FT_PE:
		for search_type_ref in idautils.XrefsTo(search_type):
			search_type_ref_address = search_type_ref.frm

			# TODO: Checking for valid record
			signature = ida_bytes.get_dword(search_type_ref_address - 12)
			attributes = ida_bytes.get_dword(search_type_ref_address + 20)
			if ((signature == 0) | (signature == 1)) & (attributes > 0x40):
				continue

			number_of_bases = ida_bytes.get_dword(search_type_ref_address + 4)
			if number_of_bases == 0:
				continue

			if IS_64:
				chd = IMAGEBASE + ida_bytes.get_dword(search_type_ref_address + 24)
			else:
				chd = ida_bytes.get_dword(search_type_ref_address + 24)

			if IsNotValidAddress(chd):
				continue

			number_of_items = ida_bytes.get_dword(chd + 8)
			if (number_of_items == 0) | (number_of_items == 1):
				continue

			if IS_64:
				array_of_bases = IMAGEBASE + ida_bytes.get_dword(chd + 12)
			else:
				array_of_bases = ida_bytes.get_dword(chd + 12)

			if IsNotValidAddress(array_of_bases):
				continue

			for i in range(number_of_items - number_of_bases, number_of_items):
				if IS_64:
					base_bcd = IMAGEBASE + ida_bytes.get_dword(array_of_bases + 4 * i)
				else:
					base_bcd = ida_bytes.get_dword(array_of_bases + 4 * i)

				if IsNotValidAddress(base_bcd):
					continue

				if IS_64:
					base_type = IMAGEBASE + ida_bytes.get_dword(base_bcd)
				else:
					base_type = ida_bytes.get_dword(base_bcd)

				if IsNotValidAddress(base_type):
					continue

				if base_type == search_type:
					continue

				if main_type != 0:
					if base_type == main_type:
						continue

				type_name = FormatTypeName(ida_name.get_demangled_name(base_type, ida_name.M_PRCMSK | ida_name.MT_LOCALNAME, 0, ida_name.GN_DEMANGLED | ida_name.GN_STRICT | ida_name.GN_LOCAL))
				types.append((base_type, type_name, SearchBaseTypes(base_type, search_type)))
	elif (FILE_TYPE == idc.FT_ELF) | (FILE_TYPE == idc.FT_MACHO):
		# if IS_64:
		# 	type_base = ida_bytes.get_qword(search_type)
		# else:
		# 	type_base = ida_bytes.get_dword(search_type)
		type_base = ida_name.get_name_base_ea(search_type, 0)

		if type_base == TYPE_INFO_ADDRESSES[0]: # Single
			if main_type != 0:
				type_name = FormatTypeName(ida_name.get_demangled_name(search_type, ida_name.M_PRCMSK | ida_name.MT_LOCALNAME, 0, ida_name.GN_DEMANGLED | ida_name.GN_STRICT | ida_name.GN_LOCAL))
				types.append((search_type, type_name, []))
		elif type_base == TYPE_INFO_ADDRESSES[1]: # Parent-Child
			if IS_64:
				type_parent = ida_bytes.get_qword(search_type + 16)
			else:
				type_parent = ida_bytes.get_dword(search_type + 8)

			type_of_parent = ida_name.get_name_base_ea(type_parent, 0)
			if type_of_parent == TYPE_INFO_ADDRESSES[0]: # Single
				type_name = FormatTypeName(ida_name.get_demangled_name(type_parent, ida_name.M_PRCMSK | ida_name.MT_LOCALNAME, 0, ida_name.GN_DEMANGLED | ida_name.GN_STRICT | ida_name.GN_LOCAL))
				types.append((type_parent, type_name, []))
			else:
				type_name = FormatTypeName(ida_name.get_demangled_name(type_parent, ida_name.M_PRCMSK | ida_name.MT_LOCALNAME, 0, ida_name.GN_DEMANGLED | ida_name.GN_STRICT | ida_name.GN_LOCAL))
				types.append((type_parent, type_name, SearchBaseTypes(type_parent, search_type)))
		elif type_base == TYPE_INFO_ADDRESSES[2]: # Multiple
			if IS_64:
				count_of_base_types = ida_bytes.get_qword(search_type + 24)
			else:
				count_of_base_types = ida_bytes.get_dword(search_type + 12)

			for i in range(count_of_base_types):
				if IS_64:
					base_type = ida_bytes.get_qword(search_type + 32 + 16 * i)
				else:
					base_type = ida_bytes.get_dword(search_type + 16 + 8 * i)

				if base_type == search_type:
					continue

				if main_type != 0:
					if base_type == main_type:
						continue

				type_of_base = ida_name.get_name_base_ea(base_type, 0)
				if type_of_base == TYPE_INFO_ADDRESSES[0]: # Single
					type_name = FormatTypeName(ida_name.get_demangled_name(base_type, ida_name.M_PRCMSK | ida_name.MT_LOCALNAME, 0, ida_name.GN_DEMANGLED | ida_name.GN_STRICT | ida_name.GN_LOCAL))
					types.append((base_type, type_name, []))
				else:
					type_name = FormatTypeName(ida_name.get_demangled_name(base_type, ida_name.M_PRCMSK | ida_name.MT_LOCALNAME, 0, ida_name.GN_DEMANGLED | ida_name.GN_STRICT | ida_name.GN_LOCAL))
					types.append((base_type, type_name, SearchBaseTypes(base_type, search_type)))

	if FILE_TYPE == idc.FT_PE:
		return FixDubTypes(types)
	elif (FILE_TYPE == idc.FT_ELF) | (FILE_TYPE == idc.FT_MACHO):
		return types

def ReConstructTypes(types, known_types = None):
	if known_types == None:
		known_types = []
	new_types = []
	for type, name, bases in types:
		if bases:
			new_types.extend(ReConstructTypes(bases, known_types))
		is_dup = False
		for known_type, known_name, known_bases in known_types:
			if known_type == type:
				is_dup = True
				break
		if is_dup != True:
			new_types.append((type, name, bases))
			known_types.append((type, name, bases))
	return new_types

def SearchTypes():
	types = []

	if FILE_TYPE == idc.FT_PE:
		type_addresses = []
		begin_address = MIN_EA
		while True:
			address = ida_search.find_binary(begin_address, MAX_EA, '2E 3F 41 56 74 79 70 65 5F 69 6E 66 6F 40 40 00', 0, ida_search.SEARCH_DOWN)
			if IsNotValidAddress(address):
				break

			begin_address = address + 16

			if IS_64:
				type_address = ida_bytes.get_qword(address - 16)
				spare = ida_bytes.get_qword(address - 8)
			else:
				type_address = ida_bytes.get_dword(address - 8)
				spare = ida_bytes.get_dword(address - 4)

			if IsNotValidAddress(type_address) | (spare != 0):
				continue

			type_addresses.append(type_address)

		for type_address in type_addresses:
			for based_type in idautils.XrefsTo(type_address):
				based_type_address = based_type.frm

				if IS_64:
					based_spare = ida_bytes.get_qword(based_type_address + 8)
				else:
					based_spare = ida_bytes.get_dword(based_type_address + 4)

				if based_spare != 0:
					continue

				based_name = FormatTypeName(ida_name.get_demangled_name(based_type_address, ida_name.M_PRCMSK | ida_name.MT_LOCALNAME, 0, ida_name.GN_DEMANGLED | ida_name.GN_STRICT | ida_name.GN_LOCAL))
				types.append((based_type_address, based_name, SearchBaseTypes(based_type_address)))
	elif (FILE_TYPE == idc.FT_ELF) | (FILE_TYPE == idc.FT_MACHO):
		for type_info_address in TYPE_INFO_ADDRESSES:
			if IsNotValidAddress(type_info_address):
				continue

			for based_type_info in idautils.XrefsTo(type_info_address):
				based_type_info_address = based_type_info.frm

				if IS_64:
					raw_based_type_name = ida_bytes.get_qword(based_type_info_address + 8)
				else:
					raw_based_type_name = ida_bytes.get_dword(based_type_info_address + 4)

				if IsNotValidAddress(raw_based_type_name):
					continue

				based_type_name = FormatTypeName(ida_name.get_demangled_name(based_type_info_address, ida_name.M_PRCMSK | ida_name.MT_LOCALNAME, 0, ida_name.GN_DEMANGLED | ida_name.GN_STRICT | ida_name.GN_LOCAL))
				types.append((based_type_info_address, based_type_name, SearchBaseTypes(based_type_info_address)))

	return ReConstructTypes(types)

def FindVirtualTableFunctions(name, table):
	functions = []

	offset = 0
	while True:
		if IS_64:
			address = ida_bytes.get_qword(table + offset)
			offset += 8
		else:
			address = ida_bytes.get_dword(table + offset)
			offset += 4

		if IsNotValidAddress(address) | ida_bytes.is_data(ida_bytes.get_flags(address)):
			break

		func = ida_funcs.get_func(address)
		if func:
			if ida_funcs.is_func_entry(func) != True:
				break
		else:
			break

		try:
			decompiled_function = ida_hexrays.decompile(address)
			if decompiled_function:
				functions.append(address)
		except ida_hexrays.DecompilationFailure:
			break

	return functions

def SearchVirtualTables(types, result = None):
	if result == None:
		result = []

	if FILE_TYPE == idc.FT_PE:
		for type, name, bases in types:
			if bases:
				SearchVirtualTables(bases, result)

			if IsNotValidAddress(type):
				continue

			exist = False
			for result_type, result_name, result_table, result_functions in result:
				if result_type == type:
					exist = True
					break
			
			if exist:
				continue

			for search_type_ref in idautils.XrefsTo(type):
				search_type_ref_address = search_type_ref.frm

				complete_object = search_type_ref_address - 12

				# TODO: Checking for valid record
				signature = ida_bytes.get_dword(complete_object)
				if (signature != 0) & (signature != 1):
					continue

				if IS_64:
					if IMAGEBASE + ida_bytes.get_dword(complete_object + 20) != complete_object:
						continue

				for type_ref in idautils.XrefsTo(complete_object):
					type_ref_address = type_ref.frm

					if IS_64:
						table = type_ref_address + 8
					else:
						table = type_ref_address + 4

					functions = FindVirtualTableFunctions(name, table)
					if functions:
						result.append((type, name, table, functions))
	elif (FILE_TYPE == idc.FT_ELF) | (FILE_TYPE == idc.FT_MACHO):
		for type, name, bases in types:
			if bases:
				SearchVirtualTables(bases, result)

			if IsNotValidAddress(type):
				continue

			exist = False
			for result_type, result_name, result_table, result_functions in result:
				if result_type == type:
					exist = True
					break
			
			if exist:
				continue

			for type_ref in idautils.XrefsTo(type):
				type_ref_address = type_ref.frm

				if IS_64:
					offset_to_this = ida_bytes.get_qword(type_ref_address - 8)
				else:
					offset_to_this = ida_bytes.get_dword(type_ref_address - 4)

				if offset_to_this != 0:
					continue

				if IS_64:
					table = type_ref_address + 8
				else:
					table = type_ref_address + 4

				functions = FindVirtualTableFunctions(name, table)
				if functions:
					result.append((type, name, table, functions))

	return result

def IsKnownType(string):
	tif = ida_typeinf.tinfo_t()
	if ida_typeinf.parse_decl(tif, None, string + ';', ida_typeinf.PT_SIL) is None:
		return (False, '')
	while tif.is_ptr():
		tif = tif.get_pointed_object()
	tif.clr_const_volatile()
	if tif.is_arithmetic() | tif.is_sse_type() | tif.is_func() | tif.is_void():
		return (False, '')
	return (True, tif.dstr())

def GetTypeString(type):
	tif = ida_typeinf.tinfo_t()
	if ida_typeinf.parse_decl(tif, None, type.dstr() + ';', ida_typeinf.PT_SIL) is None:
		return (False, '')
	tif.clr_const_volatile()
	return (True, tif.dstr())

def GetEndType(tif):
	while tif.is_ptr():
		tif = tif.get_pointed_object()
	return tif

def DecompileVirtualTablesFunctions(tables, declare, include):
	decompiled = []

	known_functions = []

	for table_type, table_name, table_address, table_functions in tables:
		unk_functions = 1
		sub_functions = 1
		pure_functions = 1

		functions = []
		for function in table_functions:
			try:
				decompiled_function = ida_hexrays.decompile(function)
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

					return_type = decompiled_function.type.get_rettype()
					status, string = GetTypeString(return_type)
					if status & (string != '?'):
						return_type = string
					else:
						return_type = return_type.dstr()
					args = [ decompiled_function.type.get_nth_arg(x) for x in range(1, decompiled_function.type.get_nargs()) ]

					end_return_type = GetEndType(decompiled_function.type.get_rettype())
					if end_return_type.is_func() | (end_return_type.is_int128() & decompiled_function.type.get_rettype().is_ptr()):
						return_type = 'void*'

					return_type = '*'.join(return_type.rsplit(' *'))
					if (return_type == '_BOOL4') | (return_type == 'BOOL'):
						return_type = 'bool'
					elif return_type == '_DWORD*':
						return_type = 'void*'
					elif return_type == '_BYTE*':
						return_type = 'unsigned char*'
					elif return_type == '_QWORD*':
						return_type = 'unsigned long long*'
					elif return_type == '_DWORD':
						return_type = 'unsigned int'

					return_type = return_type.replace('::', '_').replace('class ', '').replace('struct ', '')

					return_type_str = return_type.replace(' ', '').rsplit('&')[0].rsplit('*')[0].strip()
					is_known = False
					for known_table_type, known_table_name, known_table_address, known_table_functions in tables:
						if known_table_name == return_type_str:
							is_known = True
							break

					if is_known != True:
						status, string = IsKnownType(decompiled_function.type.get_rettype().dstr().replace('::', '_').replace('class ', '').replace('struct ', ''))
						if status & (string != '?'):
							if string not in declare:
								declare.append(string)
					else:
						if return_type_str not in include:
							include.append(return_type_str)

					function_name = ida_name.get_demangled_name(function, ida_name.M_PRCMSK | ida_name.MT_LOCALNAME, 0, ida_name.GN_DEMANGLED | ida_name.GN_STRICT | ida_name.GN_LOCAL)
					function_name_parts = function_name.rsplit('::')
					if function_name_parts:
						function_name = function_name_parts[-1]
					if function_name == '':
						function_name = f'NonNamed_{unk_functions}'
						unk_functions += 1
					if (function_name == '`scalar deleting destructor\'') | (function_name == '`vector deleting destructor\''):
						#function_string = f'virtual ~{table_name}() = 0;'
						function_string = f'virtual void deconstructor_{table_name}() = 0;'
						found_dup = 0
						for func, func_str, func_name, func_ret, func_args, real_funcname in functions:
							if func_str == function_string:
								found_dup += 1
						if found_dup:
							#function_string = f'virtual ~{function_name}{found_dup + 1}() = 0;'
							function_string = f'virtual void deconstructor_{function_name}{found_dup + 1}() = 0;'
							continue # Not exist 2nd dcotr for Windows
						functions.append((function, function_string, function_name, '', [], function_name))
						continue
					elif (function_name[0] == '~') | (function_name_parts[0] == function_name_parts[-1][1:]):
						#function_string = f'virtual ~{table_name}() = 0;'
						function_string = f'virtual void deconstructor_{table_name}() = 0;'
						found_dup = 0
						for func, func_str, func_name, func_ret, func_args, real_funcname in functions:
							if func_str == function_string:
								found_dup += 1
						if found_dup:
							#function_string = f'virtual ~{table_name}{found_dup + 1}() = 0;'
							function_string = f'virtual void deconstructor_{table_name}{found_dup + 1}() = 0;'
							continue # Not exist 2nd dcotr for Windows
						functions.append((function, function_string, function_name, '', [], function_name))
						continue
					elif function_name[:4] == 'sub_':
						return_type = 'void'
						function_name = f'NonAssociated_{sub_functions}'
						function_type_args = ''
						sub_functions += 1
					elif function_name == '__purecall':
						return_type = 'void'
						function_name = f'PureCall_{pure_functions}'
						function_type_args = ''
						pure_functions += 1

					function_type = ida_name.get_demangled_name(function, 0, 0, ida_name.GN_DEMANGLED | ida_name.GN_STRICT)
					if (function_name[:13] != 'NonAssociated') & (function_name[:8] != 'PureCall'):
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

						function_type_args = function_type_args.replace('::', '_')

					found_dup = 0
					for func, func_str, func_name, func_ret, func_args, real_funcname in functions:
						if func_name == function_name:
							found_dup += 1

					#if calling_convention != '__fastcall':
					#	function_string = f'virtual {return_type} {calling_convention} {function_name}('
					#else:
					#	function_string = f'virtual {return_type} {function_name}('

					if found_dup:
						function_name_new = f'{function_name}{found_dup + 1}'
					else:
						function_name_new = function_name

					function_string = f'virtual {return_type} {function_name_new}('

					func_args = []

					#if function_type_args:
					if 0:
						function_string += function_type_args + ') = 0;'
					else:
						for i, arg in enumerate(args):
							status, string = GetTypeString(arg)
							if status & (string != '?'):
								arg_type = string
							else:
								arg_type = arg.dstr()

							end_arg_type = GetEndType(arg)
							if end_arg_type.is_func() | (end_arg_type.is_int128() & arg.is_ptr()):
								arg_type = 'void*'

							arg_type = '*'.join(arg_type.rsplit(' *'))
							if (arg_type == '_BOOL4') | (arg_type == 'BOOL'):
								arg_type = 'bool'
							elif arg_type == '_DWORD*':
								arg_type = 'void*'
							elif arg_type == '_BYTE*':
								arg_type = 'unsigned char*'
							elif arg_type == '_QWORD*':
								arg_type = 'unsigned long long*'
							elif arg_type == '_DWORD':
								arg_type = 'unsigned int'

							arg_type = arg_type.replace('::', '_').replace('class ', '').replace('struct ', '')

							arg_type_str = arg_type.replace('const ', '').replace('volatile ', '').replace(' ', '').rsplit('&')[0].rsplit('*')[0].strip()
							is_known = False
							for known_table_type, known_table_name, known_table_address, known_table_functions in tables:
								if known_table_name == arg_type_str:
									is_known = True
									break

							if is_known != True:
								status, string = IsKnownType(arg.dstr().replace('::', '_').replace('class ', '').replace('struct ', ''))
								if status & (string != '?'):
									if string not in declare:
										declare.append(string)
								else:
									narg = arg
									while narg.is_ptr():
										narg = narg.get_pointed_object()
									if (narg.is_arithmetic() | narg.is_sse_type() | narg.is_func() | narg.is_void()) != True:
										narg = narg.dstr().replace('::', '_').replace('class ', '').replace('struct ', '').replace('const ', '').replace('volatile ', '').replace(' ', '').rsplit('&')[0].rsplit('*')[0].strip()
										if narg not in declare:
											declare.append(narg)
							else:
								if arg_type_str not in include:
									include.append(arg_type_str)

							if i >= len(args) - 1:
								function_string += f'{arg_type}'
							else:
								function_string += f'{arg_type}, '

							func_args.append(arg_type)
						function_string += ') = 0;'

					functions.append((function, function_string, function_name, return_type, func_args, function_name_new))

					is_exist = False
					for rettype, name, args in known_functions:
						if name == function_name:
							is_exist = True
							break

					if is_exist != True:
						known_functions.append((return_type, function_name, func_args))

			except ida_hexrays.DecompilationFailure:
				functions.append((function, f'virtual void FailedToDecompile_{function_name}() = 0;', function_name, return_type, []))

		if functions:

			for index, (func, string, name, rettype, args, realname) in enumerate(functions):
				for known_rettype, known_name, known_args in known_functions:
					if name == known_name:
						if known_rettype != rettype:
							args_string = ', '.join(args)
							functions[index] = (func, f'virtual {known_rettype} {realname}({args_string}) = 0; // Fixed return type', name, known_rettype, args, realname)
						break

			decompiled.append((table_type, table_name, table_address, functions))

	return decompiled

def GetBasesNames(bases, names = None):
	if names == None:
		names = set()
	for type, name, base_types in bases:
		# if base_types:
		# 	GetBasesNames(base_types, names)
		names.add(name)
	return names

def PrintBaseTypes(types, index = 0):
	for type, name, base_types in types:
		print(' ' * (index + 1) + f' > {name}')

		if base_types:
			PrintBaseTypes(base_types, index + 1)

class VirtualTableDump(ida_idaapi.plugin_t):
	flags = ida_idaapi.PLUGIN_MOD
	wanted_name = 'VirtualTableDump'
	comment = 'VirtualTableDump - Dumper for all VTables.\n'
	help = ''

	def init(self):
		if ida_pro.IDA_SDK_VERSION < 770:
			idc.msg('[VirtualTableDump] Error: Optimal IDA version is 7.7.\n')
			return ida_idaapi.PLUGIN_SKIP
		return ida_idaapi.PLUGIN_KEEP

	def term(self):
		pass

	def run(self, arg):
		if ida_auto.auto_is_ok() != True:
			idc.msg('[VirtualTableDump] Error: The analysis is not finished!\n')
			return

		if ida_hexrays.init_hexrays_plugin() != True:
			idc.msg('[VirtualTableDump] Error: Failed to initialize hexrays plugin!\n')
			return

		if (FILE_TYPE != idc.FT_PE) & (FILE_TYPE != idc.FT_ELF) & (FILE_TYPE != idc.FT_MACHO):
			idc.msg('[VirtualTableDump] Error: This file type is not supported!\n')
			return

		found_types = SearchTypes()
		idc.msg(f'[VirtualTableDump] Info: Found {len(found_types)} types.\n')

		if found_types:
			tables = SearchVirtualTables(found_types)
			idc.msg(f'[VirtualTableDump] Info: Found {len(tables)} virtual tables.\n')

			if tables:
				declare = []
				include = []
				tables = DecompileVirtualTablesFunctions(tables, declare, include)
				idc.msg(f'[VirtualTableDump] Info: Decompiled {len(tables)} virtual tables.\n')

				if tables:

					known_bases = []
					known_tables = []
					code_bases = '\n'
					code = ''

					if include:
						for inc in include:
							code_bases += f'class {inc};\n'

						code_bases += '\n'

					if declare:
						for decl in declare:
							code_bases += f'class {decl} ' + '{};\n'

						code_bases += '\n'

					for type, name, base_types in found_types:
						for table_type, table_name, table_address, table_functions in tables:

							if table_name in known_tables:
								continue

							if type == table_type:
								bases = GetBasesNames(base_types)
								if bases:
									bases_public = []
									for base in bases:
										base_is_known = False
										for known_base in known_bases:
											if base == known_base:
												base_is_known = True
												break
										if base_is_known != True:
											for known_base in include:
												if base == known_base:
													base_is_known = True
													break
											if base_is_known != True:
												for known_base in declare:
													if base == known_base:
														base_is_known = True
														break
										known_bases.append(base)
										found_base = False
										for known_type, known_name, known_address, known_functions in tables:
											if base == known_name:
												if known_functions:
													found_base = True
												break
										if base_is_known != True:
											if found_base != True:
												code_bases += f'class {base}' + ' {};\n'
											else:
												code_bases += f'class {base}; // Unexpected include\n'
										#if base == 'ConVar':
										#	print(f'ConVar = {found_base} {base_is_known}')
										bases_public.append(f'public {base}')

									bases_public = ', '.join(bases_public)

									code += f'class {table_name} : {bases_public} ' + '{\n'
								else:
									code += f'class {table_name} ' + '{\n'

								known_tables.append(table_name)

								for function, function_name, real_function_name, func_ret, func_args, real_funcname in table_functions:
									code += '\t' + function_name + '\n'

								code += '};\n\n'

					file_path = DATABASE_FILE.parent.joinpath(DATABASE_FILE.stem + '.h').__str__()
					with open(file_path, 'w+') as f:
						f.write(code_bases + '\n' + code)
						f.close()
						idc.msg(f'[VirtualTableDump] Info: Dumped in `{file_path}`.\n')

					# if tables:
					# 	for table_type, table_name, table_address, table_functions in tables:
					# 		if len(table_functions) > 0:
					# 			print(f'> {table_name}')
					# 			for function in table_functions:
					# 				print(f'   > {function}')

_VirtualTableDump = None
bPluginMode = False
def PLUGIN_ENTRY():
	global _VirtualTableDump
	global bPluginMode
	if _VirtualTableDump == None:
		_VirtualTableDump = VirtualTableDump()
	bPluginMode = True
	return _VirtualTableDump

if __name__ == '__main__':
	if bPluginMode != True:
		if ida_pro.IDA_SDK_VERSION < 770:
			idc.msg('[VirtualTableDump] Error: Optimal IDA version is 7.7\n')
		else:
			VirtualTableDump().run(0)
