# Name: VTableDump.py
# Version: 2.0.0
# Author: RenardDev (zeze839@gmail.com)

# IDA imports
import ida_idaapi
import ida_ida
import ida_name
import ida_bytes
import ida_pro
import ida_auto
import ida_search
import ida_hexrays
import idautils
import idaapi
import idc

# Python imports
import re
import pathlib
import os

SEPARATE_IN_FILES = False

def IsNotValidAddress(address):
	min_address = ida_ida.inf_get_min_ea()
	max_address = ida_ida.inf_get_max_ea()
	if (address == 0) | (address == ida_idaapi.BADADDR) | (address >= max_address) | (address < min_address):
		return True
	return False

def FindVTableFunctions(address):
	functions = []
	vtable_size = 0
	while True:
		if ida_idaapi.get_inf_structure().is_64bit():
			function_ptr = ida_bytes.get_qword(address + vtable_size)
		else:
			function_ptr = ida_bytes.get_dword(address + vtable_size)
		if IsNotValidAddress(function_ptr) | ida_bytes.is_data(ida_bytes.get_flags(function_ptr)):
			break
		functions.append(function_ptr)
		if ida_idaapi.get_inf_structure().is_64bit():
			vtable_size += 8
		else:
			vtable_size += 4
	return functions

def GenerateVTableClass(vtable_address, class_name = None):
	ready_functions = []

	class_name_set = False
	if class_name == None:
		class_name_set = True
		class_name = 'UnknownClass'

	pure_functions = 1
	have_deconstructor = False
	pure_class = False

	functions = FindVTableFunctions(vtable_address)
	if functions:
		unk_functions = 1
		sub_functions = 1
		#non_decompilable = 1
		for function in functions:
			try:
				decompiled_function = ida_hexrays.decompile(function)
			except ida_hexrays.DecompilationFailure:
				return (None, None)
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
				elif return_type == '_BYTE*':
					return_type = 'unsigned char*'

				function_name = ida_name.get_demangled_name(function, ida_name.M_PRCMSK | ida_name.MT_LOCALNAME, 0, ida_name.GN_DEMANGLED | ida_name.GN_STRICT | ida_name.GN_LOCAL)
				function_name_parts = function_name.rsplit('::')
				if function_name_parts:
					function_name = function_name_parts[-1]
				if function_name == '':
					function_name = f'NonNamed_{unk_functions}'
					unk_functions += 1
				if (function_name == '`scalar deleting destructor\'') | (function_name == '`vector deleting destructor\''):
					function_name = function_name_parts[0]
					if class_name_set:
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
				elif (function_name[0] == '~') | (function_name_parts[0] == function_name_parts[-1][1:]):
					if class_name_set:
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
				elif function_name == '__purecall':
					function_name = f'PureCall_{pure_functions}'
					pure_functions += 1

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

			#ready_functions.append(f'virtual void NonDecompilable_{non_decompilable}() = 0;\n')
			#non_decompilable += 1
			break # NOTE: In 99% of cases this means the end of the vtable.

	if have_deconstructor:
		if len(ready_functions) - 1 == pure_functions:
			pure_class = True
	else:
		if len(ready_functions) == pure_functions:
			pure_class = True

	if class_name:
		class_name_new = re.search(r'::`vftable\'+.*', class_name)
		if class_name_new:
			class_name = class_name.replace(class_name_new.group(), '')
			class_name_parts = class_name.rsplit('::')
			if class_name_parts[0] == '`anonymous namespace\'':
				class_name_parts = class_name_parts[1:]
			class_name = '::'.join(class_name_parts).replace('const ', '')

	class_begin = 'class ' + class_name + ' {\npublic:\n'

	if pure_class != True:
		for functions_string in ready_functions:
			class_begin += '\t' + functions_string

	return (class_name, class_begin + '};\n\n')

def GenerateVTableWithBasesClass(vtable_address, bases_names, class_name = None):
	ready_functions = []

	class_name_set = False
	if class_name == None:
		class_name_set = True
		class_name = 'UnknownClass'

	pure_functions = 1
	have_deconstructor = False
	pure_class = False

	functions = FindVTableFunctions(vtable_address)
	if functions:
		unk_functions = 1
		sub_functions = 1
		#non_decompilable = 1
		for function in functions:
			try:
				decompiled_function = ida_hexrays.decompile(function)
			except ida_hexrays.DecompilationFailure:
				return (None, None)
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
				elif return_type == '_BYTE*':
					return_type = 'unsigned char*'

				function_name = ida_name.get_demangled_name(function, ida_name.M_PRCMSK | ida_name.MT_LOCALNAME, 0, ida_name.GN_DEMANGLED | ida_name.GN_STRICT | ida_name.GN_LOCAL)
				function_name_parts = function_name.rsplit('::')
				if function_name_parts:
					function_name = function_name_parts[-1]
				if function_name == '':
					function_name = f'NonNamed_{unk_functions}'
					unk_functions += 1
				if (function_name == '`scalar deleting destructor\'') | (function_name == '`vector deleting destructor\''):
					function_name = function_name_parts[0]
					if class_name_set:
						class_name = function_name
					function_string = f'virtual ~{function_name}() = 0;\n'
					found_dup = 0
					for func_str in ready_functions:
						if func_str == function_string:
							found_dup += 1
					if found_dup:
						function_string = f'virtual ~{function_name}{found_dup + 1}() = 0;\n'
					ready_functions.append(function_string)
					have_deconstructor = True
					continue
				elif (function_name[0] == '~') | (function_name_parts[0] == function_name_parts[-1][1:]):
					if class_name_set:
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
				elif function_name == '__purecall':
					function_name = f'PureCall_{pure_functions}'
					pure_functions += 1

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

			#ready_functions.append(f'virtual void NonDecompilable_{non_decompilable}() = 0;\n')
			#non_decompilable += 1
			break # NOTE: In 99% of cases this means the end of the vtable.

	if have_deconstructor:
		if len(ready_functions) - 1 == pure_functions:
			pure_class = True
	else:
		if len(ready_functions) == pure_functions:
			pure_class = True

	if class_name:
		class_name_new = re.search(r'::`vftable\'+.*', class_name)
		if class_name_new:
			class_name = class_name.replace(class_name_new.group(), '')
			class_name_parts = class_name.rsplit('::')
			if class_name_parts[0] == '`anonymous namespace\'':
				class_name_parts = class_name_parts[1:]
			class_name = '::'.join(class_name_parts).replace('const ', '')

	class_begin = 'class ' + class_name + ' : public '
	
	for i, base_name in enumerate(bases_names):
		if i >= len(bases_names) - 1:
			class_begin += base_name + ' '
		else:
			class_begin += base_name + ', '

	class_begin += '{\npublic:\n'

	if pure_class != True:
		for functions_string in ready_functions:
			class_begin += '\t' + functions_string

	return (class_name, class_begin + '};\n\n')

def FindVTablesMACHO():
	base_addresses = [
		ida_name.get_name_ea(ida_idaapi.BADADDR, '__ZTVN10__cxxabiv123__fundamental_type_infoE'),
		ida_name.get_name_ea(ida_idaapi.BADADDR, '__ZTVN10__cxxabiv117__class_type_infoE'),
		ida_name.get_name_ea(ida_idaapi.BADADDR, '__ZTVN10__cxxabiv120__si_class_type_infoE'),
		ida_name.get_name_ea(ida_idaapi.BADADDR, '__ZTVN10__cxxabiv121__vmi_class_type_infoE'),
		ida_name.get_name_ea(ida_idaapi.BADADDR, '__ZTVN10__cxxabiv119__pointer_type_infoE'),
		ida_name.get_name_ea(ida_idaapi.BADADDR, '__ZTVN10__cxxabiv129__pointer_to_member_type_infoE')
	]

	possible_vtables = []

	for base_address in base_addresses:
		if IsNotValidAddress(base_address):
			continue

		types = idautils.XrefsTo(base_address)
		for type in types:
			if ida_idaapi.get_inf_structure().is_64bit():
				type_name_addr = ida_bytes.get_qword(type.frm + 8)
			else:
				type_name_addr = ida_bytes.get_dword(type.frm + 4)

			if IsNotValidAddress(type_name_addr):
				continue

			type_refs = idautils.XrefsTo(type.frm)
			for type_ref in type_refs:

				if ida_idaapi.get_inf_structure().is_64bit():
					vtable_name = ida_name.get_demangled_name(type_ref.frm - 8, ida_name.M_PRCMSK | ida_name.MT_LOCALNAME, 0, ida_name.GN_DEMANGLED | ida_name.GN_STRICT | ida_name.GN_LOCAL)
				else:
					vtable_name = ida_name.get_demangled_name(type_ref.frm - 4, ida_name.M_PRCMSK | ida_name.MT_LOCALNAME, 0, ida_name.GN_DEMANGLED | ida_name.GN_STRICT | ida_name.GN_LOCAL)

				if vtable_name:
					
					vtable_name = re.sub(r'`.*.\'', '', vtable_name)
					vtable_name = vtable_name.removeprefix('__')
					vtable_name = vtable_name.removeprefix('_')
					vtable_name = vtable_name.replace('<', '_')
					vtable_name = vtable_name.replace(',', '_')
					vtable_name = vtable_name.replace('>', '_')
					vtable_name = vtable_name.removesuffix('__')
					vtable_name = vtable_name.removesuffix('_')

					if ida_idaapi.get_inf_structure().is_64bit():
						possible_vtables.append((vtable_name, type_ref.frm + 8))
					else:
						possible_vtables.append((vtable_name, type_ref.frm + 4))

	return possible_vtables

def GetBaseClassesPE(base_image, type_itself, num_classes, ptr_to_bca, known_bases):
	bases = []

	if ida_idaapi.get_inf_structure().is_64bit():
		ptr_to_bcd = base_image + ida_bytes.get_dword(ptr_to_bca)
	else:
		ptr_to_bcd = ida_bytes.get_dword(ptr_to_bca)

	if base_image + ida_bytes.get_dword(ptr_to_bcd) != type_itself:
		return None

	for i in range(1, num_classes):
		if ida_idaapi.get_inf_structure().is_64bit():
			ptr_to_bcd = base_image + ida_bytes.get_dword(ptr_to_bca + 4 * i)
		else:
			ptr_to_bcd = ida_bytes.get_dword(ptr_to_bca + 4 * i)

		if ida_idaapi.get_inf_structure().is_64bit():
			type = base_image + ida_bytes.get_dword(ptr_to_bcd)
		else:
			type = ida_bytes.get_dword(ptr_to_bcd)
		if IsNotValidAddress(type):
			break

		if ida_idaapi.get_inf_structure().is_64bit():
			ptr_to_chd = base_image + ida_bytes.get_dword(ptr_to_bcd + 4 * 6)
		else:
			ptr_to_chd = ida_bytes.get_dword(ptr_to_bcd + 4 * 6)
		if IsNotValidAddress(ptr_to_chd):
			break

		type_name = idc.get_strlit_contents(type + 4 * 2)
		if type_name:
			try:
				type_name = type_name.decode()
				type_name = re.search(r'\.\?AV\.?(\w+).*$', type_name)
				if type_name:
					type_name = type_name.group(1)
				else:
					type_name = ''
			except:
				type_name = ''
		else:
			type_name = ''

		if type_name == '':
			break
	
		type_refs = idautils.XrefsTo(type)
		for type_ref in type_refs:
			if ida_idaapi.get_inf_structure().is_64bit():
				base_ptr_to_chd = base_image + ida_bytes.get_dword(type_ref.frm + 4)
			else:
				base_ptr_to_chd = ida_bytes.get_dword(type_ref.frm + 4)
			if IsNotValidAddress(base_ptr_to_chd):
				continue

			num_base_classes = ida_bytes.get_dword(base_ptr_to_chd + 4 * 2)

			if ida_idaapi.get_inf_structure().is_64bit():
				base_classes = GetBaseClassesPE(base_image, type, num_base_classes, ida_bytes.get_dword(base_ptr_to_chd + 4 * 3), known_bases)
			else:
				base_classes = GetBaseClassesPE(0, type, num_base_classes, ida_bytes.get_dword(base_ptr_to_chd + 4 * 3), known_bases)

			if base_classes != None:
				obj_refs = idautils.XrefsTo(type_ref.frm - 4 * 3)
				for obj_ref in obj_refs:
					if ida_idaapi.get_inf_structure().is_64bit():
						vtable_name = ida_name.get_demangled_name(obj_ref.frm + 8, ida_name.M_PRCMSK | ida_name.MT_LOCALNAME, 0, ida_name.GN_DEMANGLED | ida_name.GN_STRICT | ida_name.GN_LOCAL)
					else:
						vtable_name = ida_name.get_demangled_name(obj_ref.frm + 4, ida_name.M_PRCMSK | ida_name.MT_LOCALNAME, 0, ida_name.GN_DEMANGLED | ida_name.GN_STRICT | ida_name.GN_LOCAL)
					if vtable_name:
						vtable_name_new = re.search(r'::`vftable\'+.*', vtable_name)
						if vtable_name_new:
							vtable_name = vtable_name.replace(vtable_name_new.group(), '')
						vtable_name_parts = vtable_name.rsplit('::')
						if vtable_name_parts[0] == '`anonymous namespace\'':
							vtable_name_parts = vtable_name_parts[1:]
						vtable_name = '::'.join(vtable_name_parts).replace('const ', '')
					is_dup = False
					for known_base in known_bases:
						if known_base[0] == vtable_name:
							is_dup = True
							break
					if is_dup != True:
						if ida_idaapi.get_inf_structure().is_64bit():
							bases.append((vtable_name, base_classes, obj_ref.frm + 8))
							known_bases.append((vtable_name, base_classes, obj_ref.frm + 8))
						else:
							bases.append((vtable_name, base_classes, obj_ref.frm + 4))
							known_bases.append((vtable_name, base_classes, obj_ref.frm + 4))

	bases.reverse()
	return bases

def FindMainTypesPE():
	types = []
	min_address = ida_ida.inf_get_min_ea()
	max_address = ida_ida.inf_get_max_ea()
	while True:
		address = ida_search.find_binary(min_address, max_address, '2E 3F 41 56 74 79 70 65 5F 69 6E 66 6F 40 40 00', 0, ida_search.SEARCH_DOWN)
		if IsNotValidAddress(address):
			break
		type_ptr = ida_bytes.get_dword(address - 4 * 2)
		if IsNotValidAddress(type_ptr):
			min_address = address + 16
			continue
		min_address = address + 16
		types.append((type_ptr, address - 4 * 2))
	return types

def FindVTablesPE(known_bases = None):
	possible_vtables = []
	base_image = idaapi.get_imagebase()
	
	if known_bases == None:
		known_bases = []

	main_types = FindMainTypesPE()
	for type_ptr, address in main_types:
		types = idautils.XrefsTo(type_ptr)
		for type in types:
			if ida_bytes.is_data(ida_bytes.get_flags(type.frm)) != True:
				continue

			type_name = idc.get_strlit_contents(type.frm + 4 * 2)
			if type_name:
				try:
					type_name = type_name.decode()
					type_name = re.search(r'\.\?AV\.?(\w+).*$', type_name)
					if type_name:
						type_name = type_name.group(1)
					else:
						type_name = ''
				except:
					type_name = ''
			else:
				type_name = ''

			if type_name == '':
				continue

			type_refs = idautils.XrefsTo(type.frm)
			for type_ref in type_refs:
				if ida_idaapi.get_inf_structure().is_64bit():
					ptr_to_chd = base_image + ida_bytes.get_dword(type_ref.frm + 4)
				else:
					ptr_to_chd = ida_bytes.get_dword(type_ref.frm + 4)
				if IsNotValidAddress(ptr_to_chd):
					continue

				num_base_classes = ida_bytes.get_dword(ptr_to_chd + 4 * 2)

				if ida_idaapi.get_inf_structure().is_64bit():
					ptr_to_bca = base_image + ida_bytes.get_dword(ptr_to_chd + 4 * 3)
				else:
					ptr_to_bca = ida_bytes.get_dword(ptr_to_chd + 4 * 3)
				if IsNotValidAddress(ptr_to_bca):
					continue

				if ida_idaapi.get_inf_structure().is_64bit():
					base_classes = GetBaseClassesPE(base_image, type.frm, num_base_classes, ptr_to_bca, known_bases)
				else:
					base_classes = GetBaseClassesPE(0, type.frm, num_base_classes, ptr_to_bca, known_bases)

				if base_classes != None:
					obj_refs = idautils.XrefsTo(type_ref.frm - 4 * 3)
					for obj_ref in obj_refs:
						if ida_idaapi.get_inf_structure().is_64bit():
							vtable_name = ida_name.get_demangled_name(obj_ref.frm + 8, ida_name.M_PRCMSK | ida_name.MT_LOCALNAME, 0, ida_name.GN_DEMANGLED | ida_name.GN_STRICT | ida_name.GN_LOCAL)
						else:
							vtable_name = ida_name.get_demangled_name(obj_ref.frm + 4, ida_name.M_PRCMSK | ida_name.MT_LOCALNAME, 0, ida_name.GN_DEMANGLED | ida_name.GN_STRICT | ida_name.GN_LOCAL)
						if vtable_name:
							vtable_name_new = re.search(r'::`vftable\'+.*', vtable_name)
							if vtable_name_new:
								vtable_name = vtable_name.replace(vtable_name_new.group(), '')
							vtable_name_parts = vtable_name.rsplit('::')
							if vtable_name_parts[0] == '`anonymous namespace\'':
								vtable_name_parts = vtable_name_parts[1:]
							vtable_name = '::'.join(vtable_name_parts).replace('const ', '')
						else:
							vtable_name = type_name
						is_dup = False
						for known_base in known_bases:
							if known_base[0] == vtable_name:
								is_dup = True
								break
						if is_dup != True:
							if ida_idaapi.get_inf_structure().is_64bit():
								possible_vtables.append((vtable_name, base_classes, obj_ref.frm + 8))
								known_bases.append((vtable_name, base_classes, obj_ref.frm + 8))
							else:
								possible_vtables.append((vtable_name, base_classes, obj_ref.frm + 4))
								known_bases.append((vtable_name, base_classes, obj_ref.frm + 4))

	return possible_vtables

def ProcessMACHO():
	db_path = pathlib.Path(idc.get_idb_path()).parent
	vtables = FindVTablesMACHO()
	if SEPARATE_IN_FILES != True:
		writtable_code = ''
		for vtable_name, vtable in vtables:
			if vtable_name:
				vtable_name_detected, vtable_class = GenerateVTableClass(vtable, vtable_name)
				if vtable_name_detected == 'UnknownClass':
					continue
				if vtable_name == '':
					vtable_name = vtable_name_detected
				if vtable_class:
					writtable_code += vtable_class
		with open(db_path.joinpath('SDK.h').__str__(), 'w+') as f:
			f.write(writtable_code)
	else:
		for vtable_name, vtable in vtables:
			if vtable_name:
				vtable_name_detected, vtable_class = GenerateVTableClass(vtable, vtable_name)
				if vtable_name_detected == 'UnknownClass':
					continue
				if vtable_name == '':
					vtable_name = vtable_name_detected
				if vtable_class:
					folder = db_path.joinpath('SDK')
					if pathlib.Path(folder).exists() != True:
						os.mkdir(folder)
					vtable_name = vtable_name.replace('&', '_')
					vtable_name = vtable_name.replace('*', '_')
					vtable_name = vtable_name.replace('(', '_')
					vtable_name = vtable_name.replace(')', '_')
					with open(folder.joinpath(vtable_name.replace('::', '__') + '.h').__str__(), 'w+') as f:
						f.write(vtable_class)

def GetBasesNames(bases, names = None):
	if names == None:
		names = set()
	for vtable_name, sub_bases, vtable_address in bases:
		if sub_bases:
			GetBasesNames(sub_bases, names)
		names.add(vtable_name)
	return names

def GenerateVTableBasesPE(bases, code = None, generated = None):
	if code == None:
		code = ''

	if generated == None:
		generated = []
	
	for vtable_name, sub_bases, vtable_address in bases:
		if sub_bases:
			code += GenerateVTableBasesPE(sub_bases, code, generated)

		if vtable_name in generated:
			continue

		vtable_name_detected, vtable_class = GenerateVTableClass(vtable_address, vtable_name)
		if vtable_class:
			code += vtable_class
			generated.append(vtable_name)

	return code

def ProcessPE():
	db_path = pathlib.Path(idc.get_idb_path()).parent
	if SEPARATE_IN_FILES != True:
		known_bases = []
		vtables = FindVTablesPE(known_bases)
		writtable_code = ''
		for vtable in vtables:
			if vtable[0]:
				bases_names = list(GetBasesNames(vtable[1]))
				bases_names.reverse()
				if bases_names:
					bases_code = GenerateVTableBasesPE(vtable[1], None, known_bases)
					if bases_code:
						generated_code = GenerateVTableWithBasesClass(vtable[2], bases_names, vtable[0])
						if generated_code[1] == None:
							continue
						writtable_code += bases_code + generated_code[1]
					else:
						continue
				else:
					generated_code = GenerateVTableClass(vtable[2], vtable[0])
					if generated_code[1] == None:
						continue
					writtable_code += generated_code[1]
				#folder = idc.get_root_filename().rsplit('.')[0]
				#if pathlib.Path(folder).exists() != True:
				#	os.mkdir(folder)
				#with open(db_path.joinpath(idc.get_root_filename().rsplit('.')[0]).joinpath(vtable[0].replace(':', '_') + '.h').__str__(), 'w+') as f:
				#	f.write(writtable_code)
		folder = idc.get_root_filename().rsplit('.')[0]
		if pathlib.Path(folder).exists() != True:
			os.mkdir(folder)
		with open(db_path.joinpath('SDK.h').__str__(), 'w+') as f:
			f.write(writtable_code)
	else:
		vtables = FindVTablesPE()
		for vtable in vtables:
			vtable_name, vtable_code = GenerateVTableClass(vtable[2], vtable[0])
			if vtable_name:
				folder = db_path.joinpath('SDK')
				if pathlib.Path(folder).exists() != True:
					os.mkdir(folder)
				vtable_name = vtable_name.replace('&', '_')
				vtable_name = vtable_name.replace('*', '_')
				vtable_name = vtable_name.replace('(', '_')
				vtable_name = vtable_name.replace(')', '_')
				with open(folder.joinpath(vtable_name.replace('::', '__') + '.h').__str__(), 'w+') as f:
					f.write(vtable_code)

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

		filetype = idaapi.get_inf_structure().filetype
		if filetype == idc.FT_MACHO:
			ProcessMACHO()
		elif filetype == idc.FT_PE:
			ProcessPE()
		else:
			idc.msg('[VTableDump] Error: Failed to generate VTables!\n')
			return

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
