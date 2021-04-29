import logging

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import Section, StringTableSection

from unicorn import UC_PROT_ALL

from androidemu.internal import get_segment_protection, arm
from androidemu.internal.module import Module
from androidemu.internal.symbol_resolved import SymbolResolved

import struct

logger = logging.getLogger(__name__)

from elftools.elf.sections import SymbolTableSection

class VirtualSection(Section):
    def __init__(self, header, name, stream):
        super.__init__(self._header, name, stream)

class MyElffile(ELFFile):
    def __init__(self, stream):
        super(MyElffile, self).__init__(stream)

    def get_dynamic(self, tag):
        for seg in self.iter_segments():
            if seg.header.p_type == "PT_DYNAMIC":
                for dyn in seg.iter_tags():
                    if dyn.entry.d_tag == tag:
                        return dyn.entry.d_val

    def rva_to_offset(self, rva):
        load_segments = [x for x in self.iter_segments() if x.header.p_type == 'PT_LOAD']
        for seg in load_segments:
            if seg.header.p_vaddr <= rva < seg.header.p_vaddr + seg.header.p_memsz:
                return rva - seg.header.p_vaddr + seg.header.p_offset
        return rva

    def get_dynmic_str_section(self):

        str_addr = self.get_dynamic("DT_STRTAB")

        section_header = {}
        section_header['sh_entsize'] = 0
        section_header['sh_addr'] = str_addr
        section_header['sh_offset'] = self.rva_to_offset(str_addr)
        section_header['sh_size'] = self.get_dynamic("DT_STRSZ")
        return StringTableSection(section_header, "str", self.stream)

    def get_dynmic_symbol(self):

        symbol_addr = self.get_dynamic("DT_SYMTAB")

        sec_header = {}
        sec_header['sh_entsize'] = self.get_dynamic('DT_SYMENT')
        sec_header['sh_addr'] = symbol_addr
        sec_header['sh_offset'] = self.rva_to_offset(symbol_addr)
        sec_header['sh_size'] = int(self.get_dynamic("DT_RELSZ") / 8) * self.get_dynamic("DT_SYMENT")

        sec = Section(sec_header, ".dynsym", self.stream)

        return SymbolTableSection(
            sec, ".dynsym", self.stream,
            elffile=self,
            stringtable=self.get_dynmic_str_section())


    def get_dynmic_rel(self):
        rel_addr = self.get_dynamic("DT_REL")

        section_header = {}
        section_header['sh_entsize'] = self.get_dynamic("DT_RELENT")
        section_header['sh_size'] = self.get_dynamic("DT_RELSZ")
        section_header['sh_offset'] = self.rva_to_offset(rel_addr)
        section_header['sh_addr'] = rel_addr
        section_header['sh_type'] = 'SHT_REL'
        yield RelocationSection(section_header, ".rel", self.stream, self)

        rel_addr = self.get_dynamic("DT_RELA")
        if rel_addr != None:
            section_header = {}
            section_header['sh_entsize'] = self.get_dynamic("DT_RELAENT")
            section_header['sh_size'] = self.get_dynamic("DT_RELASZ")
            section_header['sh_offset'] = self.rva_to_offset(rel_addr)
            section_header['sh_addr'] = rel_addr
            section_header['sh_type'] = 'SHT_RELA'
            yield RelocationSection(section_header, ".rel", self.stream, self)

        rel_addr = self.get_dynamic("DT_JMPREL")
        if rel_addr != None:
            section_header = {}
            section_header['sh_entsize'] = 8
            section_header['sh_size'] = self.get_dynamic("DT_PLTRELSZ")
            section_header['sh_offset'] = self.rva_to_offset(rel_addr)
            section_header['sh_addr'] = rel_addr
            section_header['sh_type'] = 'SHT_REL'
            yield RelocationSection(section_header, ".rel", self.stream, self)


class Modules:
    """
    :type emu androidemu.emulator.Emulator
    :type modules list[Module]
    """
    def __init__(self, emu):
        self.emu = emu
        self.modules = list()
        self.symbol_hooks = dict()

    def add_symbol_hook(self, symbol_name, addr):
        self.symbol_hooks[symbol_name] = addr

    def find_symbol(self, addr):
        for module in self.modules:
            if addr in module.symbol_lookup:
                return module.symbol_lookup[addr]
        return None, None


    def load_module(self, filename):
        logger.debug("Loading module '%s'." % filename)

        with open(filename, 'rb') as fstream:
            elf = MyElffile(fstream)

            dynamic = elf.header.e_type == 'ET_DYN'

            if not dynamic:
                raise NotImplementedError("Only ET_DYN is supported at the moment.")

            # Parse program header (Execution view).

            # - LOAD (determinate what parts of the ELF file get mapped into memory)
            load_segments = [x for x in elf.iter_segments() if x.header.p_type == 'PT_LOAD']


            # Find bounds of the load segments.
            bound_low = 0
            bound_high = 0

            for segment in load_segments:
                if segment.header.p_memsz == 0:
                    continue

                if bound_low > segment.header.p_vaddr:
                    bound_low = segment.header.p_vaddr

                high = segment.header.p_vaddr + segment.header.p_memsz

                if bound_high < high:
                    bound_high = high

            # Retrieve a base address for this module.
            load_base = self.emu.memory.mem_reserve(bound_high - bound_low)

            for segment in load_segments:
                #prot = get_segment_protection(segment.header.p_flags)
                #prot = prot if prot is not 0 else UC_PROT_ALL
                prot = UC_PROT_ALL
                self.emu.memory.mem_map(load_base + segment.header.p_vaddr, segment.header.p_memsz, prot)
                self.emu.memory.mem_write(load_base + segment.header.p_vaddr, segment.data())

            rel_section = None
            for section in elf.iter_sections():
                if not isinstance(section, RelocationSection):
                    continue
                rel_section = section
                break

            #rel_section = elf.get_dynmic_rel()

            # Parse section header (Linking view).
            dynsym = elf.get_section_by_name(".dynsym")
            #dynsym = elf.get_dynmic_symbol()



            dynsym_off = 0
            dynstr_off = 0

            # Find init array.

            init_array_size = 0
            init_array_offset = 0
            init_array = []
            for x in elf.iter_segments():
                if x.header.p_type == "PT_DYNAMIC":
                    try:
                        for tag in x.iter_tags():
                            if tag.entry.d_tag == "DT_INIT_ARRAYSZ":
                                init_array_size = tag.entry.d_val
                            elif tag.entry.d_tag == "DT_INIT_ARRAY":
                                init_array_offset = tag.entry.d_val
                            elif tag.entry.d_tag == "DT_SYMTAB":
                                dynsym_off = tag.entry.d_val
                            elif tag.entry.d_tag == "DT_STRTAB":
                                dynstr_off = tag.entry.d_val
                    except UnicodeDecodeError:
                        pass


            for _ in range(int(init_array_size / 4)):
                # covert va to file offset
                for seg in load_segments:
                    if seg.header.p_vaddr <= init_array_offset < seg.header.p_vaddr + seg.header.p_memsz:
                        init_array_foffset = init_array_offset - seg.header.p_vaddr + seg.header.p_offset
                fstream.seek(init_array_foffset)
                data = fstream.read(4)
                fun_ptr = struct.unpack('I', data)[0]
                if fun_ptr != 0:
                    # fun_ptr += load_base
                    init_array.append(fun_ptr + load_base)
                    print ("find init array for :%s %x" % (filename, fun_ptr))
                else:
                    # search in reloc
                    for rel in rel_section.iter_relocations():
                        rel_info_type = rel['r_info_type']
                        rel_addr = rel['r_offset']
                        if rel_info_type == arm.R_ARM_ABS32 and rel_addr == init_array_offset:
                            sym = dynsym.get_symbol(rel['r_info_sym'])
                            sym_value = sym['st_value']
                            init_array.append(load_base + sym_value)
                            #print ("find init array for :%s %x" % (filename, sym_value))
                            break
                init_array_offset += 4

            # Resolve all symbols.
            symbols_resolved = dict()

            for section in elf.iter_sections():
                if not isinstance(section, SymbolTableSection):
                    continue
                itersymbols = section.iter_symbols()
                next(itersymbols)  # Skip first symbol which is always NULL.
                for symbol in itersymbols:

                    symbol_address = self._elf_get_symval(elf, load_base, symbol)

                    if symbol_address is not None:

                        symbols_resolved[symbol.name] = SymbolResolved(symbol_address, symbol)
                        #print ("symbol:%s addr:%x" % (symbol.name, symbol_address))

            # Relocate.
            for section in elf.iter_sections():
                if not isinstance(section, RelocationSection):
                    continue
            #for relsection in elf.get_dynmic_rel():
                for rel in section.iter_relocations():
                    sym = dynsym.get_symbol(rel['r_info_sym'])
                    sym_value = sym['st_value']

                    rel_addr = load_base + rel['r_offset']  # Location where relocation should happen
                    rel_info_type = rel['r_info_type']


                    # Relocation table for ARM
                    if rel_info_type == arm.R_ARM_ABS32:
                        # Create the new value.
                        value = load_base + sym_value
                        # Write the new value
                        self.emu.mu.mem_write(rel_addr, value.to_bytes(4, byteorder='little'))

                    elif rel_info_type == arm.R_ARM_GLOB_DAT or \
                            rel_info_type == arm.R_ARM_JUMP_SLOT or \
                            rel_info_type == arm.R_AARCH64_GLOB_DAT or \
                            rel_info_type == arm.R_AARCH64_JUMP_SLOT:
                        # Resolve the symbol.
                        if sym.name in symbols_resolved:
                            value = symbols_resolved[sym.name].address

                            # Write the new value
                            self.emu.mu.mem_write(rel_addr, value.to_bytes(4, byteorder='little'))
                    elif rel_info_type == arm.R_ARM_RELATIVE or \
                            rel_info_type == arm.R_AARCH64_RELATIVE:
                        if sym_value == 0:
                            # Load address at which it was linked originally.
                            value_orig_bytes = self.emu.mu.mem_read(rel_addr, 4)
                            value_orig = int.from_bytes(value_orig_bytes, byteorder='little')

                            # Create the new value
                            value = load_base + value_orig

                            # Write the new value
                            self.emu.mu.mem_write(rel_addr, value.to_bytes(4, byteorder='little'))
                        else:
                            raise NotImplementedError()
                    else:
                        logger.error("Unhandled relocation type %i." % rel_info_type)

            # Store information about loaded module.
            module = Module(filename, load_base, bound_high - bound_low, symbols_resolved, init_array)
            self.modules.append(module)

            #do init


            return module

    def _elf_get_symval(self, elf, elf_base, symbol):
        if symbol.name in self.symbol_hooks:
            return self.symbol_hooks[symbol.name]

        if symbol['st_shndx'] == 'SHN_UNDEF':
            # External symbol, lookup value.
            target = self._elf_lookup_symbol(symbol.name)
            if target is None:
                # Extern symbol not found
                if symbol['st_info']['bind'] == 'STB_WEAK':
                    # Weak symbol initialized as 0
                    return 0
                else:
                    logger.error('=> Undefined external symbol: %s' % symbol.name)
                    return None
            else:
                return target
        elif symbol['st_shndx'] == 'SHN_ABS':
            # Absolute symbol.
            return elf_base + symbol['st_value']
        else:
            # Internally defined symbol.
            return elf_base + symbol['st_value']

    def _elf_lookup_symbol(self, name):
        for module in self.modules:
            if name in module.symbols:
                symbol = module.symbols[name]

                if symbol.address != 0:
                    return symbol.address

        return None

    def __iter__(self):
        for x in self.modules:
            yield x
