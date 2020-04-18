#!/usr/bin/env python3
#	doscheat - Python GDB commands for DOSBox debugging
#	Copyright (C) 2020-2020 Johannes Bauer
#
#	This file is part of doscheat.
#
#	doscheat is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	doscheat is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with doscheat; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>

class DosboxCommand(PyGDBCommand):
	def _read_guest_regs(self):
		result = { }
		for (segno, segname) in enumerate([ "es", "cs", "ss", "ds", "fs", "gs" ]):
			result[segname] = self._resolve_expression("Segs.val[%d]" % (segno))
		for (regno, regname) in enumerate([ "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" ]):
			result[regname] = self._resolve_expression("cpu_regs.regs[%d].dword[0]" % (regno))
		result["eip"] = self._resolve_expression("cpu_regs.ip.dword[0]")
		return result

	def _guest_readmem(self, linear_address, length):
		host_address = self._resolve_expression("MemBase+%d" % (linear_address))
		data = self._read_memory(host_address, length)
		return data

	def _guest_readmem_seg_offset(self, segment, offset, length):
		linear_address = (0x10 * segment) + offset
		return self._guest_readmem(linear_address, length)

	def _parse_address(self, address):
		if ":" in address:
			(segment, offset) = address.split(":")
			return (0x10 * int(segment, 16)) + int(offset, 16)
		else:
			return self._resolve_expression(address)

@PyGDBCommand.register
class CaptureValueCommand(DosboxCommand):
	_CMD_NAME = "gregs"
	_HELP_PAGE = "Print the DOSBox guest registers."
	_ARGS = [ ]
	_OPTARGS = [ ]

	def run(self):
		guest_regs = self._read_guest_regs()
		print("eax %8x ebx %8x ecx %8x edx %8x" % (guest_regs["eax"], guest_regs["ebx"], guest_regs["ecx"], guest_regs["edx"]))

@PyGDBCommand.register
class CaptureValueCommand(DosboxCommand):
	_CMD_NAME = "gip"
	_HELP_PAGE = "Print the DOSBox guest IP."
	_ARGS = [ ]
	_OPTARGS = [ ]

	def run(self):
		guest_regs = self._read_guest_regs()
		print("Guest IP: %04x:%04x" % (guest_regs["cs"], guest_regs["eip"]))

@PyGDBCommand.register
class CaptureValueCommand(DosboxCommand):
	_CMD_NAME = "ghexdump"
	_HELP_PAGE = "Print the DOSBox guest memory at a particular location"
	_ARGS = [ "address", "length" ]
	_OPTARGS = [ ]

	def run(self, address, length):
		start_value = self._parse_address(address)
		length_value = self._resolve_expression(length)
		data = self._guest_readmem(start_value, length_value)
		HexDump().dump(data)

@PyGDBCommand.register
class CaptureValueCommand(DosboxCommand):
	_CMD_NAME = "gbt"
	_HELP_PAGE = "Print the DOSBox guest backtrace"
	_ARGS = [ ]
	_OPTARGS = [ ]

	def _print_frame(self, segment, offset, count = 1):
		for frameno in range(count):
			last_offset_segment = self._guest_readmem_seg_offset(segment, offset, 16)
			HexDump().dump(last_offset_segment)
			last = int.from_bytes(last_offset_segment[0 : 2], byteorder = "little")
			offset = int.from_bytes(last_offset_segment[2 : 4], byteorder = "little")
			segment = int.from_bytes(last_offset_segment[4 : 6], byteorder = "little")
			print("Frame %2d: return %04x:%04x BP %04x" % (frameno, segment, offset, last))
			offset = last

	def run(self):
		regs = self._read_guest_regs()
		self._print_frame(regs["ss"], regs["ebp"], 6)
