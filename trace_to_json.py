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

import os
import re
import sys
import json
from FriendlyArgumentParser import FriendlyArgumentParser

class REGenerator():
	@classmethod
	def named_group(cls, name, regex):
		yield "(?P<%s>%s)" % (name, regex)

	@classmethod
	def hex_number(cls, name):
		yield from cls.named_group(name, "[A-Fa-f0-9]+")

	@classmethod
	def register(cls, regname):
		yield " ?"
		yield regname
		yield ":"
		yield from cls.hex_number(regname.lower())

	@classmethod
	def flag(cls, flagname):
		yield " ?"
		yield flagname
		yield ":"
		yield from cls.named_group(flagname.lower(), "[01]")

	@classmethod
	def trace(cls):
		yield r"^"
		yield from cls.hex_number("ips")
		yield r":"
		yield from cls.hex_number("ipo")
		yield r"\s+"
		yield from cls.named_group("mnemonic", ".{32}")
		yield from cls.named_group("description", ".{24}")
		yield from cls.named_group("opcode", ".{22}")
		for regname in [ "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "DS", "ES", "FS", "GS", "SS" ]:
			yield from cls.register(regname)
		for flagname in [ "CF", "ZF", "SF", "OF", "AF", "PF", "IF", "TF", "VM" ]:
			yield from cls.flag(flagname)
		yield from cls.register("FLG")
		yield from cls.register("CR0")

	@classmethod
	def compile(cls, generator_function):
		re_text = "".join(generator_function())
#		print(re_text)
		return re.compile(re_text)

class DosboxLogfile():
	_TRACE_RE = REGenerator.compile(REGenerator.trace)

	def __init__(self, args):
		self._args = args
		self._trace = [ ]

	def _parse_line(self, line):
		result = self._TRACE_RE.fullmatch(line)
		result = result.groupdict()
		for regname in [ "ips", "ipo", "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "ds", "es", "fs", "gs", "ss", "flg", "cr0" ]:
			result[regname] = int(result[regname], 16)
		for flagname in [ "cf", "zf", "sf", "of", "af", "pf", "if", "tf", "vm" ]:
			result[flagname] = int(result[flagname])
		for text in [ "mnemonic", "description" ]:
			result[text] = result[text].strip()
		result["opcode"] = result["opcode"].lower().replace(" ", "")
		return result

	def parse(self, filename):
		filesize = os.stat(filename).st_size
		pos = 0
		with open(filename) as f:
			for (lineno, line) in enumerate(f, 1):
				pos += len(line)
				if lineno % 25000 == 0:
					print("%s: %d lines processed, %.1f%%" % (filename, lineno, pos / filesize * 100))

				if (self._args.start is not None) and (lineno < self._args.start):
					continue

				line = line.rstrip("\r\n")
				insn = self._parse_line(line)
				self._trace.append(insn)

				if self._args.stop == lineno:
					print("Stop condition reached, line %d." % (self._args.stop))
					break

	def write_json(self, jsonfile):
		with open(jsonfile, "w") as f:
			json.dump(self._trace, f, separators = (",", ":"))

parser = FriendlyArgumentParser(description = "Convert DosBox full trace to JSON format.")
parser.add_argument("--start", metavar = "insn_no", type = int, help = "First line to include in tracefile. Defaults to 1.")
parser.add_argument("--stop", metavar = "insn_no", type = int, help = "Last line to include in tracefile. Defaults to end of file.")
parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increases verbosity. Can be specified multiple times to increase.")
parser.add_argument("infile", metavar = "infile", type = str, help = "Input trace file (typically called LOGCPU.TXT)")
parser.add_argument("outfile", metavar = "outfile", type = str, help = "Output JSON file")
args = parser.parse_args(sys.argv[1:])

log = DosboxLogfile(args)
log.parse(args.infile)
log.write_json(args.outfile)
