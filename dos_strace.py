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

import sys
import json
import time
from FriendlyArgumentParser import FriendlyArgumentParser
from Tracefile import Tracefile

class Stracer():
	def __init__(self, args):
		self._args = args
		self._trace = Tracefile(self._args.infile, verbose = (self._args.verbose >= 1))

	def _handle_int21(self, insn, follow_insn):
		ah = (insn["eax"] >> 8) & 0xff
		if ah == 0x3d:
			if follow_insn["cf"] == 0:
				result = "handle %d" % (follow_insn["eax"])
			else:
				result = "failure error code 0x%02x" % (follow_insn["eax"])
			print("%d: OPEN filename in %04x:%04x -> %s" % (insn["i"], insn["ds"], insn["edx"], result))
		elif ah == 0x3e:
			print("%d: CLOSE file %d" % (insn["i"], insn["ebx"]))
		elif ah == 0x3f:
			print("%d: READ file %d, length %d, store in %04x:%04x" % (insn["i"], insn["ebx"], insn["ecx"], insn["ds"], insn["edx"]))
		elif ah == 0x40:
			print("%d: WRITE file %d, length %d, load from %04x:%04x" % (insn["i"], insn["ebx"], insn["ecx"], insn["ds"], insn["edx"]))
		elif ah == 0x41:
			print("%d: UNLINK filename in %04x:%04x" % (insn["i"], insn["ds"], insn["edx"]))
		else:
			print("%d: Unknown syscall AH = 0x%02x" % (insn["i"], ah))

	def run(self):
		for (insn, follow_insn) in zip(self._trace, self._trace[1:]):
			if insn["opcode"] == "cd21":
				self._handle_int21(insn, follow_insn)

parser = FriendlyArgumentParser(description = "Perform a DosBox system call trace on a trace log in JSON format.")
parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increases verbosity. Can be specified multiple times to increase.")
parser.add_argument("infile", metavar = "infile", type = str, help = "Input trace file in JSON format")
args = parser.parse_args(sys.argv[1:])

stracer = Stracer(args)
stracer.run()
