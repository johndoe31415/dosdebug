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

class Stracer():
	def __init__(self, args):
		self._args = args
		self._trace = self._load_tracefile()

	def _load_tracefile(self):
		t0 = time.time()
		with open(args.infile) as f:
			trace = json.load(f)
		t1 = time.time()
		tdiff = t1 - t0
		if self._args.verbose >= 1:
			print("Loaded %d traced instructions in %.1f secs (%.0f insn/sec)" % (len(trace), tdiff, len(trace) / tdiff))
		return trace

	def _handle_int21(self, insn_no, insn, follow_insn):
		ah = (insn["eax"] >> 8) & 0xff
		if ah == 0x3d:
			if follow_insn["cf"] == 0:
				result = "handle %d" % (follow_insn["eax"])
			else:
				result = "failure error code 0x%02x" % (follow_insn["eax"])
			print("%d: OPEN filename in %04x:%04x -> %s" % (insn_no, insn["ds"], insn["edx"], result))
		elif ah == 0x3e:
			print("%d: CLOSE file %d" % (insn_no, insn["ebx"]))
		elif ah == 0x3f:
			print("%d: READ file %d, length %d, store in %04x:%04x" % (insn_no, insn["ebx"], insn["ecx"], insn["ds"], insn["edx"]))
		elif ah == 0x40:
			print("%d: WRITE file %d, length %d, load from %04x:%04x" % (insn_no, insn["ebx"], insn["ecx"], insn["ds"], insn["edx"]))
		elif ah == 0x41:
			print("%d: UNLINK filename in %04x:%04x" % (insn_no, insn["ds"], insn["edx"]))
		else:
			print("%d: Unknown syscall AH = 0x%02x" % (insn_no, ah))

	def run(self):
		for (insn_no, (insn, follow_insn)) in enumerate(zip(self._trace, self._trace[1:]), 1):
			if insn["opcode"] == "cd21":
				self._handle_int21(insn_no, insn, follow_insn)

parser = FriendlyArgumentParser(description = "Perform a DosBox system call trace on a trace log in JSON format.")
parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increases verbosity. Can be specified multiple times to increase.")
parser.add_argument("infile", metavar = "infile", type = str, help = "Input trace file in JSON format")
args = parser.parse_args(sys.argv[1:])

stracer = Stracer(args)
stracer.run()
