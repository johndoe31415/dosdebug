#!/usr/bin/env python3
#	doscheat - Python GDB commands for DOSBox debugging
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
import collections
from FriendlyArgumentParser import FriendlyArgumentParser
from Tracefile import Tracefile

class DecodedSyscall():
	def __init__(self, name, parameters = None, results = None):
		self._name = name
		self._parameters = parameters
		self._results = results

	@property
	def name(self):
		return self._name

	@property
	def parameters(self):
		return self._parameters

	@property
	def parameter_string(self):
		return ", ".join("%s = %s" % (key, value) for (key, value) in self.parameters)

	@property
	def results(self):
		return self._results

	@property
	def result_string(self):
		return ", ".join("%s = %s" % (key, value) for (key, value) in self.results)

	def __str__(self):
		text = [ self.name ]
		if self.parameters is not None:
			text.append(" ")
			text.append(self.parameter_string)
		if self.results is not None:
			text.append(" -> ")
			text.append(self.result_string)
		return "".join(text)

class Stracer():
	_FILE_ERROR_CODES = {
		2:	"file not found",
		3:	"path not found",
		4:	"no handle available",
		5:	"access denied",
		6:	"invalid handle",
		12:	"access code invalid",
	}

	def __init__(self, args):
		self._args = args
		self._trace = Tracefile(self._args.infile, verbose = (self._args.verbose >= 1))
		self._unknown_syscall_count = collections.Counter()
		self._filepos = { }

	def _decode_select(self, options, value):
		return options.get(value, "unknown (0x%x)" % (value))

	def _handle_3c(self, insn, follow_insn):
		results = None
		if follow_insn is not None:
			if follow_insn["cf"] == 0:
				results = (("handle", str(follow_insn["eax"])), )
			else:
				results = (("error", self._decode_select(self._FILE_ERROR_CODES, follow_insn["eax"])), )
		return DecodedSyscall(name = "CREATE", parameters = (
			("filename", "%04x:%04x" % (insn["ds"], insn["edx"])),
			("attributes", self._decode_select({
				0: "normal",
				1: "read only",
				2: "hidden",
				3: "system",
			}, insn["ecx"])),
		), results = results)

	def _handle_rdwrite(self, name, insn, follow_insn):
		handle = insn["ebx"]
		parameters = [
			("handle", "%d" % (handle)),
			("length", "%d" % (insn["ecx"])),
			("buffer", "%04x:%04x" % (insn["ds"], insn["edx"])),
		]

		results = None
		if follow_insn is not None:
			if follow_insn["cf"] == 0:
				length = follow_insn["eax"]
				parameters.append(("old_offset", self._filepos[handle]))
				if handle in self._filepos:
					self._filepos[handle] += length
				parameters.append(("new_offset", self._filepos[handle]))
				results = (("length", length), )
			else:
				results = (("error", self._decode_select(self._FILE_ERROR_CODES, follow_insn["eax"])), )
		return DecodedSyscall(name = name, parameters = parameters, results = results)

	def _handle_3d(self, insn, follow_insn):
		results = None
		if follow_insn is not None:
			if follow_insn["cf"] == 0:
				handle = follow_insn["eax"]
				results = (("handle", handle), )
				self._filepos[handle] = 0
			else:
				results = (("error", self._decode_select(self._FILE_ERROR_CODES, follow_insn["eax"])), )
		return DecodedSyscall(name = "OPEN", parameters = (
			("mode", self._decode_select({
				0: "read",
				1: "write",
				2: "read/write"
			}, insn["eax"] & 0xff)),
			("filename", "%04x:%04x" % (insn["ds"], insn["edx"])),
		), results = results)

	def _handle_3e(self, insn, follow_insn):
		results = None
		if follow_insn is not None:
			if follow_insn["cf"] == 0:
				results = (("success", True), )
			else:
				results = (("error", self._decode_select(self._FILE_ERROR_CODES, follow_insn["eax"])), )
		handle = insn["ebx"]
		if handle in self._filepos:
			del self._filepos[handle]
		return DecodedSyscall(name = "CLOSE", parameters = (
			("handle", handle),
		), results = results)

	def _handle_3f(self, insn, follow_insn):
		return self._handle_rdwrite("READ", insn, follow_insn)

	def _handle_40(self, insn, follow_insn):
		return self._handle_rdwrite("WRITE", insn, follow_insn)

	def _handle_4c(self, insn, follow_insn):
		return DecodedSyscall(name = "EXIT", parameters = (
			("returncode", insn["eax"] & 0xff),
		))

	def _handle_int21(self, insn, follow_insn):
		ah = (insn["eax"] >> 8) & 0xff
		al = (insn["eax"] >> 0) & 0xff
		handler_name = "_handle_%02x" % (ah)
		handler = getattr(self, handler_name, None)
		if handler is not None:
			decoded = handler(insn, follow_insn)
			print("%d: [%02x] %s" % (insn["i"], ah, str(decoded)))
		else:
			print("%d: [%02x] Unknown syscall" % (insn["i"], ah))
			self._unknown_syscall_count[ah] += 1

	def run(self):
		for (insn_index, insn) in enumerate(self._trace):
			if insn["opcode"] == "cd21":
				follow_insn = None
				for (candidate, next_candidate) in zip(self._trace[insn_index + 1 : insn_index + 10 ], self._trace[insn_index + 2 : ]):
					# "iret" found
					if candidate["opcode"] == "cf":
						# Choose instruction following the iret for the return values
						follow_insn = next_candidate
						break
				self._handle_int21(insn, follow_insn)

		if self._args.verbose >= 1:
			if len(self._unknown_syscall_count) > 0:
				print()
				print("Unknown syscalls encountered:")
				for (ah, count) in self._unknown_syscall_count.most_common():
					print("   %5d 0x%02x" % (count, ah))

parser = FriendlyArgumentParser(description = "Perform a DosBox system call trace on a trace log in JSON format.")
parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increases verbosity. Can be specified multiple times to increase.")
parser.add_argument("infile", metavar = "infile", type = str, help = "Input trace file in JSON format")
args = parser.parse_args(sys.argv[1:])

stracer = Stracer(args)
stracer.run()
