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
from FriendlyArgumentParser import FriendlyArgumentParser
from Tracefile import Tracefile

class TracefileFilter():
	def __init__(self, args):
		self._args = args
		self._include = set(self._args.include)

	def _create_filter_predicate(self):
		components = [ ]

		if "syscall" in self._include:
			# Int21 or instruction after iret (to capture return value)
			followup_insn = 0
			def predicate_syscall(insn):
				nonlocal followup_insn
				if insn["opcode"] == "cd21":
					# Int21
					return True
				elif insn["opcode"] == "cf":
					# Iret, capture /next/ instruction as well for return code
					followup_insn = insn["i"] + 1
					return True
				return insn["i"] == followup_insn
			components.append(predicate_syscall)

		return lambda insn: any(component(insn) for component in components)

	def run(self):
		trace = Tracefile(self._args.infile, verbose = (args.verbose >= 1))
		trace.filter_range(self._args.start, self._args.stop)
		if not "all" in self._include:
			trace.filter(self._create_filter_predicate())
		trace.write(self._args.outfile)

parser = FriendlyArgumentParser(description = "Filter a DosBox full trace file to JSON format.")
parser.add_argument("-i", "--include", choices = [ "all", "syscall" ], action = "append", default = [ ], required = True, help = "Include which portions of the original trace file. Can be any of %(choices)s and can be specified multiple times.")
parser.add_argument("--start", metavar = "insn_no", type = int, help = "First instruction to include in tracefile. Defaults to 1.")
parser.add_argument("--stop", metavar = "insn_no", type = int, help = "Last instruction to include in tracefile. Defaults to last instruction.")
parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increases verbosity. Can be specified multiple times to increase.")
parser.add_argument("infile", metavar = "infile", type = str, help = "Input trace file in JSON format")
parser.add_argument("outfile", metavar = "outfile", type = str, help = "Output trace file, filtered, in JSON format")
args = parser.parse_args(sys.argv[1:])

tffilter = TracefileFilter(args)
tffilter.run()
