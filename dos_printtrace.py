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
import time
import json
import importlib
import re
from FriendlyArgumentParser import FriendlyArgumentParser
from Tracefile import Tracefile

class InsnPrinter():
	_mem_ref = re.compile("(?P<segname>.s):\[(?P<addr>[a-fA-F0-9]+)\]=(?P<value>[a-fA-F0-9]+)")

	def __init__(self, args):
		self._args = args
		self._trace = Tracefile(args.infile, verbose = (self._args.verbose >= 1))
		self._run_substitutions()
		self._last_regset = { }
		self._labels = self._read_labels(self._args.labels)
		self._resolve_description_addresses()

	def _resolve_description_addresses(self):
		for tracepoint in self._trace:
			result = self._mem_ref.fullmatch(tracepoint["description"])
			if result is None:
				continue
			result = result.groupdict()
			segment = tracepoint[result["segname"]]
			offset = int(result["addr"], 16)
			value = int(result["value"], 16)
			linear = (segment * 0x10) + offset
			if linear in self._labels["addresses"]:
				linear_str = self._labels["addresses"][linear]
			else:
				linear_str = "0x%x" % (linear)
			tracepoint["description"] = "%s[%x] = [%s] = %x" % (result["segname"], offset, linear_str, value)

	def _read_labels(self, filename):
		result = {
			"tracepoints": { },
			"addresses": { },
		}
		if filename is not None:
			with open(filename) as f:
				labels = json.load(f)
			if "tracepoints" in labels:
				result["tracepoints"] = { int(key): value for (key, value) in labels["tracepoints"].items() }
			if "addresses" in labels:
				for (address, name) in labels["addresses"].items():
					if ":" in address:
						(seg, off) = address.split(":")
						linear = (int(seg, 16) * 0x10) + int(off, 16)
					else:
						linear = int(address, 16)
					result["addresses"][linear] = name
		return result

	def _run_substitution(self, module_name, config):
		t0 = time.time()
		if self._args.verbose >= 1:
			print("Running substitutions from module %s" % (module_name))

		module = importlib.import_module(module_name)
		instance = module.InstructionSubstitute(config, self._trace)
		instance.run()

		t1 = time.time()
		if self._args.verbose >= 2:
			tdiff = t1 - t0
			print("Substitutions of %s finished after %.1f sec" % (module_name, tdiff))

	def _run_substitutions(self):
		global_config = { }
		for config_file in self._args.config:
			with open(config_file) as f:
				config = json.load(f)
			global_config.update(config)

		if self._args.verbose >= 2:
			print("Configuration: %s" % (global_config))

		for substitution_module in self._args.substitute:
			self._run_substitution(substitution_module, global_config)

	def _format_addr(self, segment, offset):
		if self._args.address == "actual":
			return "%04x:%04x" % (segment, offset)
		elif self._args.address == "linear":
			linear = (segment * 0x10) + offset
			return "0x%06x" % (linear)
		elif self._args.address == "normalized":
			linear = (segment * 0x10) + offset
			nsegment = (addr & 0xf0000) >> 4
			noffset = addr & 0x0ffff
			assert((nsegment * 0x10) + noffset == addr)
			return "%04x:%04x" % (nsegment, noffset)
		else:
			raise NotImplementedError(self._args.address)

	def _gap(self, gapsize):
		print("Gap of %d instructions" % (gapsize))
		self._last_regset = { }

	def _insn(self, tracepoint):
		components = [ ]
		components.append("%6d" % (tracepoint["i"]))
		components.append(" ")
		components.append("%s:" % (self._format_addr(tracepoint["ips"], tracepoint["ipo"])))
		components.append("%-30s" % (tracepoint["mnemonic"].lower()))
		components.append("%-30s" % (tracepoint["description"].lower()))
		for reg in [ "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp" ]:
			value = tracepoint[reg]
			if (self._last_regset.get(reg) == value) and (not self._args.full_regs):
				# Same value
				components.append(" " * 9)
			else:
				self._last_regset[reg] = value
				components.append("%6x %s" % (value, reg[1:]))

		text = " ".join(components)
		print(text)

	def _pseudo(self, tracepoint):
		components = [ ]
		components.append("%6d" % (tracepoint["i"]))
		components.append("+")
		components.append("%s:" % (self._format_addr(tracepoint["ips"], tracepoint["ipo"])))
		components.append("%-40s" % (tracepoint["pseudo"]))
		components.append("%-30s" % (tracepoint["description"]))
		text = " ".join(components)
		print(text)

	def run(self):
		for tracepoint in self._trace:
			if tracepoint.get("type") == "gap":
				gap = tracepoint["gap"]
				self._gap(gap)
				continue

			linear = (tracepoint["ips"] * 0x10) + tracepoint["ipo"]
			if tracepoint["i"] in self._labels["tracepoints"]:
				print()
				print("[%s]:" % (self._labels["tracepoints"][tracepoint["i"]]))
			elif linear in self._labels["addresses"]:
				print()
				print("%s:" % (self._labels["addresses"][linear]))

			if "type" not in tracepoint:
				# Regular tracepoint
				self._insn(tracepoint)
			elif tracepoint["type"] == "hidden":
				if self._args.show_hidden:
					self._insn(tracepoint)
			elif tracepoint["type"] == "pseudo":
				self._pseudo(tracepoint)
			else:
				print("Unknown type: %s" % (tracepoint["type"]))

parser = FriendlyArgumentParser(description = "Print a DOSBox trace log in JSON format.")
parser.add_argument("-l", "--labels", metavar = "file", help = "Read label definition from this file.")
parser.add_argument("-c", "--config", metavar = "file", action = "append", default = [ ], help = "Substitutions are passed configuration, consisting of a dictionary. This is parsed from a JSON document. Can also be specified multiple times, later options will override previous settings.")
parser.add_argument("-s", "--substitute", metavar = "file", action = "append", default = [ ], help = "Run specific substitutions laid out in a Python file; can be specified multiple times to run more than one module. These can be used to pretty-print code or combine multiple instructions into pseudo-ops to improve readablility (e.g., 32 bit addition or multiplication in 16 bit mode).")
parser.add_argument("-a", "--address", choices = [ "actual", "linear", "normalized" ], default = "actual", help = "Display addresses of instructions in different modes. Can be any of %(choices)s, defaults to %(default)s.")
parser.add_argument("--show-hidden", action = "store_true", help = "Show instructions that would be hidden (e.g., because they've been replaced by pseudo-ops)")
parser.add_argument("--full-regs", action = "store_true", help = "Show full register set for every instruction instead of just the delta.")
parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increases verbosity. Can be specified multiple times to increase.")
parser.add_argument("infile", metavar = "infile", type = str, help = "Input trace file in JSON format")
args = parser.parse_args(sys.argv[1:])

insnprinter = InsnPrinter(args)
insnprinter.run()
