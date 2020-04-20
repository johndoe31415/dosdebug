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

from Tracefile import TracepointRegex

class InstructionSubstitute():
	_SUPPORTED_OPTIONS = [ "mul32-entry" ]

	def __init__(self, options, trace):
		self._options = options
		self._trace = trace

	def _run_mul32(self):
		if "mul32-entry" not in self._options:
			return

		for finding in self._trace.regex_substitution([
			TracepointRegex.compile(r"push (?P<param1>.*)"),
			TracepointRegex.compile(r"push (?P<param2>.*)"),
			TracepointRegex.compile(r"push (?P<param3>.*)"),
			TracepointRegex.compile(r"push (?P<param4>.*)"),
			TracepointRegex.compile(r"call %s" % (self._options["mul32-entry"])),
			TracepointRegex.compile(r"ret.*", min_count = 0, max_count = 30, invert = True),
			TracepointRegex.compile(r"ret.*"),
		]):
			finding.str_subs("mul32 %s:%s, %s:%s" % (finding["param1"], finding["param2"], finding["param3"], finding["param4"]))

	def _run_op32(self):
		for finding in self._trace.regex_substitution([
			TracepointRegex.compile(r"(?P<op>mov|xor)  (?P<_reg>.x),(?P<_val>[a-fA-F0-9]{4})"),
			TracepointRegex.compile(r"(?P<op>mov|xor)  (?P<_reg>.x),(?P<_val>[a-fA-F0-9]{4})"),
		]):
			registers = set(groupdict["_reg"] for groupdict in finding.groupdicts)
			if registers == set([ "ax", "dx" ]):
				values = { groupdict["_reg"]: int(groupdict["_val"], 16) for groupdict in finding.groupdicts }
				value = (values["dx"] << 16) | values["ax"]
				finding.str_subs("%s32 dx:ax, %x" % (finding["op"], value), description = "%d" % (value))

	def _run_add32(self):
		for finding in self._trace.regex_substitution([
			TracepointRegex.compile(r"add  (?P<lodst>[^,]+),(?P<losrc>.*)"),
			TracepointRegex.compile(r"adc  (?P<hidst>[^,]+),(?P<hisrc>.*)"),
		]):
			finding.str_subs("add32 %s:%s, %s:%s" % (finding["hidst"], finding["lodst"], finding["hisrc"], finding["losrc"]))

	def _run_clr(self):
		for finding in self._trace.regex_substitution([
			TracepointRegex.compile(r"xor  (?P<target>[^,]+),(?P=target)"),
		]):
			finding.str_subs("%s = 0" % (finding["target"]))

	def run(self):
		self._run_mul32()
		self._run_op32()
		self._run_add32()
		self._run_clr()
