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

import re
import time
import json

class TracepointRegex():
	def __init__(self, regex, min_count = 1, max_count = 1, invert = False):
		self._regex = regex
		self._min_count = min_count
		self._max_count = max_count
		self._invert = invert

	@classmethod
	def compile(cls, regex_text, min_count = 1, max_count = 1, invert = False):
		return cls(regex = re.compile(regex_text), min_count = min_count, max_count = max_count, invert = invert)

	def match(self, stream):
		result = [ ]
		while len(result) < self._max_count:
			index = len(result)
			match = self._regex.fullmatch(stream[index]["mnemonic"])
			if match is not None:
				match = match.groupdict()

			if not self._invert:
				have_match = match is not None
			else:
				have_match = match is None

			if not have_match:
				break
			if match is None:
				match = { }
			result.append((stream[index], match))
		if not (self._min_count <= len(result) <= self._max_count):
			return None
		else:
			return result

class TracepointRegexMatch():
	def __init__(self, matches):
		self._matches = matches
		self._consistent = True
		self._variables = { }
		self._first = None
		self._last = None
		self._compute_variables()

	def _compute_variables(self):
		for (insn, groupdict) in self:
			if self._first is None:
				self._first = insn
			for (key, value) in groupdict.items():
				if key.startswith("_"):
					continue
				if (key in self._variables) and (self._variables[key] != value):
					self._consistent = False
				else:
					self._variables[key] = value
		self._last = insn

	@property
	def consistent(self):
		return self._consistent

	def dump(self):
		print(self)
		for (regex_no, regex_match) in enumerate(self._matches, 1):
			for (insn, groupdict) in regex_match:
				print("%6d [%2d] %04x:%04x %s" % (insn["i"], regex_no, insn["ips"], insn["ipo"], insn["mnemonic"]))
		print()

	def subs(self, pseudo):
		for (tracepoint, groupdict) in self:
			tracepoint["type"] = "hidden"
		tracepoint["pseudo"] = pseudo

	def str_subs(self, pseudo_str, description = ""):
		pseudo = {
			"type":			"pseudo",
			"i":			self._first["i"],
			"ips":			self._first["ips"],
			"ipo":			self._first["ipo"],
			"iend":			self._last["i"],
			"ipsend":		self._last["ips"],
			"ipoend":		self._last["ipo"],
			"pseudo":		pseudo_str,
			"description":	description,
		}
		self.subs(pseudo)

	@property
	def groupdicts(self):
		for (insn, groupdict) in self:
			yield groupdict

	def __iter__(self):
		for regex_match in self._matches:
			yield from regex_match

	def __getitem__(self, key):
		return self._variables[key]

	def __str__(self):
		return "Variables<%s>" % (", ".join("%s = %s" % (key, value) for (key, value) in sorted(self._variables.items())))

class Tracefile():
	def __init__(self, filename, verbose = False):
		self._verbose = verbose
		self._trace = self._read_tracefile(filename)
		self._trace = self._postprocess_tracefile()

	def _read_tracefile(self, filename):
		t0 = time.time()
		with open(filename) as f:
			trace = json.load(f)
		t1 = time.time()
		tdiff = t1 - t0
		if self._verbose:
			print("Read %d tracepoints in %.1f secs (%.0f kPts/sec)" % (len(trace), tdiff, len(trace) / tdiff / 1000))
		return trace

	def _postprocess_tracefile(self):
		insn_no = 0
		processed_trace = [ ]
		for tracepoint in self._trace:
			if tracepoint.get("type") == "gap":
				insn_no += tracepoint["gap"]
			else:
				insn_no += 1
				tracepoint["i"] = insn_no
				processed_trace.append(tracepoint)
		return processed_trace

	def filter(self, predicate):
		filtered = [ ]
		for tracepoint in self._trace:
			if predicate(tracepoint):
				filtered.append(tracepoint)
		self._trace = filtered

	def filter_range(self, first = None, last = None):
		if (first is None) and (last is None):
			return
		if (first is not None) and (last is not None) and (first > last):
			raise ValueError("When filtering tracepoint ranges, 'first' must be less or equal to 'last'.")

		predicate_elements = [ ]
		if first is not None:
			predicate_elements.append(lambda tracepoint: tracepoint["i"] >= first)
		if last is not None:
			predicate_elements.append(lambda tracepoint: tracepoint["i"] <= last)

		predicate = lambda tracepoint: all(predicate_element(tracepoint) for predicate_element in predicate_elements)
		self.filter(predicate)

	def write(self, filename):
		output_data = [ ]
		expect_insn = 0
		for tracepoint in self:
			expect_insn += 1
			if tracepoint["i"] != expect_insn:
				gap = tracepoint["i"] - expect_insn
				output_data.append({ "type": "gap", "gap": gap })
				expect_insn = tracepoint["i"]

			tracepoint = dict(tracepoint)
			del tracepoint["i"]
			output_data.append(tracepoint)

		with open(filename, "w") as f:
			json.dump(output_data, f, separators = (",", ":"))

	def regex_substitution(self, regexes):
		start_offset = 0
		while start_offset < len(self._trace):
			i = start_offset
			matches = [ ]
			for regex in regexes:
				stream = self._trace[i : ]
				match = regex.match(stream)
				if match is None:
					break
				i += len(match)
				matches.append(match)
			else:
				resulting_match = TracepointRegexMatch(matches)
				if resulting_match.consistent:
					yield resulting_match
			start_offset += 1

	def __len__(self):
		return len(self._trace)

	def __getitem__(self, index):
		return self._trace[index]

	def __iter__(self):
		for tracepoint in self._trace:
			yield tracepoint
			if "pseudo" in tracepoint:
				# Pseudo-op
				yield tracepoint["pseudo"]

if __name__ == "__main__":
	trace = Tracefile("test_crc.json", verbose = True)

	for finding in trace.regex_substitution([
		TracepointRegex.compile(r"push (?P<param1>.*)"),
		TracepointRegex.compile(r"push (?P<param2>.*)"),
		TracepointRegex.compile(r"push (?P<param3>.*)"),
		TracepointRegex.compile(r"push (?P<param4>.*)"),
		TracepointRegex.compile(r"call\s+2A74:363C"),
		TracepointRegex.compile(r"ret.*", min_count = 0, max_count = 30, invert = True),
		TracepointRegex.compile(r"ret.*"),
	]):
		finding.str_subs("mul32 %s:%s, %s:%s" % (finding["param1"], finding["param2"], finding["param3"], finding["param4"]))

#	for insn in trace:
#		print(insn)
