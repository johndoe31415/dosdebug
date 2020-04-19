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

import time
import json

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
			if "gap" in tracepoint:
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
				output_data.append({ "gap": gap })
				expect_insn = tracepoint["i"]

			tracepoint = dict(tracepoint)
			del tracepoint["i"]
			output_data.append(tracepoint)

		with open(filename, "w") as f:
			json.dump(output_data, f, separators = (",", ":"))

	def __len__(self):
		return len(self._trace)

	def __getitem__(self, index):
		return self._trace[index]

	def __iter__(self):
		return iter(self._trace)

if __name__ == "__main__":
	trace = Tracefile("/tmp/iii", verbose = True)
	trace.filter_range(first = 10000, last = 19999)
