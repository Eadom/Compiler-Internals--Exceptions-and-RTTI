# .ARM.exidx parser
#
# Copyright (c) 2012 Igor Skochinsky
# Version 0.1 2012-06-19
#
# This software is provided 'as-is', without any express or implied
# warranty. In no event will the authors be held liable for any damages
# arising from the use of this software.
#
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely, subject to the following restrictions:
#
#    1. The origin of this software must not be misrepresented; you must not
#    claim that you wrote the original software. If you use this software
#    in a product, an acknowledgment in the product documentation would be
#    appreciated but is not required.
#
#    2. Altered source versions must be plainly marked as such, and must not be
#    misrepresented as being the original software.
#
#    3. This notice may not be removed or altered from any source
#    distribution.

import ConfigParser, string

def set_thumb(ea):
  t = ea & 1
  ea ^= t
  SetRegEx(ea, "T", t, SR_auto)
  return ea

def make_proc(ea):
  ea = set_thumb(ea)
  MakeCode(ea)
  AutoMark(ea, AU_PROC)
  return ea

def get_prel31(ea):
  v = Dword(ea)
  r = v & 0x7fffffff
  if v & 0x40000000:
    r -= 0x80000000
  return ea + r

def parse_exidx(s):
  fn = get_prel31(s)
  # print "%08X: fn=%08X" % (s, fn)
  MakeDword(s)  
  OpOffEx(s, 0, REFINFO_NOBASE|REF_OFF32, -1, fn - Dword(s), 0)
  MakeComm(s, "[function -> %08X]" % fn)
  # make_proc(fn)
  s += 4
  e_idx = Dword(s)
  MakeDword(s)
  if e_idx == 1:
    MakeComm(s, "[cantunwind]")
  elif e_idx & 0x80000000:
    idx = (e_idx >> 24) & 0x7F
    MakeComm(s, "[inline, idx=%d]" % idx)
  else:
    tbl = get_prel31(s)
    MakeComm(s, "[eh table -> %08X]" % tbl)
    OpOffEx(s, 0, REFINFO_NOBASE|REF_OFF32, -1, tbl - Dword(s), 0)    
  s += 4
  return s

s = FirstSeg()
while s != BADADDR:
  if SegName(s) == ".ARM.exidx":
    a = SegStart(s)
    b = SegEnd(s)
    print "parsing .ARM.exidx segment: %08X .. %08X" % (a, b)
    i = 0
    while a < b:
      a = parse_exidx(a)
      i += 1
  s = NextSeg(s)
