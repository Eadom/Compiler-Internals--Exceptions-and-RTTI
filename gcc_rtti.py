# GCC RTTI parser
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

IS64 = idaapi.getseg(here()).bitness == 2

PTRSIZE = [4, 8][IS64]

# sign extend b low bits in x
# from "Bit Twiddling Hacks"
def SIGNEXT(x, b):
  m = 1 << (b - 1)
  x = x & ((1 << b) - 1)
  return (x ^ m) - m

def ptrval(ea):
  if IS64:
    return Qword(ea)
  else:
    return Dword(ea)   

import struct

ti_names = [
 "St9type_info",
 "N10__cxxabiv117__class_type_infoE",
 "N10__cxxabiv120__si_class_type_infoE",
 "N10__cxxabiv121__vmi_class_type_infoE",
]

TI_TINFO = 0
TI_CTINFO = 1
TI_SICTINFO = 2
TI_VMICTINFO = 3

# helper for bin search
def ptr_to_bytes(val):
  if IS64:
    sv = struct.pack("<Q", val)
  else:
    sv = struct.pack("<I", val)
  return " ".join("%02X" % ord(c) for c in sv)

def ptrfirst(val):
  return FindBinary(0, SEARCH_CASE|SEARCH_DOWN, ptr_to_bytes(val))

def ptrnext(val, ref):
  return FindBinary(ref+1, SEARCH_CASE|SEARCH_DOWN, ptr_to_bytes(val))
  
def xref_or_find(addr, allow_many = False):
  lrefs = list(DataRefsTo(addr))
  if len(lrefs) == 0:
    lrefs = list(refs(addr, ptrfirst, ptrnext))
  if len(lrefs) > 1 and not allow_many:
      print "too many xrefs to %08X" % addr
      return []
  lrefs = [r for r in lrefs if not isCode(GetFlags(r))]
  return lrefs
  
def find_string(s, afrom=0):
  print "searching for %s" % s
  ea = FindBinary(afrom, SEARCH_CASE|SEARCH_DOWN, '"' + s + '"')
  if ea != BADADDR:
    print "Found at %08X" % ea
  return ea

def ForceDword(ea):
  if ea != BADADDR and ea != 0:
    if not isDwrd(GetFlags(ea)):
      MakeUnknown(ea, 4, DOUNK_SIMPLE)
      MakeDword(ea)
    if isOff0(GetFlags(ea)) and GetFixupTgtType(ea) == -1:
      # remove the offset
      OpHex(ea, 0)
    
def ForceQword(ea):
  if ea != BADADDR and ea != 0:
    if not isQwrd(GetFlags(ea)):
      MakeUnknown(ea, 8, DOUNK_SIMPLE)
      MakeQword(ea)
    if isOff0(GetFlags(ea)) and GetFixupTgtType(ea) == -1:
      # remove the offset
      OpHex(ea, 0)

def ForcePtr(ea, delta = 0):
  if IS64:
    ForceQword(ea)
  else:
    ForceDword(ea)
  if GetFixupTgtType(ea) != -1 and isOff0(GetFlags(ea)):
    # don't touch fixups
    return
  pv = ptrval(ea)
  if pv != 0 and pv != BADADDR:
    # apply offset again
    if idaapi.is_spec_ea(pv):
      delta = 0
    OpOffEx(ea, 0, [REF_OFF32, REF_OFF64][IS64], -1, 0, delta)

# p pointer
# v vtable pointer (delta ptrsize*2)
# i integer (32-bit)
# l integer (32 or 64-bit)
def format_struct(ea, fmt):
  for f in fmt:
    if f in ['p', 'v']:
      if f == 'v':
        delta = PTRSIZE*2
      else:
        delta = 0
      ForcePtr(ea, delta)
      ea += PTRSIZE
    elif f == 'i':
      ForceDword(ea)
      ea += 4
    elif f == 'l':
      if IS64:
        ForceQword(ea)
        ea += 8
      else:
        ForceDword(ea)
        ea += 4
  return ea      

def force_name(ea, name):
  if isTail(GetFlags(ea)):
    MakeUnknown(ea, 1, DOUNK_SIMPLE)
  MakeNameEx(ea, name, SN_NOWARN)
  
def is_bad_addr(ea):
  return ea == 0 or ea == BADADDR or idaapi.is_spec_ea(ea) or not isLoaded(ea)

def vtname(name):
  return "__ZTV" + name

def tinfo2class(tiname):
  s = Demangle(tiname, 0)
  return s.replace("`typeinfo for'","")

def classname(namestr):
  return tinfo2class("__ZTI" + namestr)

all_classes = {}

class BaseClass:
  def __init__(self, ti, offset, flags):
    self.ti = ti
    self.offset = offset
    self.flags = flags

class ClassDescriptor:
  def __init__(self, vtable, namestr):
    self.vtable = vtable
    self.namestr = namestr
    self.bases = []
  
  def add_base(self, base, offset=0, flags=0):
    self.bases.append(BaseClass(base, offset, flags))

# dd `vtable for'std::type_info+8
# dd `typeinfo name for'std::type_info
def format_type_info(ea):
  # get the class name string
  tis = ptrval(ea + PTRSIZE)
  if is_bad_addr(tis):
    return BADADDR
  name = GetString(tis)
  if name == None or len(name) == 0:
    return BADADDR
  # looks good, let's do it
  ea2 = format_struct(ea, "vp")
  force_name(tis, "__ZTS" + name)
  force_name(ea, "__ZTI" + name)
  # find our vtable
  # 0 followed by ea
  pat = ptr_to_bytes(0) + " " + ptr_to_bytes(ea)
  vtb = FindBinary(0, SEARCH_CASE|SEARCH_DOWN, pat)
  if not is_bad_addr(vtb):
    print "vtable for %s at %08X" % (name, vtb)
    format_struct(vtb, "pp")
    force_name(vtb, vtname(name))
  else:
    vtb = BADADDR
  all_classes[ea] = ClassDescriptor(vtb, name)
  return ea2

# dd `vtable for'__cxxabiv1::__si_class_type_info+8
# dd `typeinfo name for'MyClass
# dd `typeinfo for'BaseClass
def format_si_type_info(ea):
  ea2 = format_type_info(ea)
  pbase = ptrval(ea2)
  all_classes[ea].add_base(pbase)
  ea2 = format_struct(ea2, "p")
  return ea2

# dd `vtable for'__cxxabiv1::__si_class_type_info+8
# dd `typeinfo name for'MyClass
# dd flags
# dd base_count
# (base_type, offset_flags) x base_count
def format_vmi_type_info(ea):
  ea2 = format_type_info(ea)
  ea2 = format_struct(ea2, "ii")
  base_count = Dword(ea2-4)
  clas = all_classes[ea]
  if base_count > 100:
    print "%08X: over 100 base classes?!" % ea
    return BADADDR
  for i in range(base_count):
    base_ti = ptrval(ea2)
    flags_off = ptrval(ea2 + PTRSIZE)
    off = SIGNEXT(flags_off>>8, 24)
    clas.add_base(base_ti, off, flags_off & 0xFF)
    ea2 = format_struct(ea2, "pl")
  return ea2

def find_type_info(idx):
  name = ti_names[idx]
  ea = find_string(name)
  if ea != BADADDR:
    xrefs = xref_or_find(ea)
    if xrefs:
      ti_start = xrefs[0] - PTRSIZE
      if not is_bad_addr(ti_start):
        print "found %d at %08X" % (idx, ti_start)
        ea2 = format_type_info(ti_start)
        if idx >= TI_CTINFO:
          format_struct(ea2, "p")

def handle_classes(idx, formatter):
  name = vtname(ti_names[idx])
  ea = LocByName(name)
  if ea == BADADDR:
    # try single underscore
    name = name[1:]
    ea = LocByName(name)
  if ea == BADADDR:
    print "Could not find vtable for %s" % ti_names[idx]
    return
  idx = 0
  handled = set()
  while ea != BADADDR:
    print "Looking for refs to vtable %08X" % ea
    if idaapi.is_spec_ea(ea):
      xrefs = xref_or_find(ea, True)
      ea += PTRSIZE*2
      xrefs.extend(xref_or_find(ea, True))
    else:
      ea += PTRSIZE*2
      xrefs = xref_or_find(ea, True)
    for x in xrefs:
      if not is_bad_addr(x) and not x in handled:
        print "found %s at %08X" % (name, x)
        ea2 = formatter(x)
        handled.add(x)
    ea = LocByName("%s_%d" % (name, idx))
    idx += 1

from idaapi import Choose2
class ClassChooser(Choose2):
  def __init__(self, title, deflt=1):
    Choose2.__init__(self, title, [ ["Name", 30], ["TI Address", 10|Choose2.CHCOL_HEX], ["VTable", 10|Choose2.CHCOL_HEX], ["Bases", 40]])
    self.n = len(all_classes)
    self.icon = 5
    self.selcount = 0
    self.deflt = deflt
    self.num2key = [k for k in all_classes]

  def OnClose(self):
    print "closed", str(self)
  
  def OnGetSize(self):
    """Returns the element count.
    This callback is mandatory.
    @return: Number of elements
    """
    return self.n

  def OnSelectLine(self, n):
    """
    Called when a line is selected and then Ok or double click was pressed
    @param n: Line number (0-based)
    """
    tiaddr = self.num2key[n]
    klass = all_classes[tiaddr]
    idaapi.jumpto(klass.vtable)

  def OnGetLine(self, n):
    """Called when the chooser window requires lines.
    This callback is mandatory.
    @param n: Line number (0-based)
    @return: The user should return a list with ncols elements.
        example: a list [col1, col2, col3, ...] describing the n-th line
    """
    tiaddr = self.num2key[n]
    klass = all_classes[tiaddr]
    name = classname(klass.namestr)
    ti = "%08X" % tiaddr
    vt = "%08X" % klass.vtable
    basestr = ""
    for b in klass.bases:
      if basestr: basestr += ";"
      if b.ti in all_classes:
        bklass = all_classes[b.ti]
        basename = classname(bklass.namestr)
      elif idaapi.is_spec_ea(b.ti):
        nm = Name(b.ti)
        basename = tinfo2class(nm)
      else:
        print "Base %08X not found for class %08X!" % (b.ti, tiaddr)
        basename = "ti_%08X" % b.ti
      basestr += "%s@%02X" % (basename, b.offset)

    return [name, ti, vt, basestr]


def choose_class():
  c = ClassChooser("Choose a class")
  c.Show(True)

def main():
  # turn on GCC3 demangling
  idaapi.cvar.inf.demnames |= idaapi.DEMNAM_GCC3

  print "Looking for standard type info classes"
  find_type_info(TI_TINFO)
  find_type_info(TI_CTINFO)
  find_type_info(TI_SICTINFO)
  find_type_info(TI_VMICTINFO)  
  print "Looking for simple classes"
  handle_classes(TI_CTINFO, format_type_info)
  print "Looking for single-inheritance classes"
  handle_classes(TI_SICTINFO, format_si_type_info)
  print "Looking for multiple-inheritance classes"
  handle_classes(TI_VMICTINFO, format_vmi_type_info)
  choose_class()

main()
