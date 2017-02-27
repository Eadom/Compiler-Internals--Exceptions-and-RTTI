GCC helper scripts

Copyright (c) 2012 Igor Skochinsky
Version 0.1 2012-06-19

These scripts demonstrate some of the material I covered in my
Recon 2012 talk on RTTI and exceptions implementations in compilers.
They are pretty basic and are not production quality.


* gcc_rtti.py tries to find and rename RTTI structures, and shows
the list of classes with their ancestors.

* gcc_extab.py parses and formats the .eh_frame or __eh_frame segment
and any linked LSDAs. It assumes that the LSDAs use GCC's "v0" format.

* parse_exidx.py parses the .ARM.exidx section and creates offsets
to the functions and exception data. To use it with ELF files, you
need to load the ELF in manual mode and load .ARM.exidx explicitly
(it's not loaded by default).


The scripts have been tested with IDA 6.3. They are released under
three-clause BSD license.

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

   1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.

   2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.

   3. This notice may not be removed or altered from any source
   distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
