# TWriter and TReader streams

Read this when a file or a blob was written by Delphi component streaming and you need to read a field
from it.

- **`TWriter` and `TReader` streams.** Component streams and many custom file formats are written value by value.
  `ReadInteger`, `ReadBoolean`, `ReadString`, `ReadDate` and `ReadListBegin` read a one-byte type code first, and
  `ReadStr` (a short string) does not. The codes up to Delphi 2007 are 0 `vaNull` (end of list), 1 `vaList`,
  2 `vaInt8`, 3 `vaInt16`, 4 `vaInt32`, 5 `vaExtended` (10 bytes), 6 `vaString` (length byte), 7 `vaIdent`,
  8 `vaFalse`, 9 `vaTrue`, 10 `vaBinary`, 11 `vaSet`, 12 `vaLString` (32-bit length), 13 `vaNil`,
  14 `vaCollection`, 15 `vaSingle`, 16 `vaCurrency`, 17 `vaDate` (8-byte double), 18 `vaWString` (32-bit length of
  UTF-16 units), 19 `vaInt64` and 20 `vaUTF8String`. With the reads of the loader in order, a field near the start
  of a file can be read without loading the rest. Find the loader by searching for the field's offset in the
  class (`add eax, OFFSET` before `@LStrAsg`, or `mov [reg + OFFSET], eax`) and follow the reads before it,
  including the version checks (`cmp dword [eax + n], VERSION`) that skip fields in old files.
