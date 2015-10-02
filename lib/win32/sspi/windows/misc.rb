require 'ffi'
require_relative 'constants'

class String
  # Determine if a string is base64 encoded. Use this to automatically
  # decode tokens if already encoded.
  #
  def base64?
    unpack("m").pack("m").delete("\n") == delete("\n")
  end
end

class SecurityStatusError < StandardError
  extend FFI::Library

  ffi_lib :kernel32
  attach_function :FormatMessageA, [:ulong, :ulong, :ulong, :ulong, :pointer, :ulong, :pointer], :ulong

  def initialize(context,status,errno)
    hex_status = '0x%X' % status
    msg = get_last_error(errno)
    super("#{context}:\nstatus:#{hex_status}\nmessage:#{msg}")
  end

  def get_last_error(err_num = FFI.errno)
    buf = FFI::MemoryPointer.new(:char, 512)
    FormatMessageA(12288, 0, err_num, 0, buf, buf.size, nil)
    buf.read_string
  end
end
