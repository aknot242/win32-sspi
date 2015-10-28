require 'ffi'
require_relative 'constants'

class SecurityStatusError < StandardError
  extend FFI::Library

  FORMAT_MESSAGE_FROM_SYSTEM_TABLE = 0x00001000

  ffi_lib :kernel32
  attach_function :FormatMessageA, [:ulong, :ulong, :ulong, :ulong, :pointer, :ulong, :pointer], :ulong

  def initialize(context,status,errno)
    hex_status = '0x%X' % status
    msg = get_return_status_message(status)
    super("#{context}:\nffi_errno:#{errno} win32_status:#{hex_status}\nwin32 message:#{msg}")
  end

  def get_return_status_message(win32_return_status)
    buf = FFI::MemoryPointer.new(:char, 512)
    flags = FORMAT_MESSAGE_FROM_SYSTEM_TABLE
    FormatMessageA(flags, 0, win32_return_status, 0, buf, buf.size, nil)
    buf.read_string
  end
end
