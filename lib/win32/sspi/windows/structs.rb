require 'ffi'

module Windows
  module Structs
    extend FFI::Library

    class SEC_WINNT_AUTH_IDENTITY < FFI::Struct
      layout(
        :User, :pointer,
        :UserLength, :ulong,
        :Domain, :pointer,
        :DomainLength, :ulong,
        :Password, :pointer,
        :PasswordLength, :ulong,
        :Flags, :ulong
      )
      
      def user_to_ruby_s
        bsize = self[:UserLength]
        bsize > 0 ? self[:User].read_string_length(bsize) : nil
      end
      
      def domain_to_ruby_s
        bsize = self[:DomainLength]
        bsize > 0 ? self[:Domain].read_string_length(bsize) : nil
      end
      
      def password_to_ruby_s
        bsize = self[:PasswordLength]
        bsize > 0 ? self[:Password].read_string_length(bsize) : nil
      end
    end

    class SecHandle < FFI::Struct
      layout(:dwLower, :pointer, :dwUpper, :pointer)

      # NOTE: Experimental for now, may remove this marshalling stuff later

      def marshal_dump
        [self[:dwLower].read_ulong, self[:dwUpper].read_ulong]
      end

      def marshal_load(values)
        self[:dwLower] = FFI::MemoryPointer.new(:ulong)
        self[:dwUpper] = FFI::MemoryPointer.new(:ulong)
        self[:dwLower].write_ulong(values[0])
        self[:dwUpper].write_ulong(values[1])
      end
    end

    CredHandle = SecHandle
    CtxtHandle = SecHandle

    class TimeStamp < FFI::Struct
      layout(:dwLowDateTime, :ulong, :dwHighDateTime, :ulong)
      
      def marshal_dump
        [self[:dwLowDateTime], self[:dwHighDateTime]]
      end

      def marshal_load(values)
        self[:dwLowDateTime] = values[0]
        self[:dwHighDateTime] = values[1]
      end
    end

    class SecBuffer < FFI::Struct
      layout(
        :cbBuffer, :ulong,
        :BufferType, :ulong,
        :pvBuffer, :pointer
      )

      def init(token = nil)
        self[:BufferType] = 2 # SECBUFFER_TOKEN

        if token
          self[:cbBuffer] = token.size
          self[:pvBuffer] = FFI::MemoryPointer.from_string(token)
        else
          self[:cbBuffer] = Windows::Constants::TOKENBUFSIZE # Our TOKENBUFSIZE = 12000 as Windows 7/Server 2008 era default
          self[:pvBuffer] = FFI::MemoryPointer.new(:char, Windows::Constants::TOKENBUFSIZE)
        end

        self
      end
      
      def to_ruby_s
        bsize = self[:cbBuffer]
        bsize > 0 ? self[:pvBuffer].read_string_length(bsize) : nil
      end
    end

    class SecBufferDesc < FFI::Struct
      layout(
        :ulVersion, :ulong,
        :cBuffers, :ulong,
        :pBuffers, :pointer
      )

      def init(sec_buffer)
        self[:ulVersion] = Windows::Constants::SECBUFFER_VERSION
        self[:cBuffers]  = 1
        self[:pBuffers]  = sec_buffer
        self
      end
      
      def marshal_dump
        buffer = SecBuffer.new(self[:pBuffers])
        buffer.to_ruby_s
      end
      
      def marshal_load(content)
        buffer = SecBuffer.new(self[:pBuffers])
        buffer[:cbBuffer] = content.length
        buffer[:pvBuffer].write_string(content)
      end
    end

    class SecPkgInfo < FFI::Struct
      layout(
        :fCapabilities, :ulong,
        :wVersion, :ushort,
        :wRPCID, :ushort,
        :cbMaxToken, :ulong,
        :Name, :string,
        :Comment, :string
      )
    end

    class SecPkgContext_Names < FFI::Struct
      layout(:sUserName, :pointer)
      
      def marshal_load(username)
        self[:sUserName] = FFI::MemoryPointer.from_string(username)
      end
      
      def to_ruby_s
        self[:sUserName].null? ? nil : self[:sUserName].read_string
      end
      
      def to_username_ptr
        self[:sUserName]
      end
    end
  end
end
