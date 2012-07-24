require 'base64'

require File.join(File.dirname(__FILE__), 'windows', 'constants')
require File.join(File.dirname(__FILE__), 'windows', 'structs')
require File.join(File.dirname(__FILE__), 'windows', 'functions')

module Win32
  module SSPI
    class Client
      include Windows::Constants
      include Windows::Structs
      include Windows::Functions

      attr_reader :username
      attr_reader :domain
      attr_reader :auth_type
      attr_reader :context

      # For analysis of type 1 messages. Not sure if this is useful yet.
      class MessageType1
        attr_reader :workstation
        attr_reader :domain
        attr_reader :signature

        # Breakdown based on http://davenport.sourceforge.net/ntlm.html
        def initialize(token)
          @signature = token[0,8].strip
          @type1_indicator = token[8,4]
          @flags = token[12,4]
          @domain_security_buffer = token[16,8]
          @worstation_security_buffer = token[24,8]
          @os_version_structure = token[32,8]
          @workstation = token[40,12]
          @domain = token[52..-1]
        end
      end

      def initialize(username = nil, domain = nil, auth_type = 'NTLM')
        @username  = username || ENV['USERNAME'].dup
        @domain    = domain   || ENV['USERDOMAIN'].dup
        @auth_type = auth_type
        @token     = nil
        @context   = nil
      end

      def token(encoded = false)
        if encoded
          Base64.encode64(@token).delete("\n")
        else
          @token
        end
      end

      def get_initial_token(local = true, encode = false)
        cred_struct = CredHandle.new
        time_struct = TimeStamp.new
        auth_struct = nil

        # If local is true, obtain handle to credentials of the logged in user.
        unless local
          if @username || @domain
            auth_struct = SEC_WINNT_AUTH_IDENTITY.new
            auth_struct[:Flags] = SEC_WINNT_AUTH_IDENTITY_UNICODE

            if @username
              username = @username.concat(0.chr).encode('UTF-16LE')
              auth_struct[:User] = FFI::MemoryPointer.from_string(username)
              auth_struct[:UserLength] = username.size
            end

            if @domain
              domain = @domain.concat(0.chr).encode('UTF-16LE')
              auth_struct[:Domain] = FFI::MemoryPointer.from_string(domain)
              auth_struct[:DomainLength] = domain.size
            end
          end
        end

        status = AcquireCredentialsHandle(
          nil,
          @auth_type,
          SECPKG_CRED_OUTBOUND,
          nil,
          auth_struct,
          nil,
          nil,
          cred_struct,
          time_struct
        )

        if status != SEC_E_OK
          raise SystemCallError.new('AcquireCredentialsHandle', FFI.errno)
        end

        begin
          rflags = ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONNECTION
          expiry = TimeStamp.new

          context_struct = CtxtHandle.new
          context_attrib = FFI::MemoryPointer.new(:ulong)

          sec_buf = SecBuffer.new
          sec_buf[:BufferType] = SECBUFFER_TOKEN
          sec_buf[:cbBuffer] = TOKENBUFSIZE
          sec_buf[:pvBuffer] = FFI::MemoryPointer.new(:char, TOKENBUFSIZE)

          buffer = SecBufferDesc.new
          buffer[:ulVersion] = SECBUFFER_VERSION
          buffer[:cBuffers] = 1
          buffer[:pBuffers] = sec_buf

          status = InitializeSecurityContext(
            cred_struct,
            nil,
            nil,
            rflags,
            0,
            SECURITY_NETWORK_DREP,
            nil,
            0,
            context_struct,
            buffer,
            context_attrib,
            expiry
          )

          if status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED
            raise SystemCallError.new('InitializeSecurityContext', FFI.errno)
          else
            @context = context_struct

            bsize = sec_buf[:cbBuffer]
            @token = sec_buf[:pvBuffer].read_string_length(bsize)

            if DeleteSecurityContext(context_struct) != SEC_E_OK
              raise SystemCallError.new('DeleteSecurityContext', FFI.errno)
            end
          end
        ensure
          if FreeCredentialsHandle(cred_struct) != SEC_E_OK
            raise SystemCallError.new('FreeCredentialsHandle', FFI.errno)
          end
        end

        @token
      end
    end
  end
end

# Eventually delete this
if $0 == __FILE__
  #sspi = Win32::SSPI::Client.new(nil, nil, 'NTLM')
  sspi = Win32::SSPI::Client.new
  sspi.get_initial_token
  p sspi.context
  #token = sspi.token
  #p token
  #p token
  #m = Win32::SSPI::MessageType1.new(token)
  #p m.domain
  #p m.workstation
  #p m.signature

  # According to http://davenport.sourceforge.net/ntlm.html
  #p token[0,8]   # NTLMSSP Sig
  #p token[8,4]   # Type 1 indicator
  #p token[12,4]  # Flags
  #p token[16,8]  # Supplied Domain buffer
  #p token[24,8]  # Supplied Workstation buffer
  #p token[32,-1] # OS Version structure
  #p token[40,12]  # Supplied Workstation data
  #p token[52..-1] # Supplied domain data
end
