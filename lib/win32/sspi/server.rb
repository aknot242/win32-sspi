require 'base64'
require_relative 'windows/constants'
require_relative 'windows/structs'
require_relative 'windows/misc'
require_relative 'api/server'

module Win32
  module SSPI
    class Server
      include Windows::Constants
      include Windows::Structs
      include API::Server
      extend API::Server

      attr_reader :type_1_message
      attr_reader :auth_type
      attr_reader :username
      attr_reader :domain

      def initialize(auth_type = 'NTLM')
        @auth_type = auth_type
        @context = CtxtHandle.new
        @credentials = CredHandle.new

        # This won't be initialized until the call to initial_token.
        @type_1_message = nil
        @type_2_message = nil

        # These won't be set unless complete_authentication is successful.
        @username = nil
        @domain = nil
      end

      # Returns the token initialized after the call to complete_authentication.
      # If the encoded argument is true, it returns a base64 encoded token.
      #
      def type_2_message(encoded = false)
        if encoded
          Base64.encode64(@type_2_message).delete("\n")
        else
          @type_2_message
        end
      end

      # Takes the type 1 message from the client and attemps to accept it. If
      # successful, returns a type 2 message back to the client.
      #
      def initial_token(type_1_message)
        @type_1_message = type_1_message
        time_struct = TimeStamp.new

        status = acquire_credentials_handle(
          nil,
          @auth_type,
          SECPKG_CRED_INBOUND,
          nil,
          nil,
          nil,
          nil,
          @credentials,
          time_struct
        )

        if status != SEC_E_OK
          raise SystemCallError.new('AcquireCredentialsHandle', FFI.errno)
        end

        expiry  = TimeStamp.new
        outbuf  = SecBuffer.new.init
        inbuf   = SecBuffer.new.init(@type_1_message)

        outbuf_sec = SecBufferDesc.new.init(outbuf)
        inbuf_sec  = SecBufferDesc.new.init(inbuf)

        context_attr = FFI::MemoryPointer.new(:ulong)

        status = accept_security_context(
          @credentials,
          nil,
          inbuf_sec,
          ASC_REQ_DELEGATE, # Just imitating mod_auth_sspi here
          SECURITY_NATIVE_DREP,
          @context,
          outbuf_sec,
          context_attr,
          expiry
        )

        if status != SEC_E_OK
          if status == SEC_I_COMPLETE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE
            if complete_auth_token(@context, outbuf_sec) != SEC_E_OK
              raise SystemCallError.new('CompleteAuthToken', FFI.errno)
            end
          else
            unless status == SEC_I_CONTINUE_NEEDED
              raise SystemCallError.new('AcceptSecurityContext', FFI.errno)
            end
          end
        end

        bsize = outbuf[:cbBuffer]
        @type_2_message = outbuf[:pvBuffer].read_string_length(bsize)

        @type_2_message
      end

      # Accepts a type 3 message from a client and completes the authentication
      # if successful. Returns the status of the call to AcceptSecurityContext.
      #
      def complete_authentication(token)
        inbuf = SecBuffer.new.init(token)
        inbuf_sec = SecBufferDesc.new.init(inbuf)

        context_attr = FFI::MemoryPointer.new(:ulong)

        status = accept_security_context(
          @credentials,
          @context,
          inbuf_sec,
          ASC_REQ_DELEGATE,
          SECURITY_NATIVE_DREP,
          @context,
          nil,
          context_attr,
          nil
        )

        if status != SEC_E_OK
          raise SystemCallError.new('AcceptSecurityContext', SecurityStatus.new(status))
        end

        # Finally, let's get the user and domain
        ptr = SecPkgContext_Names.new

        qstatus = query_context_attributes(@context, SECPKG_ATTR_NAMES, ptr)

        if qstatus != SEC_E_OK
          raise SytemCallError.new('QueryContextAttributes', SecurityStatus.new(status))
        end

        user_string = ptr[:sUserName].read_string

        if user_string.include?("\\")
          @domain, @username = user_string.split("\\")
        end

        if @credentials && free_credentials_handle(@credentials) != SEC_E_OK
          raise SystemCallError.new('FreeCredentialsHandle', FFI.errno)
        end

        status
      end

      # Returns a list of available security packages on the system.
      #
      def self.security_packages
        num = FFI::MemoryPointer.new(:ulong)
        spi = FFI::MemoryPointer.new(SecPkgInfo, 20) # Should be plenty
        arr = []

        result = enumerate_security_packages(num, spi)

        if result != SEC_E_OK
          raise SystemCallError.new('EnumerateSecurityPackages', FFI.errno)
        else
          begin
            num = num.read_long

            ptr = spi[0].read_pointer

            num.times{
              s = SecPkgInfo.new(ptr)
              arr << s[:Name]
              ptr += SecPkgInfo.size
            }
          ensure
            free_context_buffer(ptr)
          end
        end

        arr
      end
    end
  end
end

if $0 == __FILE__
  #server = Win32::SSPI::Server.new
  #p server
  p Win32::SSPI::Server.security_packages
end
