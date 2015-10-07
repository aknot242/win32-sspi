require_relative '../windows/constants'
require_relative '../windows/misc'
require_relative '../api/server'

module Win32
  module SSPI
    module Negotiate
      class Server
        include Windows::Constants
        include API::Server
      
        attr_accessor :auth_type
        attr_reader :token
        attr_reader :username
        attr_reader :domain
      
        def initialize(options={})
          @auth_type = options[:auth_type] || "Negotiate"
          @token = ""
          @username = ''
          @domain = ''
          @credentials_handle = nil
          @context_handle = nil
        end
        
        def authenticate_and_continue?(token)
          status = acquire_handle
          if SEC_E_OK == status
            status = accept_context(token)
            if [SEC_I_COMPLETE_NEEDED, SEC_I_COMPLETE_AND_CONTINUE].include?(status)
              status = complete_authentication
            end
            if SEC_E_OK == status
              status = query_attributes
              if SEC_E_OK == status
                free_handles
              end
            end
          end
          
          SEC_I_CONTINUE_NEEDED == status
        end
        
        def acquire_handle
          return SEC_E_OK if @credentials_handle
        
          @credentials_handle = create_credhandle
          expiry = create_timestamp
        
          status = acquire_credentials_handle(
            nil,
            @auth_type,
            SECPKG_CRED_INBOUND,
            nil,
            nil,
            nil,
            nil,
            @credentials_handle,
            expiry
          )

          if SEC_E_OK != status
            @credentials_handle = nil
            raise SecurityStatusError.new('AcquireCredentialsHandle', status, FFI.errno)
          end
          
          status
        end
      
        def accept_context(token=nil)
          ctx = @context_handle
          @context_handle ||= create_ctxhandle

          if token
            input_buffer   = create_secbuffer(token)
            input_buffer_desc  = create_secbufferdesc(input_buffer)
          end
          
          rflags = ASC_REQ_CONFIDENTIALITY | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONNECTION

          output_buffer  = create_secbuffer
          output_buffer_desc = create_secbufferdesc(output_buffer)

          context_attributes = FFI::MemoryPointer.new(:ulong)
          expiry = create_timestamp

          status = accept_security_context(
            @credentials_handle,
            ctx,
            (token ? input_buffer_desc : nil),
            rflags,
            SECURITY_NATIVE_DREP,
            @context_handle,
            output_buffer_desc,
            context_attributes,
            expiry
          )

          a_success = [SEC_E_OK, SEC_I_CONTINUE_NEEDED, SEC_I_COMPLETE_NEEDED, SEC_I_COMPLETE_AND_CONTINUE]
          if a_success.include?(status)
            @token = output_buffer.to_ruby_s
          else
            raise SecurityStatusError.new('AcceptSecurityContext', status, FFI.errno)
          end
          
          status
        end
        
        def complete_authentication
          status = SEC_E_OK
          
          if @token
            input_buffer = create_secbuffer(@token)
            input_buffer_desc  = create_secbufferdesc(input_buffer)
            
            status = complete_auth_token(@context_handle, input_buffer_desc)
            if SEC_E_OK != status
              raise SecurityStatusError.new('CompleteAuthToken', status, FFI.errno)
            end
          end
          
          status
        end

        def query_attributes
          # Finally, let's get the user and domain
          ptr = create_secpkg_context_names

          status = query_context_attributes(@context_handle, SECPKG_ATTR_NAMES, ptr)
          if SEC_E_OK != status
            raise SecurityStatusError.new('QueryContextAttributes', status, FFI.errno)
          end

          @username = ptr.to_ruby_s
          if @username.include?("\\")
            @domain, @username = @username.split("\\")
          end
          
          status
        end
        
        def free_handles
          status, dsc_status,fch_status = [SEC_E_OK,SEC_E_OK,SEC_E_OK]
          if @context_handle
            dsc_status, @context_handle = [delete_security_context(@context_handle),nil]
          end
          
          if @credentials_handle
            fch_status, @credentials_handle = [free_credentials_handle(@credentials_handle),nil]
          end

          if SEC_E_OK != dsc_status
            status = dsc_status
            raise SecurityStatusError.new('DeleteSecurityContext', status, FFI.errno)
          end

          if SEC_E_OK != fch_status
            status = fch_status
            raise SecurityStatusError.new('FreeCredentialsHandle', status, FFI.errno)
          end
          
          status
        end
      
      end
    end
  end
end
