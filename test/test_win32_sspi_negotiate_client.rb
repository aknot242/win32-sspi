########################################################################
# Tests for the Win32::SSPI::Negotiate::Client class.
########################################################################
require 'test-unit'
require 'win32/sspi/negotiate/client'

class TC_Win32_SSPI_Negotiate_Client < Test::Unit::TestCase
  SPN = "HTTP/virtual-server.gas.local"
  MockCredentialHandle = [777,888]
  MockTimeStamp = [0x000000FF,0xFF000000]
  MockContextHandle = [123,987]
  MockSecBufferContent = "0123456789"*10
  ContextAttr = Windows::Constants::ISC_REQ_CONFIDENTIALITY | 
                Windows::Constants::ISC_REQ_REPLAY_DETECT | 
                Windows::Constants::ISC_REQ_CONNECTION

  def setup
    @client = Win32::SSPI::Negotiate::Client.new(spn:SPN)
  end

  def test_spn_basic_functionality
    assert_respond_to(@client, :spn)
    assert_nothing_raised{ @client.spn }
    assert_kind_of(String, @client.spn)
    assert_equal "HTTP/virtual-server.gas.local", @client.spn
  end

  def test_auth_type_basic_functionality
    assert_respond_to(@client, :auth_type)
    assert_nothing_raised{ @client.auth_type }
    assert_kind_of(String, @client.auth_type)
    assert_equal "Negotiate", @client.auth_type
    
    client = Win32::SSPI::Negotiate::Client.new(spn:SPN, auth_type:"Kerberos")
    assert_equal "Kerberos", client.auth_type
  end

  def test_token_basic_functionality
    assert_respond_to(@client, :token)
    assert_nothing_raised{ @client.token }
    assert_nil @client.token
  end

  def test_acquire_handle_basic_functionality
    assert_respond_to(@client, :acquire_handle)
    assert_equal 0, @client.method(:acquire_handle).arity
    assert_respond_to(@client, :acquire_credentials_handle)
    assert_equal 9, @client.method(:acquire_credentials_handle).arity
  end

  def test_initialize_context_basic_functionality
    assert_respond_to(@client, :initialize_context)
    assert_equal( -1, @client.method(:initialize_context).arity)
    assert_respond_to(@client, :initialize_security_context)
    assert_equal 12, @client.method(:initialize_security_context).arity
  end

  def test_authenticate_and_continue_basic_functionality
    assert_respond_to(@client, :authenticate_and_continue?)
    assert_equal 1, @client.method(:authenticate_and_continue?).arity
  end
  
  def test_acquire_handle_invokes_windows_api_as_expected
    client = Class.new(MockNegotiateClient).new(spn:SPN)
    assert_nothing_raised{ @status = client.acquire_handle }
    assert_equal Windows::Constants::SEC_E_OK, @status

    args = client.retrieve_state(:acquire)
    assert_equal 9, args.length, "acquire_credentials_handle should have 9 arguments"
    assert_equal SPN, args[0], "unexpected psz_principal"
    assert_equal 'Negotiate', args[1], "unexpected psz_package"
    assert_equal Windows::Constants::SECPKG_CRED_OUTBOUND, args[2], "unexpected f_credentialuse"
    assert_nil args[3], "unexpected pv_logonid"
    assert_nil args[4], "unexpected p_authdata"
    assert_nil args[5], "unexpected p_getkeyfn"
    assert_nil args[6], "unexpected p_getkeyarg"
    assert_kind_of Windows::Structs::CredHandle, args[7], "unexpected ph_newcredentials"
    assert_equal MockCredentialHandle, args[7].marshal_dump
    assert_kind_of Windows::Structs::TimeStamp, args[8], "unexpected pts_expiry"
    assert_equal MockTimeStamp, args[8].marshal_dump
  end
  
  def test_acquire_handle_memoizes_handle
    client = Class.new(MockNegotiateClient).new(spn:SPN)
    assert_nothing_raised{ client.acquire_handle }
    assert_nothing_raised{ @status = client.acquire_handle }
    assert_equal Windows::Constants::SEC_E_OK, @status
    assert_equal 9, client.retrieve_state(:acquire).length
  end
  
  def test_acquire_handle_raises_when_windows_api_returns_failed_status
    client = Class.new(MockNegotiateClient) do
      def acquire_credentials_handle(*args)
        capture_state(:acquire, args)
        return Windows::Constants::SEC_E_WRONG_PRINCIPAL
      end
    end.new(spn:SPN)

    assert_raises(SecurityStatusError){ client.acquire_handle }
  end
  
  def test_initialize_context_invokes_windows_api_as_expected
    client = Class.new(MockNegotiateClient).new(spn:SPN)
    assert_nothing_raised{ client.acquire_handle }
    assert_nothing_raised{ @status = client.initialize_context }
    assert_equal Windows::Constants::SEC_I_CONTINUE_NEEDED, @status

    args = client.retrieve_state(:isc)
    assert_equal 12, args.length, "unexpected arguments"
    assert_kind_of Windows::Structs::CredHandle, args[0], "unexpected ph_credentials"
    assert_equal MockCredentialHandle, args[0].marshal_dump
    assert_nil args[1], "unexpected ph_context"
    assert_equal SPN, args[2], "unexpected psz_targetname"
    
    assert_equal ContextAttr, args[3], "unexpected f_contextreq"
    assert_equal 0, args[4], "unexpected reserved1"
    assert_equal Windows::Constants::SECURITY_NETWORK_DREP, args[5], "unexpected targetrep"
    assert_nil args[6], "unexpected p_input"
    assert_equal 0, args[7], "unexpected reserved2"
    assert_kind_of Windows::Structs::CtxtHandle, args[8], "unexpected ph_newcontext"
    assert_equal MockContextHandle, args[8].marshal_dump
    assert_kind_of Windows::Structs::SecBufferDesc, args[9], "unexpected p_output"
    assert_equal MockSecBufferContent, client.token
    assert_kind_of FFI::MemoryPointer, args[10], "unexpected pf_contextattr"
    assert_equal ContextAttr, args[10].read_ulong
    assert_kind_of Windows::Structs::TimeStamp, args[11], "unexpected pts_expiry"
    assert_equal MockTimeStamp, args[11].marshal_dump
  end
  
  def test_initialize_context_raises_when_windows_api_returns_failed_status
    client = Class.new(MockNegotiateClient) do
      def initialize_security_context(*args)
        capture_state(:isc, args)
        return Windows::Constants::SEC_E_INVALID_TOKEN
      end
    end.new(spn:SPN)

    assert_nothing_raised{ client.acquire_handle }
    assert_raises(SecurityStatusError){ client.initialize_context }
  end
  
  def test_free_context_and_credentials
    client = Class.new(MockNegotiateClient).new(spn:SPN)
    credentials = client.create_credhandle(MockCredentialHandle)
    context = client.create_ctxhandle(MockContextHandle)
    result = client.free_context_and_credentials(context,credentials)
    status_ok = Windows::Constants::SEC_E_OK
    assert_equal({name:"",status:status_ok,dsc_status:status_ok,fch_status:status_ok}, result)
  end
  
  def test_free_context_and_credentials_when_failed_delete
    client = Class.new(MockNegotiateClient) do
      def delete_security_context(*args)
        return Windows::Constants::SEC_E_INVALID_HANDLE
      end
    end.new(spn:SPN)
    credentials = client.create_credhandle(MockCredentialHandle)
    context = client.create_ctxhandle(MockContextHandle)
    result = client.free_context_and_credentials(context,credentials)
    status_ok = Windows::Constants::SEC_E_OK
    status_failed = Windows::Constants::SEC_E_INVALID_HANDLE
    expected_result = {name:"DeleteSecurityContext",
                        status:status_failed, dsc_status:status_failed, fch_status:status_ok}
    assert_equal expected_result, result
  end
  
  def test_free_context_and_credentials_when_failed_free
    client = Class.new(MockNegotiateClient) do
      def free_credentials_handle(*args)
        return Windows::Constants::SEC_E_INVALID_HANDLE
      end
    end.new(spn:SPN)
    credentials = client.create_credhandle(MockCredentialHandle)
    context = client.create_ctxhandle(MockContextHandle)
    result = client.free_context_and_credentials(context,credentials)
    status_ok = Windows::Constants::SEC_E_OK
    status_failed = Windows::Constants::SEC_E_INVALID_HANDLE
    expected_result = {name:"FreeCredentialsHandle",
                        status:status_failed, dsc_status:status_ok, fch_status:status_failed}
    assert_equal expected_result, result
  end
  
  def test_free_context_and_credentials_when_both_fail
    client = Class.new(MockNegotiateClient) do
      def delete_security_context(*args)
        return Windows::Constants::SEC_E_INVALID_HANDLE
      end
      def free_credentials_handle(*args)
        return Windows::Constants::SEC_E_INVALID_HANDLE
      end
    end.new(spn:SPN)
    credentials = client.create_credhandle(MockCredentialHandle)
    context = client.create_ctxhandle(MockContextHandle)
    result = client.free_context_and_credentials(context,credentials)
    status_failed = Windows::Constants::SEC_E_INVALID_HANDLE
    expected_result = {name:"FreeCredentialsHandle",
                        status:status_failed, dsc_status:status_failed, fch_status:status_failed}
    assert_equal expected_result, result
  end
  
  def test_both_handles_freed_when_free_handles_raises
    client = Class.new(MockNegotiateClient) do
      def delete_security_context(*args)
        capture_state(:dsc, args)
        return Windows::Constants::SEC_E_INVALID_TOKEN
      end
    end.new(spn:SPN)

    assert_nothing_raised{ client.acquire_handle }
    assert_nothing_raised{ client.initialize_context }
    
    refute_nil client.instance_variable_get(:@context_handle)
    refute_nil client.instance_variable_get(:@credentials_handle)
    
    assert_raises{ client.free_handles }
    
    assert_nil client.instance_variable_get(:@context_handle)
    assert_nil client.instance_variable_get(:@credentials_handle)
  end
  
  def test_authenticate_and_continue
    client = Class.new(MockNegotiateClient) do
      def credentials_handle; @credentials_handle; end
      def context_handle; @context_handle; end
    end.new(spn:SPN)
    counter = 0
    token = nil
    while client.authenticate_and_continue?(token)
      token = client.token
      counter += 1
      fail "loop failed to complete in a reasonable iteration count" if counter > 3
    end

    acquire_args = client.retrieve_state(:acquire)
    refute_nil acquire_args
    assert_equal 9, acquire_args.length
    
    isc_args = client.retrieve_state(:isc)
    refute_nil isc_args
    assert_equal 12, isc_args.length
    
    dsc_args = client.retrieve_state(:dsc)
    refute_nil dsc_args
    assert_equal 1, dsc_args.length
    
    fch_args = client.retrieve_state(:fch)
    refute_nil fch_args
    assert_equal 1, fch_args.length
    
    assert_nil client.credentials_handle
    assert_nil client.context_handle
  end
  
  def test_authenticate_and_continue_when_no_authenticate_header
    # while experimenting with the ruby win32-sspi client
    # and apache/mod_authnz_sspi combination I discovered that mod_authnz_sspi
    # does not return a www-authenticate header when the client
    # provides an authorization header for kerberos authentication.
    # It assumes that the client by providing an authorization header
    # the transaction is in its final leg which strictly speaking is
    # not correct. The final leg of the transaction should be signaled
    # by the return status from AcceptSecurityContext. So the end result
    # was that this client would blow out sideways because the token passed
    # to authenticate_and_continue in the 2nd leg of the transaction is
    # nil (since the server did not return any www-authenticate header).
    # To remedy this I placed a condition at the start of initialize_context
    # that states if the given token is nil and the context_handle instance
    # variable is not nil (thus we are in leg n (>1)) of the authentication
    # transaction then we must be complete.
    # TODO:
    # => Revisit mod_authnz_sspi and see if this can be fixed because
    # => I believe this is a bug or oversite in that module
    #
    client = Class.new(MockNegotiateClient).new(spn:SPN)
    counter = 0
    token = nil
    while client.authenticate_and_continue?(token)
      # normally token would be updated from the www-authenticate header
      # received from the server
      # auth_type, token = client.de_construct_http_header( resp['www-authenticate'] )
      # but for this test leave the token nil and verify that authentication terminates
      # as expected
      counter += 1
      fail "loop failed to complete in a reasonable iteration count" if counter > 3
    end

    acquire_args = client.retrieve_state(:acquire)
    refute_nil acquire_args
    assert_equal 9, acquire_args.length
    
    isc_args = client.retrieve_state(:isc)
    refute_nil isc_args
    assert_equal 12, isc_args.length
    
    dsc_args = client.retrieve_state(:dsc)
    refute_nil dsc_args
    assert_equal 1, dsc_args.length
    
    fch_args = client.retrieve_state(:fch)
    refute_nil fch_args
    assert_equal 1, fch_args.length
    
    assert_nil client.instance_variable_get(:@credentials_handle)
    assert_nil client.instance_variable_get(:@context_handle)
  end
  
  def test_acquire_handle_invokes_windows_api_as_expected_with_ntlm_auth_type
    client = Class.new(MockNegotiateClient).new(auth_type:'NTLM')
    assert_nothing_raised{ @status = client.acquire_handle }
    assert_equal Windows::Constants::SEC_E_OK, @status

    args = client.retrieve_state(:acquire)
    assert_equal 9, args.length, "acquire_credentials_handle should have 9 arguments"
    assert_nil args[0], "unexpected psz_principal"
    assert_equal 'NTLM', args[1], "unexpected psz_package"
    assert_equal Windows::Constants::SECPKG_CRED_OUTBOUND, args[2], "unexpected f_credentialuse"
    assert_nil args[3], "unexpected pv_logonid"
    assert_kind_of Windows::Structs::SEC_WINNT_AUTH_IDENTITY, args[4], "unexpected p_authdata"
    assert_equal ENV['USERNAME'], args[4].user_to_ruby_s
    assert_equal ENV['USERDOMAIN'], args[4].domain_to_ruby_s
    assert_nil args[5], "unexpected p_getkeyfn"
    assert_nil args[6], "unexpected p_getkeyarg"
    assert_kind_of Windows::Structs::CredHandle, args[7], "unexpected ph_newcredentials"
    assert_equal MockCredentialHandle, args[7].marshal_dump
    assert_kind_of Windows::Structs::TimeStamp, args[8], "unexpected pts_expiry"
    assert_equal MockTimeStamp, args[8].marshal_dump
  end
  
  def test_http_authenticate
    client = Class.new(MockNegotiateClient).new(spn:SPN)
    counter = 0
    client.http_authenticate do |header|
      counter += 1
      fail "loop failed to complete in a reasonable iteration count" if counter > 3
      header
    end
    
    assert_equal 1, counter

    acquire_args = client.retrieve_state(:acquire)
    refute_nil acquire_args
    assert_equal 9, acquire_args.length
    
    isc_args = client.retrieve_state(:isc)
    refute_nil isc_args
    assert_equal 12, isc_args.length
    
    dsc_args = client.retrieve_state(:dsc)
    refute_nil dsc_args
    assert_equal 1, dsc_args.length
    
    fch_args = client.retrieve_state(:fch)
    refute_nil fch_args
    assert_equal 1, fch_args.length
    
    assert_nil client.instance_variable_get(:@credentials_handle)
    assert_nil client.instance_variable_get(:@context_handle)
  end
  
  def test_http_authenticate_with_ntlm_protocol
    client = Class.new(MockNegotiateClient).new(auth_type:'NTLM')
    counter = 0
    client.http_authenticate do |header|
      counter += 1
      fail "loop failed to complete in a reasonable iteration count" if counter > 3
      header
    end

    assert_equal 2, counter

    acquire_args = client.retrieve_state(:acquire)
    refute_nil acquire_args
    assert_equal 9, acquire_args.length
    
    isc_args = client.retrieve_state(:isc)
    refute_nil isc_args
    assert_equal 12, isc_args.length
    
    dsc_args = client.retrieve_state(:dsc)
    refute_nil dsc_args
    assert_equal 1, dsc_args.length
    
    fch_args = client.retrieve_state(:fch)
    refute_nil fch_args
    assert_equal 1, fch_args.length
    
    assert_nil client.instance_variable_get(:@credentials_handle)
    assert_nil client.instance_variable_get(:@context_handle)
  end
  
  def teardown
    @client = nil
  end
end

class MockNegotiateClient < Win32::SSPI::Negotiate::Client
  def acquire_credentials_handle(*args)
    s_args = retrieve_state(:acquire) || Array.new
    s_args << args
    capture_state(:acquire,s_args.flatten)
    # this api should return a credential handle in arg[7] and a timestamp in arg[8]
    args[7].marshal_load(TC_Win32_SSPI_Negotiate_Client::MockCredentialHandle)
    args[8].marshal_load(TC_Win32_SSPI_Negotiate_Client::MockTimeStamp)
    return Windows::Constants::SEC_E_OK
  end
  
  def initialize_security_context(*args)
    capture_state(:isc, args)
    status = Windows::Constants::SEC_E_OK
    status = Windows::Constants::SEC_I_CONTINUE_NEEDED if args[6].nil?
    # this api should return a new context, p_output, context attr and timestamp
    args[8].marshal_load(TC_Win32_SSPI_Negotiate_Client::MockContextHandle)
    args[9].marshal_load(TC_Win32_SSPI_Negotiate_Client::MockSecBufferContent)
    args[10].write_ulong(TC_Win32_SSPI_Negotiate_Client::ContextAttr)
    args[11].marshal_load(TC_Win32_SSPI_Negotiate_Client::MockTimeStamp)
    return status
  end
  
  def delete_security_context(*args)
    capture_state(:dsc,args)
    return Windows::Constants::SEC_E_OK
  end
  
  def free_credentials_handle(*args)
    capture_state(:fch,args)
    return Windows::Constants::SEC_E_OK
  end
  
  def capture_state(key,value)
    self.class.capture_state(key,value)
  end
  
  def retrieve_state(key)
    self.class.retrieve_state(key)
  end
  
  def self.state
    @state ||= Hash.new
  end
  
  def self.capture_state(key,value)
    state[key] = value
  end
  
  def self.retrieve_state(key)
    state[key]
  end
  
  def self.clear_state
    state.clear
  end
end
