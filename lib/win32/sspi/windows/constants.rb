module Windows
  module Constants
    SECURITY_NATIVE_DREP              = 0x00000010
    SECURITY_NETWORK_DREP             = 0x00000000
    SEC_WINNT_AUTH_IDENTITY_ANSI      = 1
    SEC_WINNT_AUTH_IDENTITY_UNICODE   = 2
    SECBUFFER_TOKEN                   = 2
    SECBUFFER_VERSION                 = 0
    TOKENBUFSIZE                      = 12000

    SECPKG_ATTR_NAMES                 = 1
    SECPKG_CRED_INBOUND               = 0x00000001
    SECPKG_CRED_OUTBOUND              = 0x00000002

    ISC_REQ_CONFIDENTIALITY           = 0x00000010
    ISC_REQ_REPLAY_DETECT             = 0x00000004
    ISC_REQ_CONNECTION                = 0x00000800

    ASC_REQ_DELEGATE                  = 0x00000001
    ASC_REQ_MUTUAL_AUTH               = 0x00000002
    ASC_REQ_REPLAY_DETECT             = 0x00000004
    ASC_REQ_SEQUENCE_DETECT           = 0x00000008
    ASC_REQ_CONFIDENTIALITY           = 0x00000010
    ASC_REQ_CONNECTION                = 0x00000800
    
    SEC_E_OK                          = 0x00000000
    SEC_I_CONTINUE_NEEDED             = 0x00090312
    SEC_I_COMPLETE_NEEDED             = 0x00090313
    SEC_I_COMPLETE_AND_CONTINUE       = 0x00090314
    SEC_E_INVALID_HANDLE              = 0x80090301
    SEC_E_INVALID_TOKEN               = 0x80090308
    SEC_E_LOGON_DENIED                = 0x8009030C
    SEC_E_SECPKG_NOT_FOUND            = 0x80090305
    SEC_E_WRONG_PRINCIPAL             = 0x80090322
  end
end
