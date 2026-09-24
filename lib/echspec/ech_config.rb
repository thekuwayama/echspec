module EchSpec
  module EchConfig
    # @param public_key [String]
    # @param kem_id [Integer]
    # @param kdf_id [Integer]
    # @param aead_id [Integer]
    #
    # @return [ECHConfig]
    def self.gen_ech_config(public_key, kem_id: HPKE::DHKEM_X25519_HKDF_SHA256, kdf_id: HPKE::HKDF_SHA256, aead_id: HPKE::AES_128_GCM)
      version = "\xfe\x0d".b
      config_id = 123
      maximum_name_length = 32
      hostname = 'localhost'

      ECHConfig.new(
        version,
        ECHConfig::ECHConfigContents.new(
          ECHConfig::ECHConfigContents::HpkeKeyConfig.new(
            config_id,
            ECHConfig::ECHConfigContents::HpkeKeyConfig::HpkeKemId.new(kem_id),
            ECHConfig::ECHConfigContents::HpkeKeyConfig::HpkePublicKey.new(public_key),
            [
              ECHConfig::ECHConfigContents::HpkeKeyConfig::HpkeSymmetricCipherSuite.new(
                ECHConfig::ECHConfigContents::HpkeKeyConfig::HpkeSymmetricCipherSuite::HpkeKdfId.new(kdf_id),
                ECHConfig::ECHConfigContents::HpkeKeyConfig::HpkeSymmetricCipherSuite::HpkeAeadId.new(aead_id)
              )
            ]
          ),
          maximum_name_length,
          hostname.b,
          ECHConfig::ECHConfigContents::Extensions.new('')
        )
      )
    end
  end
end
