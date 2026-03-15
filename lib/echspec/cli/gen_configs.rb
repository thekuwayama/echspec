module EchSpec
  class CLI
    class GenConfigs
      def execute(argv)
        fpath = parse_options(argv)
        gen(fpath)
      end

      def parse_options(argv)
        op = OptionParser.new

        op.banner = 'Usage: echspec gen_configs {FILE_PATH}'

        begin
          args = op.parse(argv)
        rescue OptionParser::InvalidOption, OptionParser::MissingArgument => e
          warn op
          warn "** #{e.message}"
          exit 1
        end

        if args.length != 1
          warn op
          warn '** {FILE_PATH} argument is not specified'
          exit 1
        end
        args[0]
      end

      def gen(fpath)
        hostname = 'localhost'

        key = OpenSSL::PKey.generate_key('X25519')
        echconfigs = ECHConfigList.new(
          [
            ECHConfig.new(
              "\xfe\x0d".b,
              ECHConfig::ECHConfigContents.new(
                ECHConfig::ECHConfigContents::HpkeKeyConfig.new(
                  123,
                  ECHConfig::ECHConfigContents::HpkeKeyConfig::HpkeKemId.new(HPKE::DHKEM_X25519_HKDF_SHA256),
                  ECHConfig::ECHConfigContents::HpkeKeyConfig::HpkePublicKey.new(key.raw_public_key),
                  [
                    ECHConfig::ECHConfigContents::HpkeKeyConfig::HpkeSymmetricCipherSuite.new(
                      ECHConfig::ECHConfigContents::HpkeKeyConfig::HpkeSymmetricCipherSuite::HpkeKdfId.new(HPKE::HKDF_SHA256),
                      ECHConfig::ECHConfigContents::HpkeKeyConfig::HpkeSymmetricCipherSuite::HpkeAeadId.new(HPKE::AES_128_GCM)
                    )
                  ]
                ),
                32,
                hostname.b,
                ECHConfig::ECHConfigContents::Extensions.new('')
              )
            )
          ]
        )
        File.write(fpath, key.private_to_pem + echconfigs.to_pem)
      end
    end
  end
end
