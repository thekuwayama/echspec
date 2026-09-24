module EchSpec
  module Spec
    class Spec9
      # In the absence of an application profile standard specifying
      # otherwise, a compliant ECH application MUST implement the following
      # HPKE cipher suite:
      #
      # * KEM: DHKEM(X25519, HKDF-SHA256) (see Section 7.1 of [HPKE])
      # * KDF: HKDF-SHA256 (see Section 7.2 of [HPKE])
      # * AEAD: AES-128-GCM (see Section 7.3 of [HPKE])
      #
      # https://datatracker.ietf.org/doc/html/rfc9849#section-9
      @section = '9'
      @description = 'MUST implement the following HPKE cipher suite: KEM: DHKEM(X25519, HKDF-SHA256), KDF: HKDF-SHA256 and AEAD: AES-128-GCM.'
      class << self
        attr_reader :description, :section

        # @param fpath [String | NilClass]
        # @param hostname [String]
        # @param force_compliant [Boolean]
        #
        # @return [EchSpec::Ok<ECHConfig> | Err]
        def try_get_ech_config(fpath, hostname, force_compliant)
          result = if fpath.nil?
                     resolve_ech_configs(hostname)
                   else
                     parse_pem(File.open(fpath).read)
                   end

          ech_configs = case result
                        in Ok(obj)
                          obj
                        in Err
                          return result
                        end

          if force_compliant
            validate_compliant_ech_configs(ech_configs)
          else
            Ok.new(ech_configs.first)
          end
        end

        # @param ech_configs [Array<ECHConfig>]
        #
        # @return [EchSpec::Ok | Err]
        def validate_compliant_ech_configs(ech_configs)
          ech_config = ech_configs.find do |c|
            kconfig = c.echconfig_contents.key_config
            valid_kem_id = kconfig.kem_id.uint16 == HPKE::DHKEM_X25519_HKDF_SHA256
            valid_cipher_suite = kconfig.cipher_suites.any? do |cs|
              cs.kdf_id.uint16 == HPKE::HKDF_SHA256 && cs.aead_id.uint16 == HPKE::AES_128_GCM
            end

            valid_kem_id && valid_cipher_suite
          end
          return Ok.new(ech_config) unless ech_config.nil?

          Err.new('ECHConfigs does NOT include HPKE cipher suite: KEM: DHKEM(X25519, HKDF-SHA256), KDF: HKDF-SHA256 and AEAD: AES-128-GCM.', nil)
        end

        # @param hostname [String]
        #
        # @return [EchSpec::Ok<Array<ECHConfig>> | Err]
        def resolve_ech_configs(hostname)
          begin
            rr = Resolv::DNS.new.getresource(
              hostname,
              Resolv::DNS::Resource::IN::HTTPS
            )
          rescue Resolv::ResolvError => e
            return Err.new(e.message, nil)
          end

          # https://datatracker.ietf.org/doc/html/rfc9934#section-3
          ech = 5
          return Err.new("HTTPS resource record for #{hostname} does NOT have ech SvcParams.", nil) if rr.params[ech].nil?

          octet = rr.params[ech].value
          return Err.new('Failed to parse ECHConfig on HTTPS resource record.', nil) \
            unless octet.length >= 2 && octet.length == octet.slice(0, 2).unpack1('n') + 2

          Ok.new(ECHConfig.decode_vectors(octet.slice(2..)))
        end

        # @param hostname [String]
        #
        # @return [EchSpec::Ok<Array<ECHConfig>> | Err]
        def well_known_origin_svcb(hostname)
          res = fetch_well_known(hostname)
          body = case res
                 in Ok(obj)
                   obj
                 in Err
                   return res
                 end

          parse_origin_svcb(body)
        end

        # https://datatracker.ietf.org/doc/html/draft-ietf-tls-wkech-12
        WK_ECH_PATH = '/.well-known/origin-svcb'.freeze
        private_constant :WK_ECH_PATH

        # @param hostname [String]
        #
        # @return [EchSpec::Ok | Err]
        def fetch_well_known(hostname)
          uri = URI("https://#{hostname}#{WK_ECH_PATH}")
          res = Net::HTTP.get_response(uri)
          return Err.new("GET #{uri} returned #{res.code}.", nil) unless res.is_a?(Net::HTTPSuccess)

          Ok.new(res.body)
        rescue StandardError => e
          Err.new(e.message, nil)
        end

        # {
        #   "regeninterval": 3600,
        #   "endpoints": [
        #     {
        #       "priority": 1,
        #       "params": {
        #         "ipv4hint": [ "192.0.2.1", "192.0.2.254" ],
        #         "ech": "AD7+DQA6NAAgACCn3zNTeX/WOD...AAA==",
        #         "ipv6hint": [ "2001:DB::ec4" ],
        #         "alpn": [ "h2", "http/1.1" ]
        #       }
        #     }
        #   ]
        # }
        #
        # https://datatracker.ietf.org/doc/html/draft-ietf-tls-wkech-12#section-5
        #
        # @param body [String]
        #
        # @return [EchSpec::Ok | Err]
        # rubocop: disable Metrics/CyclomaticComplexity
        # rubocop: disable Metrics/PerceivedComplexity
        def parse_origin_svcb(body)
          h = JSON.parse(body)
          echs = h['endpoints']&.filter_map { |e| e.dig('params', 'ech') }
          return Err.new('The origin-svcb well-known resource does NOT have ech SvcParams.', nil) if echs.nil? || echs.empty?

          # if parsing any one of the ech values fails, return Err
          ech_configs = echs.flat_map do |ech|
            octet = Base64.decode64(ech)
            return Err.new('Failed to parse ECHConfig on the origin-svcb well-known resource.', nil) \
              unless octet.length >= 2 && octet.length == octet.slice(0, 2).unpack1('n') + 2

            ECHConfig.decode_vectors(octet.slice(2..))
          end

          Ok.new(ech_configs)
        rescue StandardError => e
          Err.new(e.message, nil)
        end
        # rubocop: enable Metrics/CyclomaticComplexity
        # rubocop: enable Metrics/PerceivedComplexity

        # @param pem [String]
        #
        # @return [EchSpec::Ok<Array<ECHConfig>> | Err]
        def parse_pem(pem)
          s = pem.scan(/-----BEGIN ECHCONFIG-----(.*)-----END ECHCONFIG-----/m)
                 .first
                 .first
                 .gsub("\n", '')
          b = Base64.decode64(s)
          return Err.new('Failed to parse ECHConfig on the PEM file.', nil) \
            unless b.length >= 2 && b.length == b.slice(0, 2).unpack1('n') + 2

          ech_configs = ECHConfig.decode_vectors(b.slice(2..))
          Ok.new(ech_configs)
        rescue StandardError
          # https://datatracker.ietf.org/doc/html/rfc9934#section-3
          example = <<~PEM
            -----BEGIN PRIVATE KEY-----
            MC4CAQAwBQYDK2VuBCIEICjd4yGRdsoP9gU7YT7My8DHx1Tjme8GYDXrOMCi8v1V
            -----END PRIVATE KEY-----
            -----BEGIN ECHCONFIG-----
            AD7+DQA65wAgACA8wVN2BtscOl3vQheUzHeIkVmKIiydUhDCliA4iyQRCwAEAAEA
            AQALZXhhbXBsZS5jb20AAA==
            -----END ECHCONFIG-----
          PEM
          Err.new("Failed to parse ECHConfig PEM file, expected ECHConfig PEM like following: \n\n#{example}", nil)
        end
      end
    end
  end
end
