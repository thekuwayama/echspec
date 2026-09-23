module EchSpec
  module Spec
    class Spec6_1_7_5
      # Prior to attempting a connection, a client SHOULD validate the
      # ECHConfig.contents.public_name. Clients SHOULD ignore any ECHConfig
      # structure with a public_name that is not a valid host name in
      # preferred name syntax (see Section 2 of [DNS-TERMS]). That is, to be
      # valid, the public_name needs to be a dot-separated sequence of LDH
      # labels, as defined in Section 2.3.1 of [RFC5890], where:
      #
      # * the sequence does not begin or end with an ASCII dot, and
      # * all labels are at most 63 octets.
      #
      # Clients additionally SHOULD ignore the structure if the final LDH
      # label either consists of all ASCII digits (i.e., '0' through '9') or
      # is "0x" or "0X" followed by some, possibly empty, sequence of ASCII
      # hexadecimal digits (i.e., '0' through '9', 'a' through 'f', and 'A'
      # through 'F'). This avoids public_name values that may be interpreted
      # as IPv4 literals.
      #
      # https://datatracker.ietf.org/doc/html/rfc9849#section-6.1.7-5

      # @return [EchSpec::SpecGroup]
      def self.spec_group
        SpecGroup.new(
          '6.1.7-5',
          [
            SpecCase.new(
              'Clients SHOULD ignore any ECHConfig structure with a public_name that is not a valid host name in preferred name syntax.',
              method(:validate_preferred_name_syntax)
            ),
            SpecCase.new(
              'Clients SHOULD ignore the structure if the final LDH label may be interpreted as IPv4 literals.',
              method(:validate_not_ipv4_like)
            )
          ]
        )
      end

      # @param _hostname [String]
      # @param _port [Integer]
      # @param ech_config [ECHConfig]
      #
      # @return [EchSpec::Ok | Err]
      def self.validate_preferred_name_syntax(_hostname, _port, ech_config)
        public_name = ech_config.echconfig_contents.public_name
        return Ok.new(nil) if valid_public_name?(public_name)

        Err.new("public_name #{public_name.inspect} is NOT a dot-separated sequence of LDH labels of at most 63 octets.", nil)
      end

      # @param _hostname [String]
      # @param _port [Integer]
      # @param ech_config [ECHConfig]
      #
      # @return [EchSpec::Ok | Err]
      def self.validate_not_ipv4_like(_hostname, _port, ech_config)
        public_name = ech_config.echconfig_contents.public_name
        return Ok.new(nil) unless ipv4_like?(public_name)

        Err.new("public_name #{public_name.inspect} has the final label that may be interpreted as IPv4 literals.", nil)
      end

      # https://datatracker.ietf.org/doc/html/rfc5890#section-2.3.1
      LDH_LABEL = /\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\z/
      private_constant :LDH_LABEL

      # @param public_name [String]
      #
      # @return [Boolean]
      def self.valid_public_name?(public_name)
        labels = public_name.b.split('.', -1)
        !labels.empty? && labels.all? { |label| LDH_LABEL.match?(label) }
      end

      # @param public_name [String]
      #
      # @return [Boolean]
      def self.ipv4_like?(public_name)
        final_label = public_name.b.split('.', -1).last
        return false if final_label.nil?

        /\A[0-9]+\z/.match?(final_label) || /\A0[xX][0-9A-Fa-f]*\z/.match?(final_label)
      end
    end
  end
end
