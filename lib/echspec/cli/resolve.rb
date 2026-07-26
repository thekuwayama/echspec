module EchSpec
  class CLI
    class Resolve
      def execute(argv)
        fpath, hostname = parse_options(argv)

        result = if fpath.nil?
                   Spec::Spec9.resolve_ech_configs(hostname)
                 else
                   Spec::Spec9.parse_pem(File.open(fpath).read)
                 end

        case result
        in Ok(ech_configs)
          print_ech_configs(ech_configs)
        in Err(details, _)
          warn "** #{details}"
          exit 1
        end
      end

      def parse_options(argv)
        op = OptionParser.new
        fpath = nil

        op.on(
          '-f',
          '--file FILE',
          'path to ECHConfigs PEM file       (default resolve ECHConfigs via DNS)'
        ) do |v|
          fpath = v
        end

        op.banner = <<~USAGE
          Usage: echspec resolve [OPTIONS...] {HOSTNAME}

          Resolve ECHConfigs for a hostname and print fields.

          Examples:

            $ echspec resolve example.com
            $ echspec resolve -f echconfigs.pem example.com

          Options:
        USAGE

        begin
          args = op.parse(argv)
        rescue OptionParser::InvalidOption, OptionParser::MissingArgument => e
          warn op
          warn "** #{e.message}"
          exit 1
        end

        if !fpath.nil? && !File.exist?(fpath)
          warn '** {FILE} is not found'
          exit 1
        end

        if args.length != 1
          warn op
          warn '** {HOSTNAME} argument is not specified'
          exit 1
        end

        [fpath, args[0]]
      end

      def print_ech_configs(ech_configs)
        ech_configs.each_with_index do |c, i|
          puts "#{'─' * 48}┼#{'─' * 48}" if i > 0
          print_ech_config(c)
        end
      end

      def print_field(label, value)
        puts "#{label.ljust(48)}│ #{value}"
      end

      def print_ech_config(c)
        print_field("ECHConfig:", '')
        print_field("  version(uint16):", c.version.unpack1('H4').scan(/.{2}/).join(' '))
        ec = c.echconfig_contents
        print_field("  length(uint16):", ec.encode.length)
        print_field("  contents(ECHConfigContents):", '')
        print_field("    key_config(HpkeKeyConfig):", '')
        kc = ec.key_config
        print_field("      config_id(uint8):", kc.config_id)
        print_field("      kem_id(uint16):", kc.kem_id.encode.unpack1('H4').scan(/.{2}/).join(' '))
        print_field("      public_key(opaque):", kc.public_key.opaque.unpack1('H*').scan(/.{2}/).join(' '))
        print_field("      cipher_suites(HpkeSymmetricCipherSuite):", '')
        kc.cipher_suites.each do |cs|
          print_field("        kdf_id(uint16):", cs.kdf_id.encode.unpack1('H4').scan(/.{2}/).join(' '))
          print_field("        aead_id(uint16):", cs.aead_id.encode.unpack1('H4').scan(/.{2}/).join(' '))
        end
        print_field("    maximum_name_length(uint8):", ec.maximum_name_length)
        print_field("    public_name(opaque):", ec.public_name)
        ext = ec.extensions.octet.unpack1('H*').scan(/.{2}/).join(' ')
        print_field("    extensions(opaque):", ext)
      end
    end
  end
end
