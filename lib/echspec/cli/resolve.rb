module EchSpec
  class CLI
    class Resolve
      def execute(argv)
        fpath, hostname = parse_options(argv)

        result = if fpath.nil?
                   Spec::Spec9.resolve_ech_configs(hostname)
                 else
                   Spec::Spec9.parse_pem(File.read(fpath))
                 end

        case result
        in Ok(ech_configs)
          print_ech_configs(ech_configs)
        in Err(details, _)
          warn "** #{details}"
          exit 1
        end
      end

      # rubocop: disable Metrics/MethodLength
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
          Usage: echspec resolve [OPTIONS...] [{HOSTNAME}]

          Resolve ECHConfigs for a hostname and print fields.
          {HOSTNAME} is required unless -f is specified.

          Examples:

            $ echspec resolve localhost
            $ echspec resolve -f echconfigs.pem

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

        if fpath.nil? && args.length != 1
          warn op
          warn '** {HOSTNAME} argument is not specified'
          exit 1
        end

        [fpath, args[0]]
      end
      # rubocop: enable Metrics/MethodLength

      def print_ech_configs(ech_configs)
        all_pairs = ech_configs.map { |c| field_pairs(c) }
        label_width, value_width = evaluate_widths(all_pairs)

        all_pairs.each_with_index do |pairs, i|
          puts "#{'─' * label_width}┼#{'─' * value_width}" if i.positive?
          pairs.each { |label, value| print_field(label, value, label_width) }
        end
      end

      def evaluate_widths(all_pairs)
        label_width = all_pairs.flat_map { |pairs| pairs.map { |label, _| label.length } }.max + 1
        value_width = all_pairs.flat_map { |pairs| pairs.map { |_, value| value.to_s.length } }.max + 1
        [label_width, value_width]
      end

      def print_field(label, value, label_width)
        puts "#{label.ljust(label_width)}│ #{value}"
      end

      # rubocop: disable Metrics/AbcSize
      def field_pairs(c)
        ec = c.echconfig_contents
        kc = ec.key_config
        ext = ec.extensions.octet.unpack1('H*').scan(/.{2}/).join(' ')
        cipher_suite_pairs = kc.cipher_suites.flat_map do |cs|
          [
            ['        kdf_id(uint16):', cs.kdf_id.encode.unpack1('H4').scan(/.{2}/).join(' ')],
            ['        aead_id(uint16):', cs.aead_id.encode.unpack1('H4').scan(/.{2}/).join(' ')]
          ]
        end

        [
          ['ECHConfig:', ''],
          ['  version(uint16):', c.version.unpack1('H4').scan(/.{2}/).join(' ')],
          ['  length(uint16):', ec.encode.length],
          ['  contents(ECHConfigContents):', ''],
          ['    key_config(HpkeKeyConfig):', ''],
          ['      config_id(uint8):', kc.config_id],
          ['      kem_id(uint16):', kc.kem_id.encode.unpack1('H4').scan(/.{2}/).join(' ')],
          ['      public_key(opaque):', kc.public_key.opaque.unpack1('H*').scan(/.{2}/).join(' ')],
          ['      cipher_suites(HpkeSymmetricCipherSuite):', ''],
          *cipher_suite_pairs,
          ['    maximum_name_length(uint8):', ec.maximum_name_length],
          ['    public_name(opaque):', ec.public_name],
          ['    extensions(opaque):', ext]
        ]
      end
      # rubocop: enable Metrics/AbcSize
    end
  end
end
