module EchSpec
  class CLI
    module EchConfigPrinter
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
            ['        kdf_id(hex):', cs.kdf_id.encode.unpack1('H4').scan(/.{2}/).join(' ')],
            ['        aead_id(hex):', cs.aead_id.encode.unpack1('H4').scan(/.{2}/).join(' ')]
          ]
        end

        [
          ['ECHConfig:', ''],
          ['  version(hex):', c.version.unpack1('H4').scan(/.{2}/).join(' ')],
          ['  length(integer):', ec.encode.length],
          ['  contents:', ''],
          ['    key_config:', ''],
          ['      config_id(integer):', kc.config_id],
          ['      kem_id(hex):', kc.kem_id.encode.unpack1('H4').scan(/.{2}/).join(' ')],
          ['      public_key(hex):', kc.public_key.opaque.unpack1('H*').scan(/.{2}/).join(' ')],
          ['      cipher_suites:', ''],
          *cipher_suite_pairs,
          ['    maximum_name_length(integer):', ec.maximum_name_length],
          ['    public_name(string):', ec.public_name],
          ['    extensions(hex):', ext]
        ]
      end
      # rubocop: enable Metrics/AbcSize
    end
  end
end
