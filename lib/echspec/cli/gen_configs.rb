module EchSpec
  class CLI
    class GenConfigs
      def execute(argv)
        fpath = parse_options(argv)
        write(fpath)
      end

      def parse_options(argv)
        op = OptionParser.new

        op.banner = <<~USAGE
          Usage: echspec gen_configs {FILE}

          Generate an ECHConfig PEM file.

          Examples:

            $ echspec gen_configs echconfigs.pem
        USAGE

        begin
          args = op.parse(argv)
        rescue OptionParser::InvalidOption, OptionParser::MissingArgument => e
          warn op
          warn "** #{e.message}"
          exit 1
        end

        if args.length != 1
          warn op
          warn '** {FILE} argument is not specified'
          exit 1
        end
        args[0]
      end

      def write(fpath)
        key = OpenSSL::PKey.generate_key('X25519')
        echconfigs = ECHConfigList.new([EchConfig.gen_ech_config(key.raw_public_key)])
        File.write(fpath, key.private_to_pem + echconfigs.to_pem)
      end
    end
  end
end
