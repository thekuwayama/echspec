module EchSpec
  class CLI
    class Resolve
      include EchConfigPrinter
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
    end
  end
end
