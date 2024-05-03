module EchSpec
  class CLI
    # rubocop: disable Metrics/MethodLength
    def parse_options(argv = ARGV)
      op = OptionParser.new

      # default value
      fpath = nil
      port = 443
      force_compliant = true
      verbose = false

      op.on(
        '-f',
        '--file FILE',
        'path to ECHConfigs PEM file       (default resolve ECHConfigs via DNS)'
      ) do |v|
        fpath = v
      end

      op.on(
        '-p',
        '--port VALUE',
        "server port number                (default #{port})"
      ) do |v|
        port = v
      end

      op.on(
        '-n',
        '--not-force-compliant-hpke',
        'not force compliant ECHConfig HPKE cipher suite'
      ) do
        force_compliant = false
      end

      op.on(
        '-v',
        '--verbose',
        'verbose mode; prints message stack if raised an error'
      ) do
        verbose = true
      end

      op.banner += ' hostname [section]'
      begin
        args = op.parse(argv)
      rescue OptionParser::InvalidOption, OptionParser::MissingArgument => e
        warn op
        warn "** #{e.message}"
        exit 1
      end

      if !fpath.nil? && !File.exist?(fpath)
        warn '** FILE is not found'
        exit 1
      end

      if args.empty?
        warn op
        warn '** `hostname` argument is not specified'
        exit 1
      end
      hostname = args[0]
      section = (args.size == 1 ? nil : args[1])

      [fpath, port, force_compliant, verbose, hostname, section]
    end
    # rubocop: enable Metrics/MethodLength

    def run
      fpath, port, force_compliant, verbose, hostname, section = parse_options

      if section.nil?
        Spec.run(fpath, port, hostname, force_compliant, verbose)
      else
        Spec.run_only(fpath, port, hostname, section, verbose)
      end
    end
  end
end
