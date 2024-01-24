module EchSpec
  class CLI
    def parse_options(argv = ARGV)
      op = OptionParser.new

      # default value
      fpath = nil
      port = 443

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
        'the name server port number       (default 443)'
      ) do |v|
        port = v
      end

      op.banner += ' name'
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

      if args.size != 1
        warn op
        warn '** `name` argument is not specified'
        exit 1
      end

      [fpath, port, args[0]]
    end

    def run
      fpath, port, name = parse_options
      Spec.run(fpath, port, name)
    end
  end
end
