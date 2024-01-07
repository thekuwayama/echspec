module EchSpec
  class CLI
    def parse_options(argv = ARGV)
      op = OptionParser.new

      # default value
      fpath = nil

      op.on(
        '-f',
        '--file FILE',
        'path to ECHConfigs PEM file       (default resolve ECHConfigs via DNS)'
      ) do |v|
        fpath = v
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

      [fpath, args[0]]
    end

    def run
      fpath, name = parse_options
      Spec.run(fpath, name)
    end
  end
end
