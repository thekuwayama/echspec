module EchSpec
  class CLI
    class Grease
      include EchConfigPrinter

      def execute(argv)
        port, hostname = parse_options(argv)

        TTTLS13::Logging.logger.level = Logger::WARN
        socket = TCPSocket.new(hostname, port)
        recv = TLS13Client.send_ch_with_greased_ech(socket, hostname)
        ex = recv.extensions[TTTLS13::Message::ExtensionType::ENCRYPTED_CLIENT_HELLO]

        if ex.nil? || ex.retry_configs.nil? || ex.retry_configs.empty?
          warn "** #{hostname}:#{port} did not send retry_configs"
          exit 1
        end

        print_ech_configs(ex.retry_configs)
      rescue Timeout::Error
        warn "** #{hostname}:#{port} connection timeout"
        exit 1
      rescue Errno::ECONNREFUSED
        warn "** #{hostname}:#{port} connection refused"
        exit 1
      ensure
        socket&.close
      end

      def parse_options(argv)
        op = OptionParser.new
        port = 443

        op.on(
          '-p',
          '--port VALUE',
          "server port number                (default #{port})"
        ) do |v|
          port = v
        end

        op.banner = <<~USAGE
          Usage: echspec grease [OPTIONS...] {HOSTNAME}

          Send GREASE ECH to a server and display retry_configs.

          Examples:

            $ echspec grease localhost
            $ echspec grease -p 4433 localhost

          Options:
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
          warn '** {HOSTNAME} argument is not specified'
          exit 1
        end

        [port, args[0]]
      end
    end
  end
end
