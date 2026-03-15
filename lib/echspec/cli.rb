require_relative 'cli/gen_configs'
require_relative 'cli/run'

module EchSpec
  class CLI
    using Refinements

    def execute(argv = ARGV)
      subcommands = %i[run gen_configs]

      op = OptionParser.new

      op.banner = <<~USAGE
        Usage: echspec {SUBCOMMAND}

        Available subcommands: #{subcommands.join(', ')}, version, help.
      USAGE

      op.version = EchSpec::VERSION
      op.order!(argv)

      subcommand = argv.shift
      case subcommand&.to_sym
      when :version
        puts EchSpec::VERSION
      when *subcommands
        klass = self.class.const_get(subcommand.to_camel)
        klass.new.__send__(:execute, argv)
      else
        puts op
      end
    end
  end
end
