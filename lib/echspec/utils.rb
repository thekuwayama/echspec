module EchSpec
  module Refinements
    refine String do
      def indent
        "\t#{self}"
      end

      def colorize(code)
        "\e[#{code}m#{self}\e[0m"
      end

      def red
        colorize(31)
      end

      def green
        colorize(32)
      end

      def yellow
        colorize(33)
      end
    end
  end
end
