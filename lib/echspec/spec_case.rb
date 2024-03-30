module EchSpec
  module Spec
    class SpecCase
      attr_reader :description
      attr_reader :method

      def initialize(description, method)
        @description = description
        @method = method
      end
    end
  end
end
