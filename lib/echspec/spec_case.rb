module EchSpec
  class SpecCase
    attr_reader :description, :method

    def initialize(description, method)
      @description = description
      @method = method
    end
  end
end
