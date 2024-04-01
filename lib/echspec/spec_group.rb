module EchSpec
  class SpecGroup
    attr_reader :section
    attr_reader :spec_cases

    def initialize(section, spec_cases)
      @section = section
      @spec_cases = spec_cases
    end
  end
end
