module EchSpec
  class Ok
    attr_reader :description

    def initialize(description)
      @description = description
    end

    def deconstruct
      [@description]
    end
  end

  class Err
    attr_reader :description
    attr_reader :details

    def initialize(description, details)
      @description = description
      @details = details
    end

    def deconstruct
      [@description, @details]
    end
  end
end
