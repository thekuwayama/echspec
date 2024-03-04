module EchSpec
  class Ok
    attr_reader :obj

    def initialize(obj)
      @obj = obj
    end

    def deconstruct
      [@obj]
    end
  end

  class Err
    attr_reader :details

    def initialize(details)
      @details = details
    end

    def deconstruct
      [@details]
    end
  end
end
