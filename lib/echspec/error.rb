module EchSpec
  module Error
    # Generic error, common for all classes under EchSpec::Error module.
    class Error < StandardError; end

    # Raised if the server behaves unintended before the target situation.
    class BeforeTargetSituationError < Error; end
  end
end
