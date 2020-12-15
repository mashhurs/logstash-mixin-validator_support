# encoding: utf-8

require 'logstash/version'
require 'logstash/namespace'

module LogStash
  module PluginMixins
    module ValidatorSupport

      ##
      # @api internal
      #
      # @param base [#validate_value]
      # @param validator_name [Symbol]
      def self.native?(base, validator_name)
        native_is_valid, native_coerced_or_error = base.validate_value(nil, validator_name)

        native_is_valid || !native_coerced_or_error.start_with?('Unknown validator')
      end

      ##
      # A NamedValidationAdapter is a module that can be mixed into a Logstash
      # plugin to ensure the named validator is present and available, whether
      # provided by Logstash core or approximated with the provided backport
      # implementation.
      #
      # @api internal
      #
      class NamedValidationAdapter < Module
        ##
        # Create a new named validation adapter, to approximate the implementation
        # of a named validation that exists in Logstash Core.
        #
        # @api private
        #
        # @param validator_name [Symbol]
        # @yieldparam value [Hash,Array]
        # @yieldreturn [true, Object]:  validation success returns true with coerced value (see: ValidationResult#success)
        # @yieldreturn [false, String]: validation failure returns false with error message (see: ValidationResult#failure)
        def initialize(validator_name, &validator_implementation)
          fail(ArgumentError, '`validator_name` must be a Symbol')         unless validator_name.kind_of?(Symbol)
          fail(ArgumentError, '`validator_implementation` block required') unless validator_implementation

          define_singleton_method(:validate, &validator_implementation)
          define_singleton_method(:name) { "#{NamedValidationAdapter}(#{validator_name})" }

          define_singleton_method(:extended) do |base|
            # Only include the interceptor if support is not natively provided.
            unless ValidatorSupport.native?(base, validator_name)
              interceptor = NamedValidationInterceptor.new(validator_name, self)
              base.extend(interceptor)
            end
          end
        end
      end

      ##
      # A NamedValidationInterceptor intercepts requests to validate input with the given
      # name and instead substitutes its own implementation. This implementation will
      # override Logstash core functionality.
      #
      # @api private
      #
      class NamedValidationInterceptor < Module
        ##
        # @param validator_name [Symbol]
        # @param validator [#validate]
        def initialize(validator_name, validator)
          fail(ArgumentError, '`validator_name` must be a Symbol')          unless validator_name.kind_of?(Symbol)
          fail(ArgumentError, '`validator` must respond to `\#{validate}`') unless validator.respond_to?(:validate)

          define_method(:validate_value) do |value, required_validator|
            if required_validator != validator_name
              super(value, required_validator)
            else
              value = deep_replace(value)
              value = hash_or_array(value)

              validator.validate(value)
            end
          end

          define_singleton_method(:name) { "#{NamedValidationInterceptor}(#{validator_name})" }
        end
      end

      ##
      # Helper functions for returning success and failure tuples
      module ValidationResult
        def self.success(coerced_value)
          [true, coerced_value]
        end

        def self.failure(error_message)
          [false, error_message]
        end
      end
    end
  end
end
