# encoding: utf-8

require 'logstash/plugin_mixins/validator_support'

require 'resolv'

module LogStash
  module PluginMixins
    module ValidatorSupport


      # rely on Resolv's IPv4#create and IPv6#create to validate IP addresses, but first regex to avoid most exceptions
      is_valid_ipv4 = ->(candidate) { Resolv::IPv4::Regex.match?(candidate) && Resolv::IPv4.create(candidate) rescue false}
      is_valid_ipv6 = ->(candidate) { Resolv::IPv6::Regex.match?(candidate) && Resolv::IPv6.create(candidate) rescue false}

      is_valid_hostname = ->(candidate) { (%r{\A([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\Z}i).match?(candidate) }

      # the normalized tuple from valid values
      host_port_pair = Struct.new(:host, :port)

      expectation_desc = "required-host optional-port pair"

      port_range = Range.new(0,65535)

      ##
      # When included into a Logstash plugin, adds a valiador named `required_host_optional_port`, which expects
      # exactly one string matching a required host, optionally followed by a colon and a port number, and coerces
      # valid values into a value with `host` and `port` attributes.
      # When specifying an IPv6 address, it MUST be enclosed in square-brackets, and the address itself (without
      # brackets) will be made available in the coerced value's `host` attribute
      RequiredHostOptionalPortValidationAdapter = NamedValidationAdapter.new(:required_host_optional_port) do |value|
        break ValidationResult.failure("Expected exactly one #{expectation_desc}, got `#{value.inspect}`") unless value.kind_of?(Array) && value.size <= 1

        candidate = value.first

        break ValidationResult.failure("Expected a valid #{expectation_desc}, got `#{candidate.inspect}`") unless candidate.kind_of?(String) && !candidate.empty?

        # optional port
        candidate_host, candidate_port = candidate.split(%r{\:(?=\d{1,5}\z)},2)
        port = candidate_port&.to_i

        break ValidationResult.failure("Expected a port in #{port_range.inspect}, got `#{port}`") if port && !port_range.include?(port)

        # bracket-wrapped ipv6
        if candidate_host.start_with?('[') && candidate_host.end_with?(']')
          candidate_host = candidate_host[1...-1]
          break ValidationResult.success(host_port_pair.new(candidate_host, port)) if is_valid_ipv6[candidate_host]
        else
          # ipv4 or hostname
          break ValidationResult.success(host_port_pair.new(candidate_host, port)) if is_valid_ipv4[candidate_host]
          break ValidationResult.success(host_port_pair.new(candidate_host, port)) if is_valid_hostname[candidate_host]
        end

        break ValidationResult.failure("Expected a valid #{expectation_desc}, got `#{candidate.inspect}`")
      end
    end
  end
end