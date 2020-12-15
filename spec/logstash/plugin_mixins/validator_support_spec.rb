# encoding: utf-8

require "logstash/devutils/rspec/spec_helper"

require 'logstash/plugin_mixins/validator_support'

require 'securerandom'

describe LogStash::PluginMixins::ValidatorSupport::NamedValidationAdapter do
  context 'an adapter re-defining a named validator that exists in Logstash core' do
    let(:adapter) { described_class.new(:string) { |value| [false, 'intentional failure'] } }
    let(:plugin_class) { Class.new(LogStash::Plugin) }
    before(:each) { plugin_class.extend(adapter) }
    context '#validate_value' do
      it 'does not intercept validation' do
        expect(adapter).to_not receive(:validate)

        result = plugin_class.validate_value("banana", :string)

        expect(result).to be_a_kind_of(Array)
        expect(result.size).to eq(2)

        expect(result[0]).to eq true
        expect(result[1]).to eq 'banana'
      end
    end
  end

  context 'an adapter defining a named validator that does not exist in Logstash core' do
    let(:validator_name) { "some_custom_validator_name_#{SecureRandom.hex(10)}".to_sym }
    let(:adapter) { described_class.new(validator_name) { |value| [false, 'intentional failure'] } }
    let(:plugin_class) { Class.new(LogStash::Plugin) }
    before(:each) { plugin_class.extend(adapter) }
    
    context '#validate_value' do
      it 'intercepts validation' do
        expect(plugin_class).to receive(:hash_or_array).and_call_original
        expect(plugin_class).to receive(:deep_replace).and_call_original

        expect(adapter).to receive(:validate).with(["banana"]).and_call_original

        result = plugin_class.validate_value("banana", validator_name)

        expect(result).to be_a_kind_of(Array)
        expect(result.size).to eq(2)

        expect(result[0]).to eq false
        expect(result[1]).to eq 'intentional failure'
      end
    end
  end
end
