# encoding: utf-8

require 'logstash/plugin_mixins/validator_support/field_reference_validation_adapter'

describe LogStash::PluginMixins::ValidatorSupport::FieldReferenceValidationAdapter do
  it 'is an instance of NamedValidationAdapter' do
    expect(described_class).to be_a_kind_of LogStash::PluginMixins::ValidatorSupport::NamedValidationAdapter
  end

  context '#validate' do
    [
      ['@timestamp'],
      ['[@timestamp]'],
      ['[@metadata][ssl]'],
      ['[link][0]'],
      ['one'],
      ['[fruit][[bananas][oranges]]'],
      [],
      [nil]
    ].each do |candidate|
      context "valid input `#{candidate.inspect}`" do
        it 'correctly reports the value as valid', :aggregate_failures do
          is_valid_result, coerced_or_error = described_class.validate(candidate)

          expect(is_valid_result).to be true
          expect(coerced_or_error).to eq candidate.first
        end
      end
    end

    context "valid input `''`" do
      # failed in version 1.0.x which was not compatible with LS 7.x behavior
      it 'correctly reports the value as valid' do
        is_valid_result, coerced_or_error = described_class.validate ['']

        expect(is_valid_result).to be true
        expect(coerced_or_error).to be nil
      end
    end

    [
      ['link[0]'],
      ['][N\\//\\L][D'],
      ["one","two"],
      {"this" => "that"},
      ['[fruit][bananas[oranges]]'],
    ].each do |candidate|
      let(:candidate) { candidate }

      context "invalid input `#{candidate.inspect}`" do
        it 'correctly reports the value as invalid', :aggregate_failures do
          is_valid_result, coerced_or_error = described_class.validate(candidate)

          expect(is_valid_result).to be false
          expect(coerced_or_error).to be_a_kind_of String
          expect(coerced_or_error).to_not include('Unknown validator')
          expect(coerced_or_error).to include('field reference')
        end
      end
    end
  end
end