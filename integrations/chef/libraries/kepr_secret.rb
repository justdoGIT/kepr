# frozen_string_literal: true

require_relative 'kepr_lookup'

# kepr_secret('API_TOKEN') in recipes and templates: the value from the
# local kepr daemon, read as the user chef-client runs as. Pass it to a
# property declared `sensitive true`, so Chef keeps it out of logs and
# diffs; never interpolate it into a log message.
class Chef
  module DSL
    module Kepr
      def kepr_secret(name)
        KeprLookup.get(name)
      end
    end
  end
end

Chef::DSL::Recipe.include(Chef::DSL::Kepr) if defined?(Chef::DSL::Recipe)
