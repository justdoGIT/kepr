# frozen_string_literal: true

require_relative '../../../puppet_x/kepr/lookup'

# kepr::secret('API_TOKEN') returns Sensitive[String] with the credential's
# value from the local kepr daemon, read as the user running the agent or
# `puppet apply`. Sensitive keeps it out of logs and reports.
Puppet::Functions.create_function(:'kepr::secret') do
  dispatch :secret do
    param 'String[1]', :name
    return_type 'Sensitive[String]'
  end

  def secret(name)
    Puppet::Pops::Types::PSensitiveType::Sensitive.new(KeprLookup.get(name))
  rescue KeprLookup::Error => e
    raise Puppet::ParseError, e.message
  end
end
