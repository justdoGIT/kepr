# kepr for Puppet

`kepr::secret('NAME')` returns `Sensitive[String]` with a credential's value
from the local kepr daemon, read as the user running the agent or
`puppet apply`.

```puppet
file { '/etc/app/token':
  content => kepr::secret('API_TOKEN'),
  mode    => '0600',
}
```

It runs `kepr get NAME --quiet` (no shell; the name is checked first), waits
up to 65 s for a consent prompt, and never puts the value or the CLI's
output in an error message. Test: `ruby puppet/test/test_lookup.rb`.
