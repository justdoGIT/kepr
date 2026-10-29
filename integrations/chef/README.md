# kepr for Chef

`kepr_secret('NAME')` returns the value of a credential from the local kepr
daemon, read as the user `chef-client` runs as.

```ruby
# metadata.rb: depends nothing; copy libraries/ into a cookbook
file '/etc/app/token' do
  content kepr_secret('API_TOKEN')
  sensitive true   # keeps the value out of logs and diffs
  mode '0600'
end
```

It runs `kepr get NAME --quiet` (no shell; the name is checked first), waits
up to 65 s for a consent prompt, and never puts the value or the CLI's
output in an error message. Sealed agent keys and SSH keys are refused by
the daemon. Test: `ruby chef/test/test_lookup.rb`.
