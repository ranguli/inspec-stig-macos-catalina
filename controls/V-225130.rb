# frozen_string_literal: true

control 'V-225130' do
  impact 1.0
  title "The macOS system must be integrated into a directory services
        infrastructure"
  desc  "Distinct user account databases on each separate system cause problems
        with username and password policy enforcement. Most approved directory
        services infrastructure solutions allow centralized management of users
        and passwords."
  tag stig_id: 'AOSX-15-000016'
  tag severity: 'high'

  describe command('dscl localhost -list . | /usr/bin/grep "Active Directory"') do
    its('stdout') { should_not eq '' }
  end
end
