control 'V-225130' do
  impact 'high'
  title 'The macOS system must be integrated into a directory services infrastructure'
  desc 'Distinct user account databases on each separate system cause problems with username and password policy enforcement. Most approved directory services infrastructure solutions allow centralized management of users and passwords.'
  tag disa: 'AOSX-15-000016'
  ref 'https://www.stigviewer.com/stig/apple_os_x_10.15_catalina/2020-12-11/finding/V-225130'

  describe command('dscl localhost -list . | /usr/bin/grep "Active Directory"') do
    its('stdout') { should_not eq ""}
  end
end
