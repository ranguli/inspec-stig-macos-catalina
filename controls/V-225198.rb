control 'V-225198' do
  impact 'high'
  title 'The macOS system must have the security assessment policy subsystem enabled.'
  desc 'Any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system. Accordingly, software defined by the organization as critical must be signed with a certificate that is recognized and approved by the organization.'
  tag disa: 'AOSX-15-002064'
  ref 'https://www.stigviewer.com/stig/apple_os_x_10.15_catalina/2020-12-11/finding/V-225130'

  describe command('spctl --status | grep enabled') do
    its('stdout.strip') { should eq "assessments enabled"}
  end
end
