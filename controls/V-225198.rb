# frozen_string_literal: true

control 'V-225198' do
  impact 1.0
  title "The macOS system must have the security assessment policy subsystem
        enabled."
  desc  "Any changes to the hardware, software, and/or firmware components of
        the information system and/or application can potentially have
        significant effects on the overall security of the system.
        Accordingly, software defined by the organization as critical must be
        signed with a certificate that is recognized and approved by the
        organization."
  tag stid_id: 'AOSX-15-002064'
  tag severity: 'high'

  describe command('spctl --status | grep enabled') do
    its('stdout.strip') { should eq 'assessments enabled' }
  end
end
